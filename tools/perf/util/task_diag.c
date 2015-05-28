/*
 * Use task_diag interface to retrieve information about running
 * processes. Send TASK_DIAG_CMD_GET message and get back a series
 * of messages:
 * 1. all responses have TASK_DIAG_PID attribute
 * 2. only first message for a process has DIAG_BASE attribute
 * 3. DIAG_VMA attribute may require a series of messages
 */

#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/taskstats.h>
#include <linux/task_diag.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/genl/ctrl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>


#include "event.h"
#include "machine.h"
#include "debug.h"
#include "perf_task_diag.h"

static struct genl_ops ops = {
	.o_name = (char *) TASKSTATS_GENL_NAME,
};

static struct perf_sample synth_sample = {
	.pid       = -1,
	.tid       = -1,
	.time      = -1,
	.stream_id = -1,
	.cpu       = -1,
	.period    = 1,
};

#if 0
static int parse_diag_cred(struct task_diag_cred *cred, int len,
			  struct process *proc)
{
	if (nlattrs[TASK_DIAG_CRED] == NULL) {
		pr_err("TASK_DIAG_CRED attribute not found in message\n");
		goto out_err;
	} else if (nla_len(nlattrs[TASK_DIAG_CRED]) != sizeof(*cred_msg)) {
		pr_err("Size mismatch for TASK_DIAG_CRED attribute: expected %d, found %d\n",
			sizeof(*cred_msg), nla_len(nlattrs[TASK_DIAG_CRED]));
		goto out;
	}
}
#endif

static int parse_diag_vma(struct nlattr *attr, u32 tgid, u32 tid,
			  struct synth_event *args)
{
	perf_event__handler_t process = args->process;
	union perf_event *event = args->mmap_event;
	struct machine *machine = args->machine;
	struct perf_tool *tool = args->tool;
	bool mmap_data = args->mmap_data;
	const char anonstr[] = "//anon";
	struct task_diag_vma *vma;
	size_t size;
	int rc = 0;

	task_diag_for_each_vma(vma, attr) {
		struct task_diag_vma vma_tmp;
		const char *name;

		/*
		 * copy struct to temp space to ensure 8-byte
		 * aligned accesses.
		 */
		memcpy(&vma_tmp, vma, sizeof(vma_tmp));

		event->mmap2.start = vma_tmp.start;
		event->mmap2.len   = vma_tmp.end - vma_tmp.start;
		event->mmap2.pgoff = vma_tmp.pgoff;
		event->mmap2.maj   = vma_tmp.major;
		event->mmap2.min   = vma_tmp.minor;

		event->mmap2.ino = vma_tmp.inode;
		event->mmap2.ino_generation = vma_tmp.generation;

		event->mmap2.prot = 0;
		if (vma_tmp.vm_flags & TASK_DIAG_VMA_F_READ)
			event->mmap2.prot |= PROT_READ;
		if (vma_tmp.vm_flags & TASK_DIAG_VMA_F_WRITE)
			event->mmap2.prot |= PROT_WRITE;

		if (vma_tmp.vm_flags & TASK_DIAG_VMA_F_EXEC) {
			event->mmap2.prot |= PROT_EXEC;
		} else {
			if (!mmap_data ||
			    !(vma_tmp.vm_flags & TASK_DIAG_VMA_F_READ)) {
				continue;
			}
			event->header.misc |= PERF_RECORD_MISC_MMAP_DATA;
		}

		event->mmap2.flags = 0;
		if (vma_tmp.vm_flags & TASK_DIAG_VMA_F_MAYSHARE)
			event->mmap2.flags |= MAP_SHARED;
		else
			event->mmap2.flags |= MAP_PRIVATE;

		name = task_diag_vma_name(vma);
		if (!name)
			name = anonstr;

		size = strlen(name) + 1;
		memcpy(event->mmap2.filename, name, size);
		size = PERF_ALIGN(size, sizeof(u64));
		memset(event->mmap2.filename + size, 0, machine->id_hdr_size);
		event->mmap2.header.size = (sizeof(event->mmap2) -
				(sizeof(event->mmap2.filename) - size) +
				machine->id_hdr_size);

		event->header.type = PERF_RECORD_MMAP2;
		if (machine__is_host(machine))
			event->header.misc = PERF_RECORD_MISC_USER;
		else
			event->header.misc = PERF_RECORD_MISC_GUEST_USER;

		event->mmap2.pid = tgid;
		event->mmap2.tid = tid;

		if (process(tool, event, &synth_sample, machine) != 0) {
			rc = -1;
			break;
		}
	}

	return rc;
}

static int parse_diag_base(struct task_diag_base *base, u32 len,
			   struct synth_event *args)
{
	struct perf_tool *tool = args->tool;
	struct machine *machine = args->machine;
	union perf_event *fork_event = args->fork_event;
	union perf_event *comm_event = args->comm_event;
	perf_event__handler_t process = args->process;
	pid_t pid, tgid;
	size_t size;

	if (len < sizeof(*base)) {
		pr_err("Size mismatch for TASK_DIAG_BASE attribute: expected %ld, found %d\n",
			sizeof(*base), len);
		return -EINVAL;
	}

	tgid = base->tgid;
	pid  = base->pid;

	/*
	 * generate FORK event
	 */
	/*
	 * for main thread set parent to ppid from status file. For other
	 * threads set parent pid to main thread. ie., assume main thread
	 * spawns all threads in a process
	 */
	if (tgid == pid) {
		fork_event->fork.ppid = base->ppid;
		fork_event->fork.ptid = base->ppid;  // FIXME
	} else {
		fork_event->fork.ppid = tgid;
		fork_event->fork.ptid = tgid;
	}

	fork_event->fork.pid  = tgid;
	fork_event->fork.tid  = pid;
	fork_event->fork.time = 0;

	fork_event->fork.header.type = PERF_RECORD_FORK;
	fork_event->fork.header.misc = 0;
	fork_event->fork.header.size = (sizeof(fork_event->fork)
					+ machine->id_hdr_size);
	memset((char *) fork_event + sizeof(fork_event->fork), 0,
		machine->id_hdr_size);

	if (process(tool, fork_event, &synth_sample, machine) != 0)
		return -1;

	/*
	 * generate COMM event
	 */
	memset(&comm_event->comm, 0, sizeof(comm_event->comm));
	comm_event->comm.pid = tgid;
	comm_event->comm.tid = pid;
	size = MIN(strlen(base->comm), sizeof(comm_event->comm.comm) - 1);
	memcpy(comm_event->comm.comm, base->comm, size);

	size += 1;
	size = PERF_ALIGN(size, sizeof(u64));

	memset(comm_event->comm.comm + size, 0, machine->id_hdr_size);
	comm_event->comm.header.size = (sizeof(comm_event->comm) -
					(sizeof(comm_event->comm.comm) - size) +
					machine->id_hdr_size);

	comm_event->comm.header.type = PERF_RECORD_COMM;
	comm_event->comm.header.misc = 0;

	if (process(tool, comm_event, &synth_sample, machine) != 0)
		return -1;

	return 0;
}

static int taskdiag_done_cb(struct nl_msg *nlmsg, void *arg __maybe_unused)
{
	struct nlmsghdr *nlhdr = nlmsg_hdr(nlmsg);

	if (nlhdr->nlmsg_type == NLMSG_DONE) {
		int *ret = nlmsg_data(nlhdr);

		if (*ret < 0) {
			pr_err("netlink error message: %s\n", strerror(-*ret));
			return *ret;
		}
	}

	return 0;
}

static int taskdiag_msg_cb(struct nl_msg *nlmsg, void *arg)
{
	struct nlmsghdr *nlhdr = nlmsg_hdr(nlmsg);
	struct genlmsghdr *ghdr = nlmsg_data(nlhdr);
	struct nlattr *nlattrs[TASK_DIAG_ATTR_MAX + 1];
	u32 pid = 0, tgid = 0;
	int rc = -1;

	if (ghdr->cmd == 0)
		return NL_STOP;

	if (ghdr->cmd != TASK_DIAG_CMD_GET) {
		pr_debug("Invalid task_diag command (%d)\n", ghdr->cmd);
		return -1;
	}

	if (genlmsg_parse(nlhdr, 0, nlattrs, TASK_DIAG_ATTR_MAX, NULL) != 0) {
		pr_err("Invalid taskdiag message\n");
		goto out;
	}

	if (nlattrs[TASK_DIAG_BASE]) {
		rc = parse_diag_base(nla_data(nlattrs[TASK_DIAG_BASE]),
				     nla_len(nlattrs[TASK_DIAG_BASE]),
				     arg);
		if (rc != 0)
			goto out;
	}

	/* kernel threads will not have a vma */
	if (nlattrs[TASK_DIAG_VMA]) {
		/* PID and TGID are required */
		if (!nlattrs[TASK_DIAG_PID] || !nlattrs[TASK_DIAG_TGID]) {
			pr_err("Required PID/TGID attributes not found in message.\n");
			goto out;
		}
		pid = nla_get_u32(nlattrs[TASK_DIAG_PID]);
		tgid = nla_get_u32(nlattrs[TASK_DIAG_TGID]);

		rc = parse_diag_vma(nlattrs[TASK_DIAG_VMA], pid, tgid, arg);
		if (rc != 0)
			goto out;
	}

	rc = 0;
out:
	return rc;
}


static int taskdiag_send_get(struct nl_sock *sk, pid_t pid)
{
	struct task_diag_pid req = {
		.pid = pid,
		.show_flags = TASK_DIAG_SHOW_BASE | TASK_DIAG_SHOW_VMA, // TASK_DIAG_SHOW_CRED
		.dump_strategy = TASK_DIAG_DUMP_ALL_THREAD,
	};
	struct nl_msg *msg;
	int flags = 0;
	int rc = -1;

	msg = nlmsg_alloc();
	if (msg == NULL) {
		pr_err("Failed to allocate netlink message");
		return -ENOMEM;
	}

	if (pid == 0)
		flags |= NLM_F_DUMP;

	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ops.o_id,
		  0, flags, TASK_DIAG_CMD_GET, TASKSTATS_GENL_VERSION);

	nla_put(msg, TASK_DIAG_CMD_ATTR_GET, sizeof(req), &req);

	rc = nl_send_auto_complete(sk, msg);
	if (rc < 0)
		pr_err("Failed to send message: %s", nl_geterror(rc));
	else
		rc = 0;

	nlmsg_free(msg);

	return rc;
}

/*
 * block on select for libnb related messages
 * - calls pre_wait_cb before select and post_wait_cb after
 *
 * convenience helper for simpler broker applications
 */
static int process_messages(struct nl_sock *sk)
{
	int sd = nl_socket_get_fd(sk);
	struct timeval timeout;
	fd_set rfds;
	int rc, ret = 1;

	nl_socket_set_nonblocking(sk);

	while (1) {
		FD_ZERO(&rfds);
		FD_SET(sd, &rfds);

		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		rc = select(sd + 1, &rfds, NULL, NULL, &timeout);
		if (rc < 0) {
			if (errno == EINTR)
				continue;

			pr_err("Select failed.\n");
			goto out;
		} else if (rc == 0) {
			pr_err("Timed out waiting for messages\n");
			goto out;
		}
		break;
	}

	/* expect messages to come non-stop. Once we hit EAGAIN, done */
	while (1) {
		rc = nl_recvmsgs_default(sk);
		if (rc < 0) {
			if (rc == -EBUSY)
				continue;

			if (errno == EAGAIN)
				ret = 0;
			else {
				pr_err("Message handling failed: rc %d, errno %d\n",
					rc, errno);
			}
			break;
		}
	}

out:
	return ret;
}

static void taskdiag_exit(struct nl_sock *sk)
{
	nl_close(sk);
	nl_socket_free(sk);
}

static struct nl_sock *taskdiag_init(struct synth_event *args)
{
	struct nl_sock *sk;
	int rc = 0;

	sk = nl_socket_alloc();
	if (!sk) {
		pr_err("Failed to allocate netlink socket\n");
		rc = -ENOMEM;
		goto out;
	}

	rc = genl_connect(sk);
	if (rc < 0) {
		pr_err("Failed to connect netlink socket\n");
		goto out_free;
	}

	rc = genl_ops_resolve(sk, &ops);
	if (rc < 0) {
		pr_err("Failed to resolve family name\n");
		goto out_close;
	}

	rc = nl_socket_modify_cb(sk, NL_CB_MSG_IN, NL_CB_CUSTOM,
				 taskdiag_msg_cb, args);
	if (rc < 0) {
		pr_err("Failed to set callback\n");
		goto out_close;
	}
	rc = nl_socket_modify_cb(sk, NL_CB_FINISH, NL_CB_CUSTOM,
				 taskdiag_done_cb, args);
	if (rc < 0) {
		pr_err("Failed to modify finish callback");
		goto out_close;
	}

	return sk;

out_close:
	nl_close(sk);
out_free:
	nl_socket_free(sk);
out:
	return NULL;
}

int task_diag__synthesize_threads(struct synth_event *args)
{
	struct nl_sock *sk;
	int rc = 1;

	sk = taskdiag_init(args);
	if (sk == NULL) {
		pr_err("Error creating generic netlink socket\n");
		goto err;
	}

	rc = taskdiag_send_get(sk, 0);
	if (rc < 0) {
		pr_err("Failed to send request message for diag stats. enabled?\n");
		goto err;
	}

	rc = process_messages(sk);

err:
	taskdiag_exit(sk);

	return rc;
}
