#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>

#include "../perf.h"
#include "session.h"
#include "debug.h"
#include "time-utils.h"

#define CLOCK_PERF         14

static struct timeval tv_ref;
static u64 timestamp_ref;

void perf_time__set_reftime(struct timeval *tv, u64 tref)
{
	tv_ref = *tv;
	timestamp_ref = tref;

	pr_debug("Updated ref time: %" PRIu64 " = %ld.%06d\n",
		 tref, tv_ref.tv_sec, (int) tv_ref.tv_usec);
}

int perf_time__have_reftime(struct perf_session *session)
{
	if (perf_header__has_feat(&session->header, HEADER_REFERENCE_TIME)) {
		perf_time__set_reftime(&session->header.env.tod_tv_ref,
				       session->header.env.perf_clock_ref);

		/* if timestamp_ref is 0 we don't really have a reftime */
		if (timestamp_ref == 0)
			return -1;

		return 0;
	}

	return -1;
}

char *perf_time__str(char *buf, int buflen, u64 timestamp, const char *fmt)
{
	struct tm ltime;
	u64 dt;
	struct timeval tv_dt, tv_res;

	if (fmt == NULL)
		fmt = DEFAULT_TOD_FMT;

	buf[0] = '\0';
	if (buflen < 64)
		return buf;

	if ((timestamp_ref == 0) || (timestamp == 0)) {
		unsigned long secs, usecs;
		unsigned long long nsecs;

		nsecs = timestamp;
		secs = nsecs / NSEC_PER_SEC;
		nsecs -= secs * NSEC_PER_SEC;
		usecs = nsecs / NSEC_PER_USEC;
		snprintf(buf, buflen, "%5lu.%06lu", secs, usecs);

		return buf;
	}

	if (timestamp > timestamp_ref) {
		dt = timestamp - timestamp_ref;
		tv_dt.tv_sec = (time_t) (dt / NSEC_PER_SEC);
		tv_dt.tv_usec = (dt - tv_dt.tv_sec * NSEC_PER_SEC) / 1000;
		timeradd(&tv_ref, &tv_dt, &tv_res);
	} else {
		dt = timestamp_ref - timestamp;
		tv_dt.tv_sec = (time_t) (dt / NSEC_PER_SEC);
		tv_dt.tv_usec = (dt - tv_dt.tv_sec * NSEC_PER_SEC) / 1000;
		timersub(&tv_ref, &tv_dt, &tv_res);
	}

	if (localtime_r(&tv_res.tv_sec, &ltime) == NULL)
		buf[0] = '\0';
	else {
		char date[64];

		strftime(date, sizeof(date), fmt, &ltime);
		snprintf(buf, buflen, "%s.%06d", date, (int) tv_res.tv_usec);
	}

	return buf;
}

u64 get_perf_clock(void)
{
	struct timespec ts;
	u64 t = (u64) -1;

	if (clock_gettime(CLOCK_PERF, &ts) == 0)
		t = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;

	return t;
}

static int get_reftime_clock(u64 *pclock, struct timeval *tv)
{
	int rc = -1;

	if (gettimeofday(tv, NULL) != 0)
		pr_err("gettimeofday failed. Cannot set reference time.\n");

	else {
		*pclock = get_perf_clock();
		if (*pclock == (u64) -1) {
			static int logit = 1;

			if (logit == 1)
				pr_err("Failed to get perf_clock timestamp. perf_clock module loaded?\n");

			logit = 0;
		} else
			rc = 0;
	}

	return rc;
}

int perf_time__get_reftime(u64 *pclock, struct timeval *tv)
{
	return get_reftime_clock(pclock, tv);
}

int perf_time__reftime_live(void)
{
	int rc = 0;
	u64 pclock;
	struct timeval tv;

	if (perf_time__get_reftime(&pclock, &tv) == 0)
		perf_time__set_reftime(&tv, pclock);
	else
		rc = -1;

	return rc;
}
