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

static int parse_timestr_tod(struct perf_time *ptime,
			     char *start_str, char *end_str, const char *fmt)
{
	struct tm tm, tm_ref;
	time_t t;
	u64 tref;
	char *endp;

	if (timestamp_ref == 0 || tv_ref.tv_usec == 0) {
		pr_err("timestamp reference not found in header; cannot honor start/end request\n");
		return -1;
	}

	/* adjust timestamp_ref back to tv_ref.tv_sec by taking out the
	 * microseconds element.
	 */
	tref = timestamp_ref - tv_ref.tv_usec * NSEC_PER_USEC;

	/* convert tv_ref seconds to tm */
	t = tv_ref.tv_sec;
	if (localtime_r(&t, &tm_ref) == NULL) {
		pr_err("Error converting reference time; cannot honor start/end request\n");
		return -1;
	}

	if (*start_str != '\0') {
		tm = tm_ref;   /* start with our reference time */

		/* update based on the user string */
		endp = strptime(start_str, fmt, &tm);
		if (endp == NULL || *endp != '\0') {
			pr_err("invalid start time string\n");
			return -1;
		}

		t = mktime(&tm);
		if (t > tv_ref.tv_sec)
			ptime->start = tref + (t - tv_ref.tv_sec) * NSEC_PER_SEC;
	}

	if (end_str && *end_str != '\0') {
		tm = tm_ref;   /* start with our reference time */

		/* update based on the user string */
		endp = strptime(end_str, fmt, &tm);
		if (endp == NULL || *endp != '\0') {
			pr_err("invalid end time string\n");
			return -1;
		}

		t = mktime(&tm);
		if (t < tv_ref.tv_sec) {
			ptime->end = 0;
		} else {
			ptime->end = tref + (t - tv_ref.tv_sec) * NSEC_PER_SEC;

			/* if end time is before start time perhaps it is a
			 * wrap over midnight. really need to add day option
			 * to time string.
			 */
			if (ptime->end < ptime->start)
				ptime->end += 86400;
		}
	}

	return 0;
}

static int parse_timestr_sec_nsec(struct perf_time *ptime,
				  char *start_str, char *end_str)
{
	if (start_str && (*start_str != '\0') &&
		(parse_nsec_time(start_str, &ptime->start) != 0)) {
			return -1;
	}

	if (end_str && (*end_str != '\0') &&
		(parse_nsec_time(end_str, &ptime->end) != 0)) {
			return -1;
	}

	return 0;
}

int perf_time__parse_str(struct perf_time *ptime, const char *ostr,
			 const char *fmt)
{
	char *start_str, *end_str;
	char *d, *str;
	int rc = 0;

	if (ostr == NULL || *ostr == '\0')
		return 0;

	if (fmt == NULL)
		fmt = DEFAULT_TOD_FMT;

	/* copy original string because we need to modify it */
	str = strdup(ostr);
	if (str == NULL)
		return -ENOMEM;

	ptime->start = 0;
	ptime->end = 0;

	/* str has the format: <start>,<stop>
	 * variations: <start>,
	 *             ,<stop>
	 *             ,
	 */
	start_str = str;
	d = strchr(start_str, ',');
	if (d) {
		*d = '\0';
		++d;
	}
	end_str = d;

	/*
	 * start and end times can be either wall clock as HH:MM:DD
	 * or perf_clock as second.microseconds
	 */
	if ((*start_str != '\0' && strchr(start_str, ':')) ||
		(end_str && *end_str != '\0' && strchr(end_str, ':'))) {
		rc = parse_timestr_tod(ptime, start_str, end_str, fmt);
	} else {
		rc = parse_timestr_sec_nsec(ptime, start_str, end_str);
	}

	free(str);

	/* make sure end time is after start time if it was given */
	if (rc == 0 && ptime->end && ptime->end < ptime->start)
		return -EINVAL;

	pr_debug("start time %" PRIu64 ", ", ptime->start);
	pr_debug("end time %" PRIu64 "\n", ptime->end);

	return rc;
}

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

bool perf_time__skip_sample(struct perf_time *ptime, u64 timestamp)
{
	/* if time is not set don't drop sample */
	if (timestamp == 0)
		return false;

	/* otherwise compare sample time to time window */
	if ((ptime->start && timestamp < ptime->start) ||
	    (ptime->end && timestamp > ptime->end)) {
		return true;
	}

	return false;
}
