#ifndef _TIME_UTIL_H_
#define _TIME_UTIL_H_

u64 get_perf_clock(void);

struct perf_time {
	u64 start, end;
};

#define DEFAULT_TOD_FMT "%H:%M:%S"

int perf_time__get_reftime(u64 *pclock, struct timeval *tv);

void perf_time__set_reftime(struct timeval *tv, u64 tref);
int perf_time__reftime_live(void);

int perf_time__have_reftime(struct perf_session *session);

/* converts time t into a string. If time-of-day reference exists
 * returned strig is time-of-day. fmt can be used to change the format
 * of the string created. fmt is passed to strftime.
 */
char *perf_time__str(char *buf, int buflen, u64 t, const char *fmt);

int perf_time__parse_str(struct perf_time *ptime, const char *ostr,
			 const char *fmt);

bool perf_time__skip_sample(struct perf_time *ptime, u64 timestamp);

#endif
