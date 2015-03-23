#ifndef _TIME_UTIL_H_
#define _TIME_UTIL_H_

#define DEFAULT_TOD_FMT "%H:%M:%S"

void perf_time__set_reftime(struct timeval *tv, u64 tref);

int perf_time__have_reftime(struct perf_session *session);

/* converts time t into a string. If time-of-day reference exists
 * returned strig is time-of-day. fmt can be used to change the format
 * of the string created. fmt is passed to strftime.
 */
char *perf_time__str(char *buf, int buflen, u64 t, const char *fmt);

#endif
