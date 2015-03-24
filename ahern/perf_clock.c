/*
 * Implements CLOCK_PERF.
 *
 * perf_clock is not exported, but for as long as I can remember perf_clock
 * is local_clock which is exported. Make use of that.
 *
 * posix clock implementation by Pawel Moll
 *     https://lkml.org/lkml/2013/3/14/523
 *
 * module by David Ahern, December 2013
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/posix-timers.h>

#define CLOCK_PERF         14

static int perf_posix_clock_getres(const clockid_t which_clock,
				   struct timespec *tp)
{
	*tp = ns_to_timespec(TICK_NSEC);
	return 0;
}

static int perf_posix_clock_get(clockid_t which_clock, struct timespec *tp)
{
	*tp = ns_to_timespec(local_clock());
	return 0;
}


static struct k_clock perf_posix_clock = {
	.clock_getres = perf_posix_clock_getres,
	.clock_get = perf_posix_clock_get,
};

static int perf_posix_clock_init(void)
{
	/* register this character driver */
	posix_timers_register_clock(CLOCK_PERF, &perf_posix_clock);

	pr_info("perf_clock clock registered\n");

	/* no API to unregister a clock so this module cannot be unloaded */
	__module_get(THIS_MODULE);

	return 0;
}

module_init(perf_posix_clock_init);

MODULE_AUTHOR("David Ahern");
MODULE_LICENSE("GPL");
