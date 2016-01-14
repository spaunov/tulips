#include "clock.h"
#include <stdio.h>

#ifndef __USE_POSIX199309
#define __USE_POSIX199309
#endif

#include <time.h>
#include <sys/time.h>

static uint64_t clock_cps = 0;

static uint64_t rdtsc(void)
{
	uint64_t a, d;
	__asm__ __volatile__("rdtsc" : "=a"(a), "=d"(d));
	return (a | (d << 32));
}

static uint64_t get_cps()
{
	struct timespec ts = {1, 0};
	uint64_t res = 0, tsc = rdtsc();
	nanosleep(&ts, NULL);
	res = rdtsc() - tsc;
	return res;
}

void clock_init(void)
{
	clock_cps = get_cps();
}

uint64_t cycles_per_second(void)
{
	return clock_cps;
}

clock_time_t clock_time(void)
{
	return rdtsc();
}
