/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdint.h>
#include <assert.h>
#include <time.h>

struct ol_time_tsc_params
{
    uint64_t  hz;
    uint64_t  tsc_cost;
};

struct ol_time_tsc_measure
{
    uint64_t t_s;
    uint64_t tsc_s;
    uint64_t min_tsc_gtod;
};

static struct ol_time_tsc_params tsc;

static uint64_t
monotonic_clock(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static inline uint64_t
monotonic_clock_freq(void)
{
    return 1000000000;
}

#ifdef __x86_64__
static void
ol_time_tsc(uint64_t* pval)
{
    uint64_t low, high;
    __asm__ __volatile__("rdtsc" : "=a" (low) , "=d" (high));
    *pval = (high << 32) | low;
}
#elif defined(__aarch64__)
# define ol_time_tsc(pval) \
    __asm__ __volatile__("isb; mrs %0, cntvct_el0": "=r" (*(pval)))
#else
# error Unknown processor.
#endif

static void
measure_begin(struct ol_time_tsc_measure* measure)
{
    uint64_t    t_s;
    uint64_t    tsc_s, tsc_e2;
    uint64_t    tsc_gtod, min_tsc_gtod;
    int         n;

    ol_time_tsc(&tsc_s);
    t_s = monotonic_clock();
    ol_time_tsc(&tsc_e2);
    min_tsc_gtod = tsc_e2 - tsc_s;
    n = 0;
    do {
        ol_time_tsc(&tsc_s);
        t_s = monotonic_clock();
        ol_time_tsc(&tsc_e2);
        tsc_gtod = tsc_e2 - tsc_s;
        if (tsc_gtod < min_tsc_gtod)
            min_tsc_gtod = tsc_gtod;
    } while (++n < 20 || (tsc_gtod > min_tsc_gtod * 2 && n < 100));

    measure->min_tsc_gtod = min_tsc_gtod;
    measure->t_s = t_s;
    measure->tsc_s = tsc_s;
}


static uint64_t
measure_end(const struct ol_time_tsc_measure* measure, int interval_usec)
{
    uint64_t t_s = measure->t_s;
    uint64_t min_tsc_gtod = measure->min_tsc_gtod;
    uint64_t tsc_s = measure->tsc_s;
    uint64_t t_freq = monotonic_clock_freq();
    uint64_t t_interval = interval_usec * t_freq / 1000000;
    uint64_t t_e;
    uint64_t tsc_e, tsc_e2;
    uint64_t tsc_gtod, ticks;
    int n = 0, skew = 0;

    do {
        ol_time_tsc(&tsc_e);
        t_e = monotonic_clock();
        ol_time_tsc(&tsc_e2);

        if (tsc_e2 < tsc_e)
        {
            skew = 1;
            break;
        }

        tsc_gtod = tsc_e2 - tsc_e;
        ticks = t_e - t_s;
    } while (++n < 20 || ticks < t_interval || tsc_gtod > min_tsc_gtod * 2);

    assert(skew == 0);

    return (tsc_e - tsc_s) * t_freq / ticks;
}


static uint64_t
measure_hz(int interval_usec)
{
    struct ol_time_tsc_measure measure;
    measure_begin(&measure);
    return measure_end(&measure, interval_usec);
}

static int64_t
ol_time_tsc_usec(const struct ol_time_tsc_params* params, int64_t tsc)
{
    return tsc * 1000000 / params->hz;
}


uint64_t ol_time_get_usec()
{
    uint64_t t;
    ol_time_tsc(&t);
    return ol_time_tsc_usec(&tsc, t);
}

void ol_time_init()
{
    tsc.hz = measure_hz(100000);
}
