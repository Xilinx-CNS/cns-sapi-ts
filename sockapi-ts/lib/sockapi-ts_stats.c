/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TAPI to calculate statistics.
 *
 * Implementation of functions for calculating statistics from TE vector
 * with integers.
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#include "sockapi-ts_stats.h"

#include <stdlib.h>

static int
sockts_qsort_compare_int(const void* pa, const void* pb)
{
    const int* a = pa;
    const int* b = pb;
    return *a - *b;
}

/** See definition in sockapi-ts_stats.h */
te_errno
sockts_stats_int_get(te_vec *values, sockts_stats_int *stats)
{
    size_t values_n = te_vec_size(values);
    long int sum = 0;
    size_t i;
    int *values_sorted = NULL;

    if (values_n == 0)
        return TE_EINVAL;

    if (values->element_size != sizeof(int) || stats == NULL)
        return TE_EINVAL;

    values_sorted = TE_ALLOC(values_n * sizeof(int));
    memcpy(values_sorted, values->data.ptr, values_n * sizeof(int));
    qsort(values_sorted, values_n, sizeof(int), &sockts_qsort_compare_int);

    stats->median = values_sorted[values_n >> 1u];
    stats->min = values_sorted[0];
    stats->max = values_sorted[values_n - 1];

    for (i = 0; i < values_n; i++)
        sum += values_sorted[i];
    stats->mean = (int) (sum / values_n);

    free(values_sorted);
    return 0;
}

/** See definition in sockapi-ts_stats.h */
unsigned int
sockts_stats_int_out_of_range_num(te_vec *values, int range_value,
                                  unsigned int range_percent,
                                  unsigned int *num_min_p,
                                  unsigned int *num_max_p)
{
    int range_min = range_value - (range_value * range_percent / (double)100);
    int range_max = range_value + (range_value * range_percent / (double)100);
    unsigned int num_min = 0;
    unsigned int num_max = 0;
    int *elem;

    if (values->element_size != sizeof(int))
        return TE_EINVAL;

    TE_VEC_FOREACH(values, elem)
    {
        if (*elem > range_max)
            num_max++;
        else if (*elem < range_min)
            num_min++;
    }

    if (num_min_p != NULL)
        *num_min_p = num_min;

    if (num_max_p != NULL)
        *num_max_p = num_max;

    return num_min + num_max;
}
