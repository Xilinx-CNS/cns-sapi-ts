/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TAPI to calculate statistics.
 *
 * Definitions of functions for calculating statistics from TE vector
 * with integers.
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#ifndef __SOCKAPI_TS_STATS_H__
#define __SOCKAPI_TS_STATS_H__

#include "sockapi-test.h"
#include "te_errno.h"
#include "te_vector.h"

/** Statistics for integer values */
typedef struct sockts_stats_int {
    int mean;
    int median;
    int min;
    int max;
} sockts_stats_int;

/**
 * Get stats from TE vector with integer values.
 *
 * @param[in]  values       TE vector with integer values
 * @param[out] stats        Pointer to structure to be filled with stats
 *
 * @return Status code.
 */
extern te_errno sockts_stats_int_get(te_vec *values, sockts_stats_int *stats);

/**
 * Get the number of values that are out of range from the specified value.
 *
 * @param[in]  values           TE vector with integer values
 * @param[in]  range_value      Middle value of the range
 * @param[in]  range_percent    Percentage of @p range_value that sets half
 *                              the width of the range
 * @param[out] num_min          The number of values that are less than the
 *                              lower limit of the range (may be @c NULL)
 * @param[out] num_max          The number of values that are greater than the
 *                              upper limit of the range (may be @c NULL)
 *
 * @return Out of range values number.
 */
extern unsigned int sockts_stats_int_out_of_range_num(te_vec *values,
                                                      int range_value,
                                                      unsigned int range_percent,
                                                      unsigned int *num_min,
                                                      unsigned int *num_max);

#endif /* __SOCKAPI_TS_STATS_H__ */
