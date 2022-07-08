/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief FD caching Test Suite
 *
 * FD caching support tests suite macros
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_FD_CACHE_H__
#define __TS_FD_CACHE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "onload.h"

/**
 * Compare two numbers and return the lowest one. If one of the numbers
 * is @c -1, the second one will be returned.
 * 
 * @param num1  First number
 * @param num2  Second number
 * 
 * @return Comparison result.
 */
static inline int
get_low_value(int num1, int num2)
{
    if (num1 == -1)
        return num2;

    if (num2 == -1)
        return num1;

    if (num1 < num2)
        return num1;

    return num2;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif
