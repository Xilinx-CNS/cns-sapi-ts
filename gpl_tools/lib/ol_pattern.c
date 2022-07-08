/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */
#include <stdbool.h>
#include "ol_pattern.h"

/* Maximum count of numbers in a sequence. */
#define SEQUENCE_MAX_NUM (256 * 256)

/* Count of numbers in a sequence (should not be greater than the maximum). */
#define SEQUENCE_NUM SEQUENCE_MAX_NUM

/* Period of a sequence - total length of all two-digit numbers. */
#define SEQUENCE_PERIOD_NUM (SEQUENCE_NUM * 2)

/**
 * Get nth element of a string which is a concatenation of
 * a periodic sequence 1, 2, 3, ..., SEQUENCE_PERIOD_NUM, 1, 2, ...
 * where numbers are written in a positional base 256 system.
 *
 * @param n     Number
 *
 * @return Character code
 */
static char
ol_pattern_get_nth_elm(int n)
{
    bool msb = false;

    n %= SEQUENCE_PERIOD_NUM;

    /* Even positions in array contain most significant bits. */
    if (n % 2 == 0)
        msb = true;

    /* Map from position in array to sequence number. */
    n /= 2;

    return msb ? n / 256 : n % 256;
}

void
ol_pattern_fill_buff_with_sequence(char *buf, int size, int start_n)
{
    int i;

    start_n %= SEQUENCE_PERIOD_NUM;

    for (i = 0; i < size; i++)
        buf[i] = ol_pattern_get_nth_elm(start_n + i);
}
