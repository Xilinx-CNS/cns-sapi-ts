/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

/**
 * Fill buffer @p buf with patterned sequence of bytes starting with
 * @p start_n sequence element.
 *
 * @param buf       The buffer to fill.
 * @param size      Size of the buffer.
 * @param start_n   The number of the first element in sequence to start
 *                  filling with.
 */
extern void ol_pattern_fill_buff_with_sequence(char *buf, int size,
                                               int start_n);
