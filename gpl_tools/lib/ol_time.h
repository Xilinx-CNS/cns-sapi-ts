/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_TIME_H__
#define __OL_TIME_H__

#include <stdint.h>

/**
 * Get current timestamp in useconds.
 *
 * @return number of useconds since CPU reset.
 */
uint64_t ol_time_get_usec();

/**
 * Initialize timing subsystem internal data.
 */
void ol_time_init();

#endif /* __OL_TIME_H__ */
