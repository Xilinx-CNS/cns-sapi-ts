/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_CLIENT_H__
#define __OL_CLIENT_H__

#include "ol_apprtt.h"

#define OL_CLIENT_LIM_UNSPEC 0

/**
 * Main client application function.
 * If neither @p time_to_run or @p bytes_to_send are specified, the client
 * runs infinitely.
 *
 * @param state         Application state handle.
 * @param host          String containing an address to connect.
 * @param time_to_run   Time to run, in seconds. Applicable if
 *                      @p bytes_to_send is not specified.
 * @param bytes_to_send Number of bytes to send. Applicable if
 *                      @p time_to_run is not specified.
 * @param chunk_size    Size of sent data for RTT measuring.
 * @param use_pattern   Client should send data according to the pattern.
 *
 * @return Status code
 * @retval 0    No errors.
 * @retval -1   An error occured.
 */
int
ol_rtt_client(ol_app_state *state, const char *host, int time_to_run,
              int bytes_to_send, int chunk_size, bool use_pattern);

#endif /* __OL_CLIENT_H__ */
