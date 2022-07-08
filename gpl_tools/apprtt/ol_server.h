/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_SERVER_H__
#define __OL_SERVER_H__

#include <stdbool.h>

#include "ol_apprtt.h"

/**
 * Main server application function.
 *
 * @param state         Application state handle.
 * @param chunk_size    Size of data chunk. When server receives the size,
 *                      it answers with a byte.
 *
 * @return Status code
 * @retval 0    No errors.
 * @retval -1   An error occured.
 */
int
ol_rtt_server(ol_app_state *state, int chunk_size, bool data_check);

#endif /* __OL_SERVER_H__ */
