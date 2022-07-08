/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_CEPH_GENERATOR_H__
#define __OL_CEPH_GENERATOR_H__

#include "ol_ceph.h"

#define OL_CEPH_GENERATOR_LIM_UNSPEC 0

/**
 * Main generator application function.
 *
 * @param state         Application state handle.
 * @param host          String containing an address to connect or @c NULL
 *                      for passive connection opening.
 * @param port          Port number in host byte order, to bind in passive
 *                      case, or connect in active.
 * @param time_to_run   Time to run, in seconds.
 *
 * @return Status code
 * @retval 0    No errors.
 * @retval -1   An error occured.
 */
int
ol_ceph_generator(ol_ceph_state *state, const char *host, int port,
                  int time_to_run);

#endif /* __OL_CEPH_GENERATOR_H__ */
