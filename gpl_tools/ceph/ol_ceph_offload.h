/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_CEPH_OFFLOAD_H__
#define __OL_CEPH_OFFLOAD_H__

#include <stdbool.h>

/**
 * A value for Onload TCP socket option to enable TCP/Ceph offloading.
 * For more information see @c ONLOAD_TCP_OFFLOAD option documentation
 * in src/include/onload/extensions_zc.h.
 */
#define OFFLOAD_ID_CEPH 6801

/**
 * Enable TCP/Ceph offloading for @p socket.
 *
 * @param socket    Non-connected socket.
 */
void ol_ceph_offload_enable(int socket);

/**
 * Disable TCP/Ceph offloading for @p socket.
 *
 * @param socket    Non-connected socket.
 */
void ol_ceph_offload_disable(int socket);

/**
 * Check whether TCP/Ceph offloading is enabled for @p socket.
 *
 * @param socket    Socket.
 *
 * @return @c true if offloading is supported and enabled, @c false otherwise.
 */
bool ol_ceph_offload_check(int socket);

#endif /* __OL_CEPH_OFFLOAD_H__ */
