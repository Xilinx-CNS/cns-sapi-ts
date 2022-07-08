/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_CEPH_H__
#define __OL_CEPH_H__

/**
 * Generic application data for generator and client.
 */
typedef struct ol_ceph_state
{
    void       *buf;        /**< Pointer to a buffer to read/write to. */
    size_t      bufsize;    /**< Size of the buffer. */
} ol_ceph_state;

#define _OL_MAKE_STR(_x) #_x
#define OL_MAKE_STR(_x) _OL_MAKE_STR(_x)

/** TCP port a client connects to. */
#define OL_CEPH_APP_PORT 6800

/** String representation of @ref OL_CEPH_APP_PORT */
#define OL_CEPH_APP_PORT_STR OL_MAKE_STR(OL_CEPH_APP_PORT)

#endif /* __OL_CEPH_H__ */
