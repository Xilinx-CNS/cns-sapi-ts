/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_APPRTT_H__
#define __OL_APPRTT_H__

/**
 * Generic application data for server and client.
 */
typedef struct ol_app_state
{
    void       *buf;            /**< Pointer to a buffer to read/write to. */
    size_t      bufsize;        /**< Size of the buffer. */
    void       *internal_data;  /**< Internal data for client/server. */
} ol_app_state;

/** TCP port a client connects to. */
#define SERVER_PORT 2048

/**
 * Size of application buffer for sending/receiving data. The size is chosen
 * to be multiple times bigger than socket send buffer size.
 */
#define APP_BUF_SIZE (1024 * 512)

#endif /* __OL_APPRTT_H__ */
