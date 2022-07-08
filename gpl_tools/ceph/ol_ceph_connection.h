/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_CEPH_CONNECTION_H__
#define __OL_CEPH_CONNECTION_H__

#include <stdbool.h>

#if HAVE_ZC
#include "onload/extensions_zc.h"
#include "etherfabric/vi.h"
#include "etherfabric/pd.h"
#include "etherfabric/memreg.h"

typedef struct ol_ef_vi_t
{
#if USE_DLSYM
    struct
    {
        int (*ef_driver_open_f)(ef_driver_handle*);
        int (*ef_driver_close_f)(ef_driver_handle);

        int (*ef_pd_alloc_by_name_f)(ef_pd*, ef_driver_handle, const char*,
                                     enum ef_pd_flags);
        int (*ef_pd_free_f)(ef_pd*, ef_driver_handle);

        int (*ef_vi_alloc_from_pd_f)(ef_vi*, ef_driver_handle, struct ef_pd*,
                                     ef_driver_handle, int, int, int, ef_vi*,
                                     ef_driver_handle, enum ef_vi_flags);
        int (*ef_vi_free_f)(ef_vi*, ef_driver_handle);

        int (*ef_memreg_alloc_f)(ef_memreg*, ef_driver_handle, struct ef_pd*,
                                 ef_driver_handle, void*, size_t);
        int (*ef_memreg_free_f)(ef_memreg*, ef_driver_handle);
        int (*ef_vi_transmit_unbundle_f)(ef_vi* ep, const ef_event* event,
                                         ef_request_id* ids);
    } ops;
#endif /* USE_DLSYM */

    /* Handle for accessing the driver */
    ef_driver_handle dh;
    /* Protection domain */
    struct ef_pd pd;
    /* Virtual interface */
    struct ef_vi vi;
    /* Registered memory for DMA */
    void *dma_mem;
    size_t dma_mem_size;
    struct ef_memreg memreg;
    /* Variable to track DMA transactions */
    uint32_t dma_id;
    /* Interface to allocate protection domain for */
    const char *iface;
} ol_ef_vi_t;
#endif /* HAVE_ZC */

typedef struct ol_ceph_connection
{
    int socket;
    void *buf;
    size_t offs;
    size_t buflen;
#if HAVE_ZC
    struct onload_zc_hlrx* hlrx;
    bool ceph_offload_support;
    ol_ef_vi_t ef_vi;

#if USE_DLSYM
    struct
    {
        int (*onload_zc_hlrx_alloc_f)(int, int, struct onload_zc_hlrx**);
        int (*onload_zc_hlrx_free_f)(struct onload_zc_hlrx*);
        ssize_t (*onload_zc_hlrx_recv_zc_f)(struct onload_zc_hlrx*,
                                            struct onload_zc_msg*,
                                            size_t, int);
        int (*onload_zc_hlrx_buffer_release_f)(int, onload_zc_handle);
        ssize_t (*onload_zc_hlrx_recv_copy_f)(struct onload_zc_hlrx*,
                                            struct msghdr*, int);
    } ops;
#endif /* USE_DLSYM */
#endif /* HAVE_ZC */
} ol_ceph_connection;

/**
 * Initialize new connection instance.
 *
 * @param conn      The instance.
 * @param s         The socket.
 * @param iface     Name of SFC interface to use with ef_vi API.
 * @param buf       Buffer.
 * @param buflen    Size of the @p buf.
 * @param use_zc    If @c TRUE, initialize zero-copy and ev_vi libraries. The
 *                  flag has no sence if Onload headers are not presented.
 *
 * @return zero on success, or a negative error value in case of failure.
 */
int ol_ceph_conn_init(ol_ceph_connection *conn, int s, const char *iface,
                      void *buf, size_t buflen, bool use_zc);

/**
 * Close the connection.
 *
 * @param conn      The instance.
 *
 * @return zero on success, or a negative error value in case of failure.
 */
int ol_ceph_conn_close(ol_ceph_connection *conn);

/**
 * Read @p len_to_read bytes via @p conn.
 *
 * @param conn          TCP connection.
 * @param len_to_read   How much bytes to read.
 * @param append        If @c true, append new data to existing data in the
 *                      connection buffer.
 *
 * @return Number of read bytes, or zero if peer closed the connection,
 *         or a negative error value in case of failure.
 */
ssize_t ol_ceph_recv(ol_ceph_connection *conn, size_t len_to_read, bool append);

/**
 * Read @p len_to_read bytes via @p conn using zero-copy Onload API.
 *
 * @param conn          TCP connection.
 * @param len_to_read   How much bytes to read.
 * @param append        If @c true, append new data to existing data in the
 *                      connection buffer.
 *
 * @return Number of read bytes, or zero if peer closed the connection,
 *         or a negative error value in case of failure.
 */
ssize_t ol_ceph_recv_zc(ol_ceph_connection *conn, size_t len_to_read,
                        bool append);

/**
 * Push user data to the connection buffer to send it later
 * with @ref ol_ceph_send.
 *
 * @param conn  Connection handle.
 * @param data  User data or @c NULL to fill buffer with random data.
 * @param len   Length of data to append.
 *
 * @return zero on success, or a negative error value in case of failure.
 */
int ol_ceph_append(ol_ceph_connection *conn, const void *data, size_t len);

/**
 * Send all data from the internal connection buffer.
 *
 * @param conn  Connection handle.
 *
 * @return number of sent bytes, or a negative error value in case of failure.
 */
ssize_t ol_ceph_send(ol_ceph_connection *conn);

#endif /* __OL_CEPH_CONNECTION_H__ */
