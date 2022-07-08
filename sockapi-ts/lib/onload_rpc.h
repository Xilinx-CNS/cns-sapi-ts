/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Test API - Onload specific RPC
 *
 * Definition of TAPI for Onload specific remote calls
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __ONLOAD_RPC_H__
#define __ONLOAD_RPC_H__

#include "rcf_rpc.h"
#include "te_rpc_types.h"
#include "extensions.h"

/** Default Onload MSS */
#define ONLOAD_MSS 1448

/** Return code of function @a onload_delegated_send_prepare. */
typedef enum onload_delegated_send_rc rpc_onload_delegated_send_rc;

/**
 * Copy .iov_len  value to .iov_rlen in rpc_iovec structure.
 * 
 * @param iov       Buffers array
 * @param iovlen    Items number
 */
static void
iov_cp_rlen(rpc_iovec *iov, int iovlen)
{
    int i;

    for (i = 0; i < iovlen; i++)
        iov[i].iov_rlen = iov[i].iov_len;
}

/**
 * Initialize onload_delegation_* API to transmit data.
 * 
 * @param rpcs      RPC server handler
 * @param fd        File descriptor
 * @param size      Total data amount which is expected to be sent
 * @param flags     Flags
 * @param out       Onload delegated send API context, it will be
 *                  initialized during the call
 * 
 * @note See onload/extensions.h for details.
 * @note It's not byte ordering safe to make any changes in out->headers on
 *       the test side.
 * 
 * @return @c 0 on success or error code.
 */
extern rpc_onload_delegated_send_rc
    rpc_onload_delegated_send_prepare(rcf_rpc_server *rpcs, int fd,
                                      int size, unsigned flags,
                                      struct onload_delegated_send* out);

/**
 * Update @p ods context. It uses in case if data amount of sending packet
 * differs from MSS.
 * 
 * @param rpcs      RPC server handler
 * @param ods       ODS context
 * @param bytes     Data amount of the sending packet
 * @param push      Set PSH flag
 * 
 * @note See onload/extensions.h for details.
 */
extern void
    rpc_onload_delegated_send_tcp_update(rcf_rpc_server *rpcs,
                                         struct onload_delegated_send* ods,
                                         int bytes, int push);

/**
 * Advance @p ods context in accordance to sent data amount. It is called
 * after packet transmission.
 * 
 * @param rpcs      RPC server handler
 * @param ods       ODS context
 * @param bytes     Data amount of the sending packet
 * @param push      Set PSH flag
 * 
 * @note See onload/extensions.h for details.
 */
extern void
    rpc_onload_delegated_send_tcp_advance(rcf_rpc_server *rpcs,
                                          struct onload_delegated_send* ods,
                                          int bytes);

/**
 * Finalize and check packets transmission, retransmit in case of loss. It
 * can be considered as send() -like function.
 * 
 * @param rpcs      RPC server handler
 * @param fd        File descriptor
 * @param iov       Vector with sent data
 * @param riovlen   Actual data vector length
 * @param iovlen    Data vector length to be passed
 * @param flags     Flags
 * 
 * @note See onload/extensions.h for details.
 
 * @return Sent data amount or @c -1.
 */
extern int
    rpc_onload_delegated_send_complete_gen(rcf_rpc_server *rpcs, int fd,
                                           rpc_iovec* iov, int riovlen,
                                           int iovlen, int flags);

/**
 * Finalize and check packets transmission, retransmit in case of loss. It
 * can be considered as send() -like function.
 * 
 * @param rpcs      RPC server handler
 * @param fd        File descriptor
 * @param iov       Vector with sent data
 * @param iovlen    Actual data vector length
 * @param flags     Flags
 * 
 * @note See onload/extensions.h for details.
 
 * @return Sent data amount or @c -1.
 */
static inline int
rpc_onload_delegated_send_complete(rcf_rpc_server *rpcs, int fd,
                                   rpc_iovec* iov, int iovlen, int flags)
{
    iov_cp_rlen(iov, iovlen);
    return rpc_onload_delegated_send_complete_gen(rpcs, fd, iov, iovlen,
                                                  iovlen, flags);
}

/**
 * Cancel data transmission. Calling of this function is not necessary if
 * all requested data by function @a rpc_onload_delegated_send_prepare was
 * sent, otherwise this function must be called to finalize ODS API work.
 * 
 * @param rpcs      RPC server
 * @param fd        File descriptor
 * 
 * @note See onload/extensions.h for details.
 */
extern int rpc_onload_delegated_send_cancel(rcf_rpc_server *rpcs, int fd);

/**
 * Send iov data vector using ODS API.
 *
 * @param rpcs        RPC server handler
 * @param fd          File descriptor
 * @param iov         Data vector
 * @param iov_rlen    Actual data vector length
 * @param iov_len     Data vector length to be passed
 * @param flags       Flags (for @b onload_delegated_send_complete()
 *                    which understands @c RPC_MSG_DONTWAIT and
 *                    @c RPC_MSG_NOSIGNAL).
 * @param raw_send    Use raw send API for data transmission if @c TRUE;
 *                    otherwise do not actually send the data, only
 *                    pass it to @b onload_delegated_send_complete()
 *                    and rely on Onload to (re)transmit it.
 *
 * @note See onload/extensions.h for details.
 *
 * @return Sent data amount or @c -1.
 */
extern int rpc_od_send_iov_gen(rcf_rpc_server *rpcs, int fd, rpc_iovec *iov,
                               int riovlen, int iovlen,
                               rpc_send_recv_flags flags, te_bool raw_send);

/**
 * Send iov data vector using ODS API and raw send API
 *
 * @param rpcs        RPC server handler
 * @param fd          File descriptor
 * @param iov         Data vector
 * @param iov_len     Actual data vector length
 * @param flags       Flags
 *
 * @return Sent data amount or @c -1.
 */
static inline int
rpc_od_send_iov_raw(rcf_rpc_server *rpcs, int fd, rpc_iovec *iov,
                    int iovlen, rpc_send_recv_flags flags)
{
    iov_cp_rlen(iov, iovlen);
    return rpc_od_send_iov_gen(rpcs, fd, iov, iovlen, iovlen, flags, TRUE);
}

/**
 * Send iov data vector using ODS API, packets will be sent after calling
 * @a onload_delegated_send_complete.
 *
 * @param rpcs      RPC server handler
 * @param fd        File descriptor
 * @param iov       Data vector
 * @param iov_len   Actual data vector length
 * @param flags     Flags
 *
 * @return Sent data amount or @c -1.
 */
static inline int
rpc_od_send_iov(rcf_rpc_server *rpcs, int fd, rpc_iovec *iov, int iovlen,
                rpc_send_recv_flags flags)
{
    iov_cp_rlen(iov, iovlen);
    return rpc_od_send_iov_gen(rpcs, fd, iov, iovlen, iovlen, flags, FALSE);
}

/**
 * Send data using ODS API.
 *
 * @param rpcs      RPC server handler
 * @param fd        File descriptor
 * @param buf       Data buffer
 * @param len       Data amount to be sent
 * @param flags     Flags
 * @param raw_send  Use raw send API for data transmission if @c TRUE;
 *                  otherwise do not actually send the data, only
 *                  pass it to @b onload_delegated_send_complete()
 *                  and rely on Onload to (re)transmit it.
 *
 * @note See onload/extensions.h for details.

 * @return Sent data amount or @c -1.
 */
static inline int rpc_od_send_gen(rcf_rpc_server *rpcs, int fd,
                                  const void *buf, size_t len,
                                  rpc_send_recv_flags flags,
                                  te_bool raw_send)
{
    rpc_iovec iov;

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)buf;
    iov.iov_len = len;
    if (buf != NULL)
        iov.iov_rlen = len;
    else
        iov.iov_rlen = 0;

    return rpc_od_send_iov_gen(rpcs, fd, &iov, 1, 1, flags, raw_send);
}

/**
 * Send data using ODS API and raw send API
 *
 * @param rpcs        RPC server handler
 * @param fd          File descriptor
 * @param buf         Data buffer
 * @param len         The buffer length
 * @param flags       Flags
 *
 * @note See onload/extensions.h for details.
 *
 * @return Sent data amount or @c -1.
 */
static inline int
rpc_od_send_raw(rcf_rpc_server *rpcs, int fd, const void *buf, size_t len,
                rpc_send_recv_flags flags)
{
    return rpc_od_send_gen(rpcs, fd, buf, len, flags, TRUE);
}

/**
 * Send data using ODS API, packets will be sent after calling
 * @a onload_delegated_send_complete.
 *
 * @param rpcs      RPC server handler
 * @param fd        File descriptor
 * @param buf       Data buffer
 * @param len       The buffer length
 * @param flags     Flags
 *
 * @note See onload/extensions.h for details.
 *
 * @return Sent data amount or @c -1.
 */
static inline int
rpc_od_send(rcf_rpc_server *rpcs, int fd, const void *buf, size_t len,
            rpc_send_recv_flags flags)
{
    return rpc_od_send_gen(rpcs, fd, buf, len, flags, FALSE);
}

/**
 * Create a socket where unicast is non-accelerated.
 *
 * @param rpcs      RPC server handle.
 * @param domain    Communication domain.
 * @param type      Socket type.
 * @param protocol  Protocol.
 *
 * @return Socket descriptor on success, -1 on failure.
 */
extern int rpc_onload_socket_unicast_nonaccel(rcf_rpc_server *rpcs,
                                              rpc_socket_domain domain,
                                              rpc_socket_type type,
                                              rpc_socket_proto protocol);

#endif /* !__ONLOAD_RPC_H__ */
