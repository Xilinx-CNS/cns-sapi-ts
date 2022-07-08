/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros and functions for Onload delegated send API.
 *
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __OD_SEND_H__
#define __OD_SEND_H__

/**
 * Send data using ODS API, call required RPC functions step by step from
 * the test.
 *
 * @param pco_iut       RPC server handler
 * @param iut_s         Socket
 * @param sendbuf       Data buffer to be send
 * @param length        The buffer length
 * @param flags         Flags
 * @param raw_send      Use raw send API to send data
 * @param ifindex       Interface index to send packet for raw sending
 *                      if @p raw_send is @c TRUE
 * @param raw_socket    Raw socket for sending data if @p raw_send is @c TRUE
 * @param send_complete Data amount which is requested to be sent when
 *                      _complete() is called.
 *
 * @return Sent bytes number or @c -1
 */
extern int od_send_ext(rcf_rpc_server *pco_iut, int iut_s,
                       const void *sendbuf, int length, int flags,
                       te_bool raw_send, int ifindex, int raw_socket,
                       size_t *send_complete);

/**
 * Send data using ODS API, call required RPC functions step by step from
 * the test.
 *
 * @param pco_iut       RPC server handler
 * @param iut_s         Socket
 * @param sendbuf       Data buffer to be send
 * @param length        The buffer length
 * @param flags         Flags
 * @param raw_send      Use raw send API to send data
 * @param ifindex       Interface index to send packet for raw sending
 *                      if @p raw_send is @c TRUE
 * @param raw_socket    Raw socket for sending data if @p raw_send is @c TRUE
 *
 * @return Sent bytes number or @c -1
 */
static inline int
od_send(rcf_rpc_server *pco_iut, int iut_s, const void *sendbuf, int length,
        int flags, te_bool raw_send, int ifindex,  int raw_socket)
{
    return od_send_ext(pco_iut, iut_s, sendbuf, length, flags, raw_send,
                       ifindex, raw_socket, NULL);
}

#endif /* __OD_SEND_H__ */
