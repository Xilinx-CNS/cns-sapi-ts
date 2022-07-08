/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 * 
 * Helper functions implementation for Onload delegated send API
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 * 
 * $Id$
 */

#include "sockapi-test.h"
#include "onload_rpc.h"
#include "od_send.h"
#include "sockapi-ta.h"
#include "tapi_sockets.h"

/* See description in od_send.h */
int
od_send_ext(rcf_rpc_server *pco_iut, int iut_s, const void *sendbuf,
            int length, int flags, te_bool raw_send,
            int ifindex, int raw_socket, size_t *send_complete)
{
    struct onload_delegated_send ods;
    uint8_t    headers[OD_HEADERS_LEN];
    rpc_iovec  iov[2];
    int        sent = 0;
    int        rc;
    te_bool    dont_jump = RPC_AWAITING_ERROR(pco_iut);
    rcf_rpc_op op = pco_iut->op;

    if (pco_iut->op != RCF_RPC_WAIT)
    {
        memset(&ods, 0, sizeof(ods));
        ods.headers_len = OD_HEADERS_LEN;
        ods.headers = headers;

        pco_iut->op = RCF_RPC_CALL_WAIT;
        RPC_DONT_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_onload_delegated_send_prepare(pco_iut, iut_s, length, 0,
                                               &ods);

        while (sent < length)
        {
            iov[0].iov_len = ods.headers_len;
            iov[0].iov_base = ods.headers;
            iov[1].iov_base = (void *)sendbuf + sent;
            iov[1].iov_len = od_get_min(&ods);
            if (iov[1].iov_len == 0)
                break;

            rpc_onload_delegated_send_tcp_update(pco_iut, &ods,
                                                 iov[1].iov_len, TRUE);

            if (raw_send)
            {
                rc = tapi_sock_raw_tcpv4_send(pco_iut, iov, 2,
                                              ifindex, raw_socket, TRUE);
            }
            rpc_onload_delegated_send_tcp_advance(pco_iut, &ods,
                                                  iov[1].iov_len);

            sent += iov[1].iov_len;
        }
    }

    iov[0].iov_base = (void *)sendbuf;
    iov[0].iov_len = sent;
    if (dont_jump)
        RPC_AWAIT_IUT_ERROR(pco_iut);
    pco_iut->op = op;

    if (send_complete != NULL)
        *send_complete = sent;
    rc = rpc_onload_delegated_send_complete(pco_iut, iut_s, iov, 1, flags);

    if (pco_iut->op != RCF_RPC_WAIT && rc < length && rc > 0)
        rpc_onload_delegated_send_cancel(pco_iut, iut_s);

    return rc;
}

