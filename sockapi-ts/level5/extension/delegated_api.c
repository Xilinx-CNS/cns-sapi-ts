/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-delegated_api onload_delegated_* API usage
 *
 * @objective  Usage sample of onload_delegated_* API.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param length        Data length to be sent
 * @param single_rpc    Use single RPC to perform data transmission
 * @param raw_send      Use @a oo_raw_send for data transmission if @c TRUE 
 *                      otherwise @a onload_delegated_send_complete is used
 * @param use_iov       Use _iov functions to send data
 
 * 
 * @type Conformance.
 *
 * @par Scenario:
 * -# Create TCP connection between IUT and tester.
 * -# Send data from IUT with Onload delegated API, use various RPCs in
 *    dependence on arguments @p use_iov, @p single_rpc and @p raw_send.
 * -# Receive data on tester.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/delegated_api"

#include "sockapi-test.h"
#include "template.h"
#include "onload_rpc.h"
#include "od_send.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if = NULL;
    te_bool                    single_rpc = FALSE;
    te_bool                    raw_send = TRUE;
    te_bool                    use_iov = TRUE;

    rpc_iovec *iov      = NULL;
    char      *sendbuf  = NULL;
    char      *recvbuf  = NULL;
    int        iovlen = 10;
    int        length;
    int        iut_s  = -1;
    int        tst_s  = -1;
    int        raw_socket = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(use_iov);
    TEST_GET_BOOL_PARAM(single_rpc);
    TEST_GET_BOOL_PARAM(raw_send);
    TEST_GET_INT_PARAM(length);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    sockts_extend_cong_window(pco_iut, iut_s, pco_tst, tst_s);

    if (use_iov)
        iov = init_iovec(iovlen, length, &sendbuf);
    else
        sendbuf = te_make_buf_by_len(length);

    if (single_rpc)
    {
        if (use_iov)
        {
            if (raw_send)
                rpc_od_send_iov_raw(pco_iut, iut_s, iov, iovlen, 0);
            else
                rpc_od_send_iov(pco_iut, iut_s, iov, iovlen, 0);
        }
        else
        {
            if (raw_send)
                rpc_od_send_raw(pco_iut, iut_s, sendbuf, length, 0);
            else
                rpc_od_send(pco_iut, iut_s, sendbuf, length, 0);
        }
    }
    else
        od_send(pco_iut, iut_s, sendbuf, length, 0, raw_send,
                iut_if->if_index, raw_socket);

    recvbuf = te_make_buf_by_len(length);
    rc = 0;
    while (rc < length)
        rc += rpc_recv(pco_tst, tst_s, recvbuf + rc, length - rc, 0);

    if (memcmp(sendbuf, recvbuf, length) != 0)
        TEST_VERDICT("Received data differs from the sent");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (raw_send)
        CLEANUP_RPC_CLOSE(pco_iut, raw_socket);

    if (use_iov)
        release_iovec(iov, iovlen);

    free(sendbuf);
    free(recvbuf);

    TEST_END;
}
