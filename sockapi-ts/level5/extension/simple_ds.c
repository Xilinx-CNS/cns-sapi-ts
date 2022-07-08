/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 *
 */

/** @page extension-simple_ds Send data using delegated send API
 *
 * @objective  Check that simple case of sending using delegated send API works correctly
 *
 * @param length        Data length to be sent
 * @param raw_send      Use Onload API for raw send
 *
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/simple_ds"

#include "sockapi-test.h"
#include "template.h"
#include "onload_rpc.h"
#include "od_send.h"
#include "sockapi-ta.h"
#include "tapi_sockets.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if = NULL;
    te_bool                    raw_send = TRUE;

    struct onload_delegated_send ods;
    uint8_t                      headers[OD_HEADERS_LEN];
    rpc_iovec                    iov[2];

    char      *sendbuf  = NULL;
    char      *recvbuf  = NULL;
    int        length;
    int        sent = 0;
    int        iut_s  = -1;
    int        tst_s  = -1;
    int        raw_socket = -1;
    te_bool    readable = TRUE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(raw_send);
    TEST_GET_INT_PARAM(length);

    TEST_STEP("Create TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    sendbuf = te_make_buf_by_len(length);

    memset(&ods, 0, sizeof(ods));
    ods.headers_len = OD_HEADERS_LEN;
    ods.headers = headers;

    TEST_STEP("Create raw socket if @p raw_send is @c TRUE");
    if (raw_send)
    {
        raw_socket = rpc_socket(pco_iut, RPC_AF_PACKET, RPC_SOCK_RAW,
                                RPC_IPPROTO_RAW);
    }

    TEST_STEP("Prepare headers for sending.");
    rc = rpc_onload_delegated_send_prepare(pco_iut, iut_s, length, 0,
                                           &ods);

    TEST_STEP("Send data from IUT with Onload delegated API, use raw send API "
              "if @p raw_send is @ TRUE");
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
            CHECK_RC(tapi_sock_raw_tcpv4_send(pco_iut, iov, 2,
                                              iut_if->if_index,
                                              raw_socket, TRUE));
        }

        rpc_onload_delegated_send_tcp_advance(pco_iut, &ods,
                                              iov[1].iov_len);

        sent += iov[1].iov_len;
    }

    iov[0].iov_base = (void *)sendbuf;
    iov[0].iov_len = sent;

    rc = rpc_onload_delegated_send_complete(pco_iut, iut_s, iov, 1, 0);

    /* Receive data on tester. */
    recvbuf = te_make_buf_by_len(length);
    rc = 0;

    while (rc < length)
    {
        RPC_GET_READABILITY(readable, pco_tst, tst_s, TAPI_WAIT_NETWORK_DELAY);
        if (readable)
            rc += rpc_recv(pco_tst, tst_s, recvbuf + rc, length - rc, 0);
        else
            break;
    }

    RPC_GET_READABILITY(readable, pco_tst, tst_s, 0);
    if (readable)
    {
        TEST_VERDICT("Socket tst_s is not expected to be readable, "
                     "but it is");
    }

    if (rc != length)
    {
        TEST_VERDICT("Unexpected amount of data is received: %d instead of %d",
                     rc, length);
    }

    if (memcmp(sendbuf, recvbuf, length) != 0)
        TEST_VERDICT("Received data differs from the sent");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (raw_send)
        CLEANUP_RPC_CLOSE(pco_iut, raw_socket);

    free(sendbuf);
    free(recvbuf);

    TEST_END;
}
