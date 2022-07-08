/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 *
 * $Id$
 */

/** @page sendrecv-recv_dgram_wild  Receive operations with datagram sockets
 *                                  via set of @b recv_func functions
 *
 * @objective Check support of read operations with DGRAM sockets.
 *
 * @type conformance
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on TESTER
 * @param iut_addr              Network address on IUT
 * @param tst_addr              Network address on TESTER
 * @param func                  Function used to read data
 * @param use_wildcard          Use wildcard address for IUT
 *
 * @par Scenario:
 *  -# open two SOCK_DGRAM sockets @p tst_s and @p iut_s
 *     at @p pco_tst and @p pco_iut accordingly;
 *  -# Bind @p iut_s socket accroding to @p use_wildcard parameter.
 *  -# send data from @p tst_s and recv on @p iut_s
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_dgram_wild"

#include "sockapi-test.h"

#define SEND_AND_CHECK(_sender, _sender_s) \
    do {                                                              \
        te_fill_buf(tx_buf, tx_buf_len);                              \
        RPC_WRITE(rc, _sender, _sender_s, tx_buf, tx_buf_len);        \
        TAPI_WAIT_NETWORK;                                            \
        rc = func(pco_iut, iut_s, rx_buf, rx_buf_len, 0);             \
        SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, tx_buf_len, rc);   \
    } while(0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    rpc_recv_f              func;
    const struct sockaddr  *iut_addr1;
    const struct sockaddr  *iut_addr2;
    const struct sockaddr  *tst1_addr;
    struct sockaddr_storage connect_addr;
    int                     iut_s = -1;
    int                     tst1_s = -1;
    int                     tst2_s = -1;
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  tx_buf_len;
    size_t                  rx_buf_len;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_RECV_FUNC(func);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR_NO_PORT(iut_addr2);

    memcpy(&connect_addr, iut_addr2, te_sockaddr_get_size(iut_addr2));
    te_sockaddr_set_port(SA(&connect_addr),
                         te_sockaddr_get_port(iut_addr1));

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr1);

    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst1, tst1_s, iut_addr1);

    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst1_addr),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst2, tst2_s, SA(&connect_addr));

    SEND_AND_CHECK(pco_tst1, tst1_s);
    TAPI_WAIT_NETWORK;
    SEND_AND_CHECK(pco_tst2, tst2_s);
    TAPI_WAIT_NETWORK;
    SEND_AND_CHECK(pco_tst1, tst1_s);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
