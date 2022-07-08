/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_peek_dgram MSG_PEEK flag does not mix datagrams
 *
 * @objective Check that @c MSG_PEEK flag does not mix data from
 *            different datagrams.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param pco_iut   PCO with IUT
 * @param iut_addr  Network address on IUT
 * @param pco_tst1  The first Tester PCO
 * @param pco_tst2  The second Tester PCO
 * @param func      Function to be used in the test to receive data:
 *                  - @ref arg_types_recv_func_with_flags
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_peek_dgram"
#include "sockapi-test.h"
#include "rpc_sendrecv.h"

int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char *func;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst1_s = -1;
    int tst2_s = -1;
    size_t  pkt_len;
    size_t  min_len;
    size_t  len1;
    size_t  len2;
    ssize_t len;

    char *rx_buf;
    char *tx_buf1 = NULL;
    char *tx_buf2 = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(pkt_len);

    rx_buf = malloc(pkt_len);
    min_len = pkt_len/2;

    if ((tx_buf1 = te_make_buf(min_len, pkt_len, &len1)) == NULL)
        TEST_STOP;
    if ((tx_buf2 = te_make_buf(min_len, pkt_len, &len2)) == NULL)
        TEST_STOP;

    TEST_STEP("Create UDP socket @b iut_s on IUT, bind it to @p iut_addr.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("Create UDP socket @b tst1_s on @p pco_tst1, connect it "
              "to @p iut_addr.");
    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst1, tst1_s, iut_addr);

    TEST_STEP("Create UDP socket @b tst2_s on @p pco_tst2, connect it "
              "to @p iut_addr.");
    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst2, tst2_s, iut_addr);

    TEST_STEP("Send some data from @b tst1_s.");
    RPC_SEND(rc, pco_tst1, tst1_s, tx_buf1, len1, 0);

    TEST_STEP("Call @p func on @b iut_s with @c MSG_PEEK flag, "
              "check that it returns sent data.");
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, pkt_len,
                       RPC_MSG_PEEK);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf1, rx_buf, len1, len);

    TEST_STEP("Send some data from @b tst2_s.");
    RPC_SEND(rc, pco_tst2, tst2_s, tx_buf2, len2, 0);

    TEST_STEP("Call @p func on @b iut_s with @c MSG_PEEK, check that it "
              "again returns data sent from @b tst1_s, not data sent "
              "from @b tst2_s.");
    memset(rx_buf, 0, pkt_len);
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, pkt_len,
                       RPC_MSG_PEEK);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf1, rx_buf, len1, len);

    TEST_STEP("Call @p func on @b iut_s without @c MSG_PEEK, check that "
              "it again returns data sent from @b tst1_s, not data sent "
              "from @b tst2_s.");
    memset(rx_buf, 0, pkt_len);
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, pkt_len, 0);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf1, rx_buf, len1, len);

    TEST_STEP("Call @p func on @b iut_s with @c MSG_PEEK, check that "
              "it finally returns data sent from @b tst2_s.");
    memset(rx_buf, 0, pkt_len);
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, pkt_len,
                       RPC_MSG_PEEK);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf2, rx_buf, len2, len);

    TEST_STEP("Call @p func on @b iut_s without @c MSG_PEEK, check that "
              "it again returns data sent from @b tst2_s.");
    memset(rx_buf, 0, pkt_len);
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, pkt_len, 0);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf2, rx_buf, len2, len);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    free(tx_buf1);
    free(tx_buf2);

    TEST_END;
}
