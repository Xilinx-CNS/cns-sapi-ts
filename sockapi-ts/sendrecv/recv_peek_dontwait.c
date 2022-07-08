/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_peek_dontwait MSG_PEEK and MSG_DONTWAIT flags together
 *
 * @objective Check that @c MSG_PEEK and @c MSG_DONTWAIT flags may be
 *            used simultaneously.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func      Function to be used in the test to receive data:
 *                  - @ref arg_types_recv_func_with_flags
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_peek_dontwait"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static char rx_buf[DATA_BULK];
static char tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;
    const char         *func;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;
    ssize_t len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(func);

    TEST_STEP("Create a pair of connected sockets of type @p sock_type "
              "on IUT and Tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Check that data can be sent and received over the "
              "sockets in both directions.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    te_fill_buf(tx_buf, DATA_BULK);

    TEST_STEP("Call @p func on the IUT socket, passing to it "
              "@c MSG_DONTWAIT and @c MSG_PEEK flags. Check that it "
              "fails with @c EAGAIN or @c EWOULDBLOCK.");
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                       RPC_MSG_DONTWAIT | RPC_MSG_PEEK);

    if (len >= 0)
    {
        TEST_VERDICT("The first call of the receiving function succeeded");
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EWOULDBLOCK &&
             RPC_ERRNO(pco_iut) != RPC_EAGAIN)
    {
        TEST_VERDICT("The first call of the receiving function failed "
                     "with unexpected errno %r", RPC_ERRNO(pco_iut));
    }

    TEST_STEP("Send some data from the Tester socket and wait for a "
              "while.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, sizeof(tx_buf), 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Again call @p func on the IUT socket with @c MSG_DONTWAIT "
              "and @c MSG_PEEK flags. Check that it returns data sent from "
              "the Tester socket.");
    memset(rx_buf, 0, sizeof(rx_buf));
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                       RPC_MSG_DONTWAIT | RPC_MSG_PEEK);
    if (len < 0)
    {
        TEST_VERDICT("Peer sent data to the socket, but %s() with "
                     "MSG_DONTWAIT|MSG_PEEK flags failed with errno %s",
                     func, errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf, rx_buf, DATA_BULK, len,
                          "The second call of the receiving function");

    TEST_STEP("Call @p func the third time on the IUT socket, this time "
              "passing only @c MSG_DONTWAIT flag to it. Check that it "
              "again returns data sent from the Tester socket.");
    memset(rx_buf, 0, sizeof(rx_buf));
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                       RPC_MSG_DONTWAIT);
    SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf, rx_buf, DATA_BULK, len,
                          "The third call of the receiving function");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
