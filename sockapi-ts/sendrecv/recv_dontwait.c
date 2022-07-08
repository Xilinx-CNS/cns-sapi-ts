/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_dontwait Support of MSG_DONTWAIT flag for receiving
 *
 * @objective Check that @c MSG_DONTWAIT flag is supported for receiving
 *            and it's not kept in socket for subsequent operations.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type   Socket type:
 *                    - @c SOCK_STREAM
 *                    - @c SOCK_DGRAM
 * @param func        Function to be used in the test to receive data:
 *                    - @ref arg_types_recv_func_with_flags
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_dontwait"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"


#define DATA_BULK       1024  /**< Size of data to be sent */

/** Timeout to assume that data do not arrive */
#define NO_DATA_TIMEOUT_MSEC    10000


static char tx_buf[DATA_BULK];
static char rx_buf[DATA_BULK];


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
    te_bool done;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(func);

    TEST_STEP("Create a pair of connected sockets on IUT and Tester "
              "according to @p sock_type.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Check that data can be sent in both directions between "
              "the sockets.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("Call @p func with @c MSG_DONTWAIT on IUT, check that it "
              "fails with @c EAGAIN.");
    te_fill_buf(tx_buf, DATA_BULK);
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                       RPC_MSG_DONTWAIT);

    if (len >= 0)
        TEST_VERDICT("The first call of the tested function succeeded");

    if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
    {
        TEST_VERDICT("The first call of the tested function failed "
                     "with unexpected error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }

    TEST_STEP("Send some data from the Tester socket and wait for a "
              "while.");

    if (rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK) != DATA_BULK)
        TEST_FAIL("Cannot send data from TST");

    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @p func again with @c MSG_DONTWAIT on IUT, check that "
              "now it succeeds.");
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                       RPC_MSG_DONTWAIT);
    if (len < 0)
    {
        TEST_VERDICT("The second call of the tested function failed "
                     "with error " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }

    SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf, rx_buf, DATA_BULK, len,
                          "The second call of the tested function");

    TEST_STEP("Call @p func without @c MSG_DONTWAIT on IUT, check that "
              "it blocks.");
    pco_iut->op = RCF_RPC_CALL;
    recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);

    TAPI_WAIT_NETWORK;
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
    {
        ERROR_VERDICT("The function does not block even without "
                      "MSG_DONTWAIT");
    }

    TEST_STEP("Send some data from the Tester socket.");
    if (rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK) != DATA_BULK)
        TEST_FAIL("Cannot send data from TST");

    TEST_STEP("Check that on IUT @p func unblocked and returned sent data.");
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);
    if (len < 0)
    {
        TEST_VERDICT("The third call of the tested function failed "
                     "with error " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf, rx_buf, DATA_BULK, len,
                          "The third call of the tested function");

    if (done)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
