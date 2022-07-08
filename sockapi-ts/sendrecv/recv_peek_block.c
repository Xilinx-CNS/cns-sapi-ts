/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_peek_block MSG_PEEK does not affect blocking
 *
 * @objective Check that @c MSG_PEEK flag does not affect receiver
 *            blocking properties.
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

#define TE_TEST_NAME  "sendrecv/recv_peek_block"
#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define DATA_BULK       1024  /**< Size of data to be sent */
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

    /* Prepare sockets */

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(func);

    TEST_STEP("Create a connected pair of sockets of type @p sock_type on "
              "IUT and Tester.");
    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    TEST_STEP("Call @p func on the IUT socket with RCF_RPC_CALL, passing "
              "to it @c MSG_PEEK flag.");
    pco_iut->op = RCF_RPC_CALL;
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                       MSG_PEEK);

    TEST_STEP("Wait for a while and check that it still hangs blocked.");
    TAPI_WAIT_NETWORK;
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                          MSG_PEEK);
        if (rc < 0)
        {
            TEST_VERDICT("Receive function called with MSG_PEEK failed: %r",
                         RPC_ERRNO(pco_iut));
        }
        else
        {
            TEST_VERDICT("The function does not block even with MSG_PEEK");
        }
    }

    TEST_STEP("Send some data from the Tester socket.");
    te_fill_buf(tx_buf, sizeof(tx_buf));
    if (rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK) != DATA_BULK)
        TEST_FAIL("Cannot send data from TST");

    TEST_STEP("Wait for @p func termination, check that it successully "
              "returns data sent from Tester.");
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                       MSG_PEEK);
    if (len < 0)
    {
        TEST_VERDICT("Receive function called with MSG_PEEK unblocked "
                     "but failed with errno %r", RPC_ERRNO(pco_iut));
    }
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, DATA_BULK, len);

    TEST_STEP("Call @p func again on the IUT socket, this time without "
              "@c MSG_PEEK flag, check that the same data is returned.");
    memset(rx_buf, 0, sizeof(rx_buf));
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, DATA_BULK, len);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
