/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_waitall_stream MSG_WAITALL flag for stream sockets
 *
 * @objective Check support of @c MSG_WAITALL flag for stream sockets.
 *            Check that @c MSG_WAITALL flag does not affect subsequent
 *            operations on the socket.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *                  - @ref arg_types_env_peer2peer_fake
 * @param func      Function to be used in the test to receive data:
 *                  - @ref arg_types_recv_func_with_flags
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_waitall_stream"
#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define DATA_BULK       512  /**< Size of data to be sent */
static char rx_buf[DATA_BULK * 2];


int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char *func;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;
    ssize_t len;
    size_t  len1;
    size_t  len2;

    char    *tx_buf1 = NULL;
    char    *tx_buf2 = NULL;
    te_bool  done = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);

    TEST_STEP("Choose randomly @b len1 and @b len2 - sizes of data "
              "to be sent.");

    if ((tx_buf1 = te_make_buf(1, DATA_BULK, &len1)) == NULL)
        TEST_STOP;

    if ((tx_buf2 = te_make_buf(1, DATA_BULK, &len2)) == NULL)
        TEST_STOP;

    TEST_STEP("Establish TCP connection between a pair of sockets on IUT "
              "and Tester.");
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("On IUT call @p func with @c RCF_RPC_CALL, passing "
              "@c MSG_WAITALL flag and buffer length @b len1 + @b len2.");
    pco_iut->op = RCF_RPC_CALL;
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, len1 + len2,
                       RPC_MSG_WAITALL);

    TEST_STEP("Send from the Tester socket @b len1 bytes.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf1, len1, 0);

    TEST_STEP("Wait for a while to be sure that data reaches IUT, and then "
              "check that @p func is not unblocked. Then send @b len2 "
              "bytes from the Tester socket.");

    TAPI_WAIT_NETWORK;

    rc = rcf_rpc_server_is_op_done(pco_iut, &done);
    if (rc != 0)
        TEST_VERDICT("rcf_rpc_server_is_op_done() failed with %r", rc);
    if (done)
    {
        ERROR_VERDICT("Receive function called with MSG_WAITALL was "
                      "unblocked after receiving part of the data");
    }
    else
    {
        RPC_SEND(rc, pco_tst, tst_s, tx_buf2, len2, 0);
    }

    TEST_STEP("Check that @p func unblocks, returning all the data sent "
              "from the Tester socket.");

    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, len1 + len2,
                       RPC_MSG_WAITALL);

    if (len < 0)
    {
        TEST_VERDICT("Tested function called with MSG_WAITALL failed "
                     "with error " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    if (len != (ssize_t)(len1 + len2))
    {
        INFO("%d bytes is received instead of %u",
             (int)len, (unsigned)(len1 + len2));
        TEST_VERDICT("Incorrect amount of data was received with "
                     "MSG_WAITALL flag");
    }
    if (memcmp(tx_buf1, rx_buf, len1) != 0 ||
        memcmp(tx_buf2, rx_buf + len1, len2) != 0)
    {
        TEST_VERDICT("Data received on IUT with MSG_WAITALL does not match "
                     "sent data");
    }

    TEST_STEP("Send @b len1 bytes from the Tester socket again.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf1, len1, 0);

    TEST_STEP("Call again @p func on the IUT socket, but this time without "
              "@c MSG_WAITALL flag, passing @b len1 + @b len2 as buffer "
              "length. Check that it returns @b len1 bytes sent from "
              "Tester.");

    memset(rx_buf, 0, sizeof(rx_buf));
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, len1 + len2, 0);
    if (len < 0)
    {
        TEST_VERDICT("Tested function called without MSG_WAITALL failed "
                     "with error " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf1, rx_buf, len1, len,
                          "Tested function called without MSG_WAITALL");

    if (done)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf1);
    free(tx_buf2);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}

