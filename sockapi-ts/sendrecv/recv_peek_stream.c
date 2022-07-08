/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_peek_stream MSG_PEEK for stream socket
 *
 * @objective Check @c MSG_PEEK functionality for stream sockets.
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

#define TE_TEST_NAME  "sendrecv/recv_peek_stream"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"


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
    size_t  pkt_len;
    size_t  min_len;
    size_t  rcv_len;
    size_t  len1;
    size_t  len2;
    ssize_t len;

    char *tx_buf1 = NULL;
    char *tx_buf2 = NULL;

    char *rx_buf;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(pkt_len);

    rx_buf = malloc(pkt_len * 2); /* for both portions */
    min_len = pkt_len/2;

    if ((tx_buf1 = te_make_buf(min_len, pkt_len, &len1)) == NULL)
        TEST_STOP;

    if ((tx_buf2 = te_make_buf(min_len, pkt_len, &len2)) == NULL)
        TEST_STOP;

    TEST_STEP("Create a pair of connected TCP sockets on IUT and Tester.");
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Send some data from the Tester socket.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf1, len1, 0);

    /*
     * Data may be sent in more than one packet, so wait until
     * it all arrives.
     */
    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @b func on the IUT socket, passing @c MSG_PEEK flag "
              "to it. Check that it returns data sent from Tester.");
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, pkt_len,
                       RPC_MSG_PEEK);
    if (len < 0)
    {
        TEST_VERDICT("The receive function failed with errno %r when "
                     "called with MSG_PEEK", RPC_ERRNO(pco_iut));
    }
    SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf1, rx_buf, len1, len,
                          "Receiving data with MSG_PEEK");

    TEST_STEP("Send more data from Tester.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf2, len2, 0);

    TEST_STEP("Wait for a while and call @p func again on the IUT socket; "
              "check that it returns all the data sent from Tester "
              "(including the data returned previously with @c MSG_PEEK "
              "flag).");
    TAPI_WAIT_NETWORK;
    rcv_len = pkt_len * 2;
    memset(rx_buf, 0, rcv_len);
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, rcv_len, 0);
    if (len < 0)
    {
        TEST_VERDICT("The second call of receiving function failed "
                     "with errno %r", RPC_ERRNO(pco_iut));
    }

    if (len != (ssize_t)(len1 + len2))
    {
        INFO("%d bytes is received instead of %u",
             (int)len, (unsigned)(len1 + len2));
        TEST_VERDICT("Incorrect amount of data is received when "
                     "calling receiving function without MSG_PEEK");
    }

    if (memcmp(tx_buf1, rx_buf, len1) != 0)
        TEST_VERDICT("Data received on IUT does not match sent data");

    if (memcmp(tx_buf2, rx_buf + len1, len2) != 0)
        TEST_VERDICT("Data received on IUT does not match sent data");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf1);
    free(tx_buf2);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
