/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_dgram_small_buf Receive datagram with smaller buffer
 *
 * @objective Check behaviour when datagram larger than provided buffer
 *            is received.
 *
 * @type conformance, compatibility
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func        Function to be used in the test to receive data:
 *                    - @ref arg_types_recv_func_with_flags
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_dgram_small_buf"
#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static char rx_buf[DATA_BULK];

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
    size_t  len;
    ssize_t recv_len;

    char *tx_buf = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);

    /* Fixme: disable msg_flags auto check. In case of incomplete reading of
     * a datagram flag MSG_TRUNC is set, what is detected by the check. If
     * msg_flags check is desired then explicit call of recvmsg() like
     * functions should be done with subsequent flags check.
     *
     * This does not require any reversion, i.e. the check is disabled only
     * for the current test run. */
    tapi_rpc_msghdr_msg_flags_init_check(FALSE);

    if (strcmp(func, "onload_zc_recv") == 0)
        TEST_VERDICT("The test is not suitable for onload_zc_recv()"
                     " function");

    TEST_STEP("Create a pair of connected UDP sockets on IUT and Tester.");
    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    if ((tx_buf = te_make_buf(2, 1000, &len)) == NULL)
        TEST_STOP;

    TEST_STEP("Send a datagram from the Tester socket.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, len, 0);

    TEST_STEP("Try to read one byte less than was sent on the IUT socket, "
              "using @p func. Check that it succeeds.");
    len--;
    recv_len = recv_by_func(func, pco_iut, iut_s, rx_buf, len, 0);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, len, recv_len);

    TEST_STEP("Call recv() on the IUT socket with @c MSG_DONTWAIT flag, "
              "check that it fails with EAGAIN.");
    RPC_AWAIT_ERROR(pco_iut);
    if (rpc_recv(pco_iut, iut_s, rx_buf, len, RPC_MSG_DONTWAIT) >= 0)
    {
        TEST_VERDICT("recv() returned success after reading part of "
                     "a received datagram");
    }

    if (pco_iut->_errno != RPC_EWOULDBLOCK && pco_iut->_errno != RPC_EAGAIN)
    {
        TEST_VERDICT("After reading part of a received datagram, recv() "
                     "failed with unexpected errno %r", RPC_ERRNO(pco_iut));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf);

    TEST_END;
}

