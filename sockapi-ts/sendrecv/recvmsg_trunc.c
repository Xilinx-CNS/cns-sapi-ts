/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recvmsg_trunc MSG_TRUNC is returned by recvmsg()
 *
 * @objective Check that @c MSG_TRUNC flag is returned in message flags
 *            when datagram larger than provided buffer is received.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.5
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param recv_f    Receiving function to check:
 *                  - @ref arg_types_recv_func_with_msg
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recvmsg_trunc"
#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define DATA_BULK       1024
static char rx_buf[DATA_BULK];
static char tx_buf[DATA_BULK];


int
main(int argc, char *argv[])
{
    /* Environment variables */

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int        recv_len = DATA_BULK - 1;
    rpc_iovec  vector = { .iov_base = rx_buf,
                          .iov_len = recv_len,
                          .iov_rlen = sizeof(rx_buf) };
    rpc_msghdr msg = { .msg_name = NULL,
                       .msg_namelen = 0,
                       .msg_iov = &vector,
                       .msg_iovlen = 1,
                       .msg_control = NULL,
                       .msg_controllen = 0,
                       .msg_flags = 0,
                       .msg_rnamelen = 0,
                       .msg_riovlen = 1,
                       .msg_cmsghdr_num = 0,
                       .msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK };

    int iut_s = -1;
    int tst_s = -1;
    int len;

    rpc_msg_read_f recv_f;

    TEST_START;

    /* Prepare sockets */

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_MSG_READ_FUNC(recv_f);

    if (strcmp(rpc_msg_read_func_name(recv_f), "onload_zc_recv") == 0)
        TEST_VERDICT("The test is not suitable for onload_zc_recv() "
                     "function");

    TEST_STEP("Create a pair of connected @c SOCK_DGRAM sockets on IUT and "
              "Tester.");
    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    TEST_STEP("Send a datagram from the Tester socket.");

    te_fill_buf(tx_buf, DATA_BULK);
    memset(rx_buf, 0, sizeof(rx_buf));
    if (rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK) != DATA_BULK)
        TEST_FAIL("Cannot send a datagram from TST");

    TEST_STEP("Call @p recv_f function to receive data on the IUT socket, "
              "passing to it a buffer one byte shorter than datagram sent "
              "from Tester.");
    len = recv_f(pco_iut, iut_s, &msg, 0);

    TEST_STEP("Check that expected data was received and that @c MSG_TRUNC "
              "flag was set in msg.msg_flags.");
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, recv_len, len);
    sockts_check_msg_flags(&msg, RPC_MSG_TRUNC);

    TEST_STEP("Call @p recv_f function the second time on the IUT socket "
              "with @c MSG_DONTWAIT flag, check that it fails with "
              "@c EAGAIN.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = recv_f(pco_iut, iut_s, &msg, RPC_MSG_DONTWAIT);
    if (rc >= 0)
    {
        TEST_VERDICT("Second call of receive function succeeded "
                     "instead of failing with EAGAIN");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                        "The second call of receive function failed");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

