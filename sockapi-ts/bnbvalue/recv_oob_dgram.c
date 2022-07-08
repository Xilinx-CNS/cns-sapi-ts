/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-recv_oob_dgram Behavior of receiving functions on socket of SOCK_DGRAM type if flag MSG_OOB passed
 *
 * @objective Check that receiving functions correctly process @c MSG_OOB
 *            flag if called on socket of the @c SOCK_DGRAM type.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func_tested   Function to be tested:
 *                      - @ref arg_types_recv_func_with_flags
 *
 * @par Test sequence:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/recv_oob_dgram"

#include "sockapi-test.h"

#define TST_BUF_LEN  300

int
main(int argc, char *argv[])
{
    const char        *func_tested = NULL;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;

    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;
    struct sockaddr_storage     from;
    socklen_t                   fromlen = sizeof(from);

    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    int                     sent;
    int                     rcv;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func_tested);

    tx_buf = te_make_buf_by_len(TST_BUF_LEN);
    rx_buf = te_make_buf_by_len(TST_BUF_LEN);

    /* Scenario */

    /* Get connection for test purposes */

    TEST_STEP("Create a pair of UDP sockets on IUT and Tester, "
              "binding the IUT socket to wildcard address.");
    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

#define RECV_BY_FUNC                                                          \
do {                                                                          \
    if (strcmp(func_tested, "recv") == 0)                                     \
    {                                                                         \
        rcv = rpc_recv(pco_iut, iut_s, rx_buf, TST_BUF_LEN, RPC_MSG_OOB);     \
    }                                                                         \
    else if (strcmp(func_tested, "recvfrom") == 0)                            \
    {                                                                         \
        rcv = rpc_recvfrom(pco_iut, iut_s, rx_buf, TST_BUF_LEN, RPC_MSG_OOB,  \
                           SA(&from), &fromlen);                              \
    }                                                                         \
    else if (strcmp(func_tested, "recvmsg") == 0 ||                           \
             strcmp(func_tested, "onload_zc_recv") == 0 ||                    \
             strcmp(func_tested, "onload_zc_hlrx_recv_zc") == 0 ||            \
             strcmp(func_tested, "onload_zc_hlrx_recv_copy") == 0)            \
    {                                                                         \
        struct rpc_msghdr msg;                                                \
        struct rpc_iovec  rx_buf_vec;                                         \
                                                                              \
        rx_buf_vec.iov_base = rx_buf;                                         \
        rx_buf_vec.iov_rlen = rx_buf_vec.iov_len = TST_BUF_LEN;               \
                                                                              \
        memset(&msg, 0, sizeof(msg));                                         \
        msg.msg_name = SA(&from);                                             \
        msg.msg_rnamelen = msg.msg_namelen = fromlen;                         \
        msg.msg_iov = &rx_buf_vec;                                            \
        msg.msg_riovlen = msg.msg_iovlen = 1;                                 \
                                                                              \
        if (strcmp(func_tested, "recvmsg") == 0)                              \
        {                                                                     \
            rcv = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_OOB);             \
        }                                                                     \
        else if (strcmp(func_tested, "onload_zc_recv") == 0)                  \
        {                                                                     \
            rcv = rpc_simple_zc_recv(pco_iut, iut_s, &msg, RPC_MSG_OOB);      \
        }                                                                     \
        else if (strcmp(func_tested, "onload_zc_hlrx_recv_zc") == 0)          \
        {                                                                     \
            rcv = rpc_simple_hlrx_recv_zc(pco_iut, iut_s, &msg,               \
                                          RPC_MSG_OOB, TRUE);                 \
        }                                                                     \
        else                                                                  \
        {                                                                     \
            rcv = rpc_simple_hlrx_recv_copy(pco_iut, iut_s, &msg,             \
                                            RPC_MSG_OOB, TRUE);               \
        }                                                                     \
    }                                                                         \
    else if (strcmp(func_tested, "recvmmsg") == 0)                            \
    {                                                                         \
        struct rpc_mmsghdr mmsg;                                              \
        struct rpc_msghdr *msg = &mmsg.msg_hdr;                               \
        struct rpc_iovec   rx_buf_vec;                                        \
                                                                              \
        rx_buf_vec.iov_base = rx_buf;                                         \
        rx_buf_vec.iov_rlen = rx_buf_vec.iov_len = TST_BUF_LEN;               \
                                                                              \
        memset(msg, 0, sizeof(*msg));                                         \
        msg->msg_name = SA(&from);                                            \
        msg->msg_rnamelen = msg->msg_namelen = fromlen;                       \
        msg->msg_iov = &rx_buf_vec;                                           \
        msg->msg_riovlen = msg->msg_iovlen = 1;                               \
                                                                              \
        rcv = rpc_recvmmsg_alt(pco_iut, iut_s, &mmsg, 1, RPC_MSG_OOB, NULL);  \
    }                                                                         \
    else                                                                      \
    {                                                                         \
        TEST_FAIL("Unknown function to be tested");                           \
    }                                                                         \
} while(0)

    TEST_STEP("Call @p tested_func with @c RCF_RPC_CALL on IUT, passing "
              "@c MSG_OOB flag to it.");
    pco_iut->op = RCF_RPC_CALL;
    RECV_BY_FUNC;

    TEST_STEP("Send some data from Tester to unblock @p tested_func "
              "if it was blocked.");
    RPC_SEND(sent, pco_tst, tst_s, tx_buf, TST_BUF_LEN, 0);

    TEST_STEP("Finish @p tested_func call, check that it failed "
              "with EINVAL.");
    pco_iut->op = RCF_RPC_WAIT;
    RPC_AWAIT_ERROR(pco_iut);
    RECV_BY_FUNC;

    if (rcv < 0)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "%s() with MSG_OOB "
                        "flag fails, but", func_tested);
    }
    else
    {
        RING_VERDICT("%s() with MSG_OOB flag ignores it and returns "
                     "usual data", func_tested);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(rx_buf);
    free(tx_buf);

    TEST_END;
}
