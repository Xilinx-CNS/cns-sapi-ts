/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-two_sockets I/O multiplexing functions with splice and two sockets
 *
 * @objective Check I/O multiplexing functions behaviour with two
 *            connections, pipe and two @b splice() operations.
 *
 * @param pco_iut      PCO on IUT
 * @param pco_tst1     Auxiliary PCO
 * @param pco_tst2     Auxiliary PCO
 * @param iomux        Type of I/O Multiplexing function
 *                     (@b select(), @b pselect(), @b poll())
 * @param packet_num   Number of packets to be sent
 * @param set_move     Whether to set @c SPLICE_F_MOVE flag
 * @param set_nonblock Whether to set @c SPLICE_F_NONBLOCK flag
 * @param diff_stacks  Whether to use different stacks for sockets and pipe
 *
 * @par Scenario:
 * 
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/iomux_splice_two_sockets"
#include "sockapi-test.h"
#include "iomux.h"

#define CHECK_DATA(_buf, _buf_len, _got_buf, _got_buf_len) \
do {                                             \
    if (_got_buf_len != _buf_len)                \
        TEST_FAIL("Only part of data received"); \
    if (memcmp(_buf, _got_buf, _buf_len))        \
            TEST_FAIL("Invalid data received");  \
} while(0);

#define DATA_BULK       1024  /**< Size of data to be sent */

/** Duration of the rpc_iomux_splice() call, in seconds. */
#define IOMUX_SPLICE_TIME2RUN   30

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr1 = NULL;
    const struct sockaddr  *tst_addr1 = NULL;

    const struct sockaddr  *iut_addr2 = NULL;
    const struct sockaddr  *tst_addr2 = NULL;

    int                     iut_s1 = -1;
    int                     tst_s1 = -1;
    int                     iut_s2 = -1;
    int                     tst_s2 = -1;

    void           *tx_buf = NULL;
    void           *rx_buf = NULL;

    int                     fds[2];

    int                     flags = 0;
    int                     packet_num;
    te_bool                 diff_stacks = FALSE;
    te_bool                 set_move = FALSE;
    te_bool                 set_nonblock = FALSE;

    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst1, tst_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst2, tst_addr2);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(packet_num);
    TEST_GET_BOOL_PARAM(diff_stacks);
    TEST_GET_BOOL_PARAM(set_move);
    TEST_GET_BOOL_PARAM(set_nonblock);

    tx_buf = te_make_buf_by_len(DATA_BULK);
    rx_buf = te_make_buf_by_len(DATA_BULK);

    flags = set_move ? RPC_SPLICE_F_MOVE : 0;
    if (set_nonblock)
        flags |= RPC_SPLICE_F_NONBLOCK;

    TEST_STEP("Generate connection between @p pco_iut and @p pco_tst1: @p iut_s1 "
              "and @p tst_s1 sockets");
    GEN_CONNECTION(pco_iut, pco_tst1, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr1, tst_addr1, &iut_s1, &tst_s1);

    if (diff_stacks)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, "test1");

    TEST_STEP("Generate connection between @p pco_iut and @p pco_tst1: @p iut_s1 "
              "and @p tst_s1 sockets");
    GEN_CONNECTION(pco_iut, pco_tst2, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr2, tst_addr2, &iut_s2, &tst_s2);

    if (diff_stacks)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, "test2");
    TEST_STEP("Create pipe");
    rpc_pipe(pco_iut, fds);

    TEST_STEP("Call @b iomux_splice() routine on @p pco_iut with iut_s1 socket "
              "with write end of the pipe() and on @p pco_iut with iut_s2 socket "
              "with read end of the pipe()");
    pco_iut->op = RCF_RPC_CALL;
    rpc_iomux_splice(pco_iut, iomux, iut_s1, fds[1], DATA_BULK, flags,
                     IOMUX_SPLICE_TIME2RUN);
    pco_iut1->op = RCF_RPC_CALL;
    rpc_iomux_splice(pco_iut1, iomux, fds[0], iut_s2, DATA_BULK, flags,
                     IOMUX_SPLICE_TIME2RUN);

    TAPI_WAIT_NETWORK;

    TEST_STEP("Send @p packet_num packets from @p pco_tst1 and get it on "
              "@p pco_tst2. Verify data.");
    for (i = 0; i < packet_num; i++)
    {
        te_fill_buf(tx_buf, DATA_BULK);
        RPC_SEND(rc, pco_tst1, tst_s1, tx_buf, DATA_BULK, 0);
        rc = rpc_recv(pco_tst2, tst_s2, rx_buf, DATA_BULK, 0);
        CHECK_DATA(tx_buf, rc, rx_buf, DATA_BULK);
    }

    pco_iut->op = RCF_RPC_WAIT;
    rpc_iomux_splice(pco_iut, iomux, iut_s1, fds[1], DATA_BULK, flags,
                     IOMUX_SPLICE_TIME2RUN);

    pco_iut1->op = RCF_RPC_WAIT;
    rpc_iomux_splice(pco_iut1, iomux, fds[0], iut_s2, DATA_BULK, flags,
                     IOMUX_SPLICE_TIME2RUN);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s2);
    CLEANUP_RPC_CLOSE(pco_iut, fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fds[1]);
    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
