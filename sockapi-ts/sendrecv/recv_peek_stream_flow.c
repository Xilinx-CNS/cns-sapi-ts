/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_peek_stream_flow Receiving a flow of data using MSG_PEEK
 *
 * @objective Check that @c MSG_PEEK works correctly when it is used
 *            often while receiving a lot of data from peer.
 *
 * @type conformance
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_lo
 *                  - @ref arg_types_env_peer2peer_ipv6
 *                  - @ref arg_types_env_peer2peer_lo_ipv6
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_peek_stream_flow"

#include "sockapi-test.h"

/* Number of seconds to run rpc_pattern_sender() */
#define TIME2RUN 2

/* How many times to try sending and receiving */
#define ITERS_NUM 10

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct if_nameindex *tst_if = NULL;

    int iut_s = -1;
    int tst_s = -1;

    int i;
    uint64_t received;

    tapi_pat_sender sender_ctx;
    tarpc_pat_gen_arg *lcg_arg = NULL;
    tarpc_pat_gen_arg recv_gen_arg;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_STEP("Disable TSO and GSO on Tester interface.");
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                              pco_tst->ta, tst_if->if_name,
                                              "tx-tcp-segmentation", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                              pco_tst->ta, tst_if->if_name,
                                              "tx-generic-segmentation", 0));

    CFG_WAIT_CHANGES;

    TEST_STEP("Create a pair of connected TCP sockets on IUT and Tester.");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Set @c TCP_NODELAY on Tester socket to make sure that data "
              "is sent as soon as possible.");
    rpc_setsockopt_int(pco_tst, tst_s, RPC_TCP_NODELAY, 1);

    tapi_pat_sender_init(&sender_ctx);
    sender_ctx.gen_func = RPC_PATTERN_GEN_LCG;
    sender_ctx.duration_sec = TIME2RUN;
    sender_ctx.size.min = 1;
    sender_ctx.size.max = SOCKTS_MSG_STREAM_MAX;
    sender_ctx.size.once = FALSE;

    lcg_arg = &sender_ctx.gen_arg;
    lcg_arg->offset = 0;
    lcg_arg->coef1 = rand_range(0, RAND_MAX);
    lcg_arg->coef2 = rand_range(0, RAND_MAX) | 1;
    lcg_arg->coef3 = rand_range(0, RAND_MAX);
    memcpy(&recv_gen_arg, lcg_arg, sizeof(recv_gen_arg));

    TEST_STEP("In a loop do the following many times:");
    TEST_SUBSTEP("Call @b rpc_sockts_peek_stream_receiver() on IUT with "
                 "@c RCF_RPC_CALL, wait for a while to make sure it is "
                 "started.");
    TEST_SUBSTEP("Call @b rpc_pattern_sender() on Tester, wait for its "
                 "termination.");
    TEST_SUBSTEP("Wait for termination of previously called "
                 "@b rpc_sockts_peek_stream_receiver() on IUT, check that "
                 "it returns success and that it received and checked "
                 "all the data sent by @b rpc_pattern_sender().");

    for (i = 0; i < ITERS_NUM; i++)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_sockts_peek_stream_receiver(
                        pco_iut, iut_s, TE_SEC2MS(TIME2RUN + 1),
                        TAPI_WAIT_NETWORK_DELAY, &recv_gen_arg, &received);

        MSLEEP(100);

        rpc_pattern_sender(pco_tst, tst_s, &sender_ctx);

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_sockts_peek_stream_receiver(
                        pco_iut, iut_s, TE_SEC2MS(TIME2RUN + 1),
                        TAPI_WAIT_NETWORK_DELAY, &recv_gen_arg, &received);

        if (rc < 0)
        {
            TEST_VERDICT("rpc_sockts_peek_stream_receiver() failed with "
                         "error " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
        }

        if (received != sender_ctx.sent)
            TEST_VERDICT("Received different number of bytes than sent");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
