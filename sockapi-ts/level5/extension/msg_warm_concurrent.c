/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/**
 * @page level5-extension-msg_warm_concurrent Concurrent sending from two sockets and ONLOAD_MSG_WARM
 *
 * @objective Check that using @c ONLOAD_MSG_WARM flag is harmless when
 *            data is sent from two sockets concurrently.
 *
 * @param sock_type     Socket type:
 *                      - tcp active
 *                      - tcp passive
 * @param func          Testing send function:
 *                      - send
 *                      - sendto
 *                      - sendmsg
 *                      - onload_zc_send
 * @param nonblock      If @c TRUE, use the single thread and
 *                      nonblocking send; otherwise use
 *                      separate thread for each socket and
 *                      blocking send.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/msg_warm_concurrent"

#include "sockapi-test.h"

/** How long to send data, in seconds. */
#define SEND_FLOW_TIME2RUN 5

/** How long to wait until all data is received. */
#define RECEIVE_TIMEOUT SEND_FLOW_TIME2RUN + 2

/** Minimum size of buffer passed to send function at once. */
#define BUF_SIZE_MIN 1

/** Maximum size of buffer passed to send function at once. */
#define BUF_SIZE_MAX 1000

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    rcf_rpc_server     *pco_iut_thread = NULL;
    rcf_rpc_server     *pco_tst_thread = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    struct sockaddr_storage iut_addr2;
    struct sockaddr_storage tst_addr2;

    int   iut_s1 = -1;
    int   iut_s2 = -1;
    int   tst_s1 = -1;
    int   tst_s2 = -1;

    uint64_t sent1 = 0;
    uint64_t sent2 = 0;

    te_bool test_failed = FALSE;

    sockts_socket_type    sock_type;
    rpc_send_f            func;
    te_bool               nonblock;

    tapi_pat_receiver     recv_ctx1;
    tapi_pat_receiver     recv_ctx2;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_SEND_FUNC(func);
    TEST_GET_BOOL_PARAM(nonblock);

    if (!nonblock)
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_iut_thread",
                                              &pco_iut_thread));

    CHECK_RC(rcf_rpc_server_thread_create(pco_tst, "pco_tst_thread",
                                          &pco_tst_thread));

    TEST_STEP("Establish two TCP connections.");

    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s1, &tst_s1, NULL);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr2));
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &tst_addr2));

    SOCKTS_CONNECTION(pco_iut, pco_tst, SA(&iut_addr2), SA(&tst_addr2),
                      sock_type, &iut_s2, &tst_s2, NULL);

    TEST_STEP("If @p nonblock is @c TRUE, start sending data from one thread, "
              "using two sockets in turns, using nonblocking send. Otherwise "
              "use two threads, each sending data from one of sockets. For every "
              "send function call choose randomly whether to pass "
              "@c ONLOAD_MSG_WARM flag.");

    if (nonblock)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_send_msg_warm_flow(pco_iut, rpc_send_func_name(func),
                               iut_s1, iut_s2, BUF_SIZE_MIN, BUF_SIZE_MAX,
                               SEND_FLOW_TIME2RUN, &sent1, &sent2);
    }
    else
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_send_msg_warm_flow(pco_iut, rpc_send_func_name(func),
                               iut_s1, -1, BUF_SIZE_MIN, BUF_SIZE_MAX,
                               SEND_FLOW_TIME2RUN, &sent1, NULL);

        pco_iut_thread->op = RCF_RPC_CALL;
        rpc_send_msg_warm_flow(pco_iut_thread,
                               rpc_send_func_name(func),
                               iut_s2, -1, BUF_SIZE_MIN, BUF_SIZE_MAX,
                               SEND_FLOW_TIME2RUN, &sent2, NULL);
    }

    tapi_pat_receiver_init(&recv_ctx1);
    recv_ctx1.gen_func = RPC_PATTERN_GEN;
    recv_ctx1.iomux = FUNC_DEFAULT_IOMUX;
    recv_ctx1.duration_sec = RECEIVE_TIMEOUT;

    tapi_pat_receiver_init(&recv_ctx2);
    recv_ctx2.gen_func = RPC_PATTERN_GEN;
    recv_ctx2.iomux = FUNC_DEFAULT_IOMUX;
    recv_ctx2.duration_sec = RECEIVE_TIMEOUT;

    TEST_STEP("Start receiving data on Tester in two threads with "
              "@b rpc_pattern_receiver().");

    pco_tst->op = RCF_RPC_CALL;
    rpc_pattern_receiver(pco_tst, tst_s1, &recv_ctx1);

    pco_tst_thread->op = RCF_RPC_CALL;
    rpc_pattern_receiver(pco_tst_thread, tst_s2, &recv_ctx2);

    TEST_STEP("Wait until data sending is finished, check that nothing failed.");

    if (nonblock)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_send_msg_warm_flow(pco_iut, rpc_send_func_name(func),
                                    iut_s1, iut_s2, BUF_SIZE_MIN,
                                    BUF_SIZE_MAX, SEND_FLOW_TIME2RUN,
                                    &sent1, &sent2);
        if (rc < 0)
        {
            ERROR_VERDICT("rpc_send_msg_warm_flow() failed, errno %r",
                          RPC_ERRNO(pco_iut));
            test_failed = TRUE;
        }
    }
    else
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_send_msg_warm_flow(pco_iut, rpc_send_func_name(func),
                                    iut_s1, -1, BUF_SIZE_MIN, BUF_SIZE_MAX,
                                    SEND_FLOW_TIME2RUN, &sent1, NULL);
        if (rc < 0)
        {
            ERROR_VERDICT("First sending thread failed, errno "
                          RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
            test_failed = TRUE;
        }

        RPC_AWAIT_ERROR(pco_iut_thread);
        rc = rpc_send_msg_warm_flow(pco_iut_thread,
                                    rpc_send_func_name(func),
                                    iut_s2, -1, BUF_SIZE_MIN, BUF_SIZE_MAX,
                                    SEND_FLOW_TIME2RUN, &sent2, NULL);
        if (rc < 0)
        {
            ERROR_VERDICT("Second sending thread failed, errno "
                          RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut_thread));
            test_failed = TRUE;
        }
    }

    TEST_STEP("Wait until data reception is finished, check that only data "
              "sent without @c ONLOAD_MSG_WARM was received successfully "
              "from each socket.");

    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_pattern_receiver(pco_tst, tst_s1, &recv_ctx1);
    if (rc < 0)
    {
        if (rc == -2 || recv_ctx1.received != sent1)
            ERROR_VERDICT("Unexpected data was received from the first "
                          "socket on Tester");
        else
            ERROR_VERDICT("rpc_pattern_received() failed for the first "
                          "socket, errno %r", RPC_ERRNO(pco_tst));

        test_failed = TRUE;
    }

    RPC_AWAIT_ERROR(pco_tst_thread);
    rpc_pattern_receiver(pco_tst_thread, tst_s2, &recv_ctx2);
    if (rc < 0)
    {
        if (rc == -2 || recv_ctx2.received != sent2)
            ERROR_VERDICT("Unexpected data was received from the second "
                          "socket on Tester");
        else
            ERROR_VERDICT("rpc_pattern_received() failed for the second "
                          "socket, errno %r", RPC_ERRNO(pco_tst_thread));

        test_failed = TRUE;
    }

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    if (pco_iut_thread != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));
    if (pco_tst_thread != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_tst_thread));

    TEST_END;
}
