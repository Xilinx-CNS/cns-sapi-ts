/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page ext_stackname-tcp_conn_move_fd_in_pkt_flow Call @b onload_move_fd() on a socket just after TCP connection establishment with incoming packet flow
 *
 * @objective Check that after establishing passive TCP connection with
 *            incoming packet flow data is received after moving accepted
 *            socket to different stack.
 *
 * @type use case
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 * @param threads           Number of threads to send data from the @b Tester
 * @param time2send         Time (in seconds) to send data
 * @param iterations        Number of repetitions
 * @param close_accepted    If @c TRUE - close accepted sockets after each
 *                          iteration, else - close sockets at the end of test
 *
 * @par Scenario:
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/tcp_conn_move_fd_in_pkt_flow"

#include "sockapi-test.h"
#include "onload.h"
#include "extensions.h"
#include "move_fd_helpers.h"

#define STACK_NAME "acc_s"

#define RECV_BUF_SIZE 4096

struct recv_info {
    int                     sock;
    struct sockaddr_storage rem_addr;
    socklen_t               rem_addrlen;
    uint64_t                bytes;
    uint64_t                last_rc;
};

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut =    NULL;
    rcf_rpc_server *pco_thread = NULL;
    rcf_rpc_server *pco_tst =    NULL;

    const struct sockaddr   *iut_addr = NULL;
    const struct sockaddr   *tst_addr = NULL;
    struct sockaddr_storage *bind_addrs = NULL;
    int                      iut_s = -1;
    int                      iut_s_listen = -1;
    int                      iut_s_aux = -1;
    int                     *socks2close = NULL;

    int                      threads;
    int                      time2send;
    int                      iterations;
    te_bool                  close_accepted;

    int                      iter;
    int                      i;
    te_bool                  test_failed = FALSE;
    te_bool                  bool_rc;
    char                    *init_stack_name;
    te_bool                  restore_stack_name = FALSE;
    te_bool                  op_done;

    struct recv_info        *ri = NULL;
    char                    *recv_buf = NULL;
    uint64_t                *sent = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(threads);
    TEST_GET_INT_PARAM(time2send);
    TEST_GET_INT_PARAM(iterations);
    TEST_GET_BOOL_PARAM(close_accepted);

    /* Variable initialization */
    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    CHECK_NOT_NULL((ri = TE_ALLOC(sizeof(*ri) * threads)));
    bind_addrs = TE_ALLOC(sizeof(*bind_addrs) * threads);
    recv_buf = TE_ALLOC(RECV_BUF_SIZE);
    sent = TE_ALLOC(sizeof(*sent) * threads);
    if (!close_accepted)
    {
        socks2close = TE_ALLOC(sizeof(*socks2close) * iterations * threads);
        for (i = 0; i < iterations * threads; i++)
            socks2close[i] = -1;
    }

    TEST_STEP("Create listening socket on IUT on default stack.");
    iut_s_listen = rpc_stream_server(pco_iut, RPC_PROTO_DEF, FALSE, iut_addr);
    if (iut_s_listen < 0)
    {
        TEST_FAIL("Failed to create listening socket on IUT: %r",
                   RPC_ERRNO(pco_iut));
    }

    TEST_STEP("Set stack name to @c STACK_NAME.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_GLOBAL, STACK_NAME,
                                         TRUE, &iut_s_aux);
    restore_stack_name = TRUE;

    for (iter = 0; iter < iterations; iter++)
    {
        RING("Starting iteraion: %d", iter + 1);
        TEST_STEP("For each @c iteration do the following:");
        TEST_SUBSTEP("Start on Tester @c threads number where each thread "
                      "will connect to IUT listening socket and immediately "
                      "send data for @c time2send seconds;");

        if (pco_thread != NULL)
        {
            CHECK_RC(rcf_rpc_server_destroy(pco_thread));
            pco_thread = NULL;
        }
        CHECK_RC(rcf_rpc_server_thread_create(pco_tst, "tst_thread",
                 &pco_thread));

        memset(ri, 0, sizeof(*ri) * threads);
        for (i = 0; i < threads; i++)
            ri[i].sock = -1;
        memset(bind_addrs, 0, sizeof(*bind_addrs) * threads);
        memset(sent, 0, sizeof(*sent) * threads);

        for (i = 0; i < threads; i++)
        {
            tapi_sockaddr_clone_exact(tst_addr, bind_addrs + i);
            CHECK_RC(tapi_allocate_set_port(pco_tst, SA(bind_addrs + i)));
        }
        pco_thread->op = RCF_RPC_CALL;
        op_done = FALSE;
        rpc_connect_send_dur_time(pco_thread, threads, iut_addr,
                                  bind_addrs, time2send, sent);

        while (true)
        {
            for (i = 0; i < threads; i++)
            {
                te_bool readable;
                if (ri[i].sock == -1)
                {
                    /* Accept incoming connection */
                    RPC_GET_READABILITY(readable, pco_iut, iut_s_listen, 0);
                    if (!readable)
                        continue;

                    TEST_SUBSTEP("Accept incoming connection on IUT;");

                    ri[i].rem_addrlen = sizeof(ri[i].rem_addr);
                    if ((rc = rpc_accept(pco_iut, iut_s_listen,
                                         SA(&(ri[i].rem_addr)),
                                         &(ri[i].rem_addrlen))) < 0)
                    {
                        continue;
                    }
                    ri[i].sock = rc;
                    ri[i].rem_addrlen = sizeof(ri[i].rem_addr);
                    CHECK_RC(rpc_getpeername(pco_iut, ri[i].sock,
                                SA(&(ri[i].rem_addr)), &(ri[i].rem_addrlen)));

                    TEST_SUBSTEP("Move accepted IUT socket to @c STACK_NAME "
                                 "and receive all data from Tester;");
                    bool_rc = tapi_rpc_onload_move_fd_check(pco_iut, ri[i].sock,
                                TAPI_MOVE_FD_SUCCESS_EXPECTED, STACK_NAME, NULL);
                    if (!bool_rc)
                    {
                        TEST_FAIL("Failed to move accepted IUT socket to "
                                  "@c STACK_NAME");
                    }
                }
                else
                {
                    /* Read data */
                    pco_iut->silent = TRUE;
                    RPC_GET_READABILITY(readable, pco_iut, ri[i].sock, 0);

                    pco_iut->silent = TRUE;
                    if ((rc = rpc_recv(pco_iut, ri[i].sock, recv_buf,
                                       RECV_BUF_SIZE, 0)) < 0)
                    {
                        TEST_FAIL("rec_recv() failed unexpectedly");
                    }
                    else
                    {
                        ri[i].bytes += rc;
                        ri[i].last_rc = rc;
                    }
                }
            }

            if (!op_done)
                CHECK_RC(rcf_rpc_server_is_op_done(pco_thread, &op_done));

            if (op_done)
            {
                te_bool all_socks_accepted = TRUE;
                te_bool all_last_rc_is_zero = TRUE;

                for (i = 0; i < threads; i++)
                {
                    if (ri[i].sock == -1)
                        all_socks_accepted = FALSE;

                    if (ri[i].last_rc != 0)
                        all_last_rc_is_zero = FALSE;
                }
                if (all_socks_accepted && all_last_rc_is_zero)
                    break;
            }
        };

        pco_thread->op = RCF_RPC_WAIT;
        rpc_connect_send_dur_time(pco_thread, threads, iut_addr,
                                  bind_addrs, time2send, sent);

        if (close_accepted)
        {
            TEST_SUBSTEP("Close accepted sockets if @c close_accepted is @c TRUE;");
            for (i = 0; i < threads; i++)
            {
                if (ri[i].sock == -1)
                    RPC_CLOSE(pco_iut, ri[i].sock);
            }
        }
        else if (!close_accepted)
        {
            for (i = 0; i < threads; i++)
                socks2close[iterations * threads + threads] = ri[i].sock;
        }

        TEST_SUBSTEP("Check that sent and received data match.");
        for (i = 0; i < threads; i++)
        {
            int j;
            for (j = 0 ; j < threads; j++)
            {
                if (te_sockaddrcmp(SA(&bind_addrs[i]), sizeof(*bind_addrs),
                                   SA(&ri[j].rem_addr), ri[j].rem_addrlen) == 0)
                {
                    RING("Thread #%d: bytes sent %lu, received %lu",
                          i, sent[i], ri[j].bytes);
                    if (sent[i] != ri[j].bytes)
                    {
                        ERROR("Sent and received data are not match: %lu != %lu",
                              sent[i], ri[j].bytes);
                        test_failed = TRUE;
                    }
                }
            }
        }
    }

    if (!close_accepted)
    {
        TEST_STEP("Close all accepted sockets if @c close_accepted is @c FALSE "
                  "at the end of test after all @c iterations have finished.");
        /* This step will be done in the cleanup section */
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_thread));
    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);
    if (iut_s_aux != -1)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    if (iut_s_listen != -1)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s_listen);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (socks2close != NULL)
    {
        for (i = 0; i < iterations * threads; i++)
        {
            if (socks2close[i] != -1)
                CLEANUP_RPC_CLOSE(pco_iut, socks2close[i]);
        }
    }

    free(recv_buf);
    free(bind_addrs);

    TEST_END;
}
