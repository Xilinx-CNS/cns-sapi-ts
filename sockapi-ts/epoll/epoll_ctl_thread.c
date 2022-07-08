/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 */

/**
 * @page epoll-epoll_ctl_thread Contentious epoll_ctl() calls from threads.
 *
 * @objective Check that a lot of epoll_ctl() operations from different threads
 *            do not crash system.
 *
 * @param env              Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param check_epoll_wait Check events after epoll_ctl() call
 * @param num_threads      Number of threads to call epoll_ctl():
 *      - @c 1
 *      - @c 5
 * @param conns_per_thread Number of connections per each thread:
 *      - @c 1
 *      - @c 32
 * @param iter_num         Number of test iterations:
 *      - @c 1
 *      - @c 2
 *      - @c 5
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "epoll/epoll_ctl_thread"

#include "sockapi-test.h"

/* How long to run every thread with epoll_ctl()/epoll_wait(), in ms */
#define TIME2RUN 1000

typedef struct thread_data
{
    rcf_rpc_server *iut_pco_th;       /**< IUT aux thread */
    rpc_ptr         iut_socks_handle; /**< IUT socket array handle */

    rcf_rpc_server *tst_pco_th;       /**< TST aux thread */
    rpc_ptr         tst_socks_handle; /**< TST socket array handle */
} thread_data;

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int i = 0;
    int iter = 0;
    int epfd = -1;
    thread_data *threads = NULL;
    int num_threads = 0;
    int conns_per_thread = 0;
    int iter_num = 0;
    int iut_l = -1;
    te_bool check_epoll_wait = FALSE;

    pid_t iut_pid;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(num_threads);
    TEST_GET_INT_PARAM(conns_per_thread);
    TEST_GET_INT_PARAM(iter_num);
    TEST_GET_BOOL_PARAM(check_epoll_wait);

    /* This was added to debug ON-13048. */
    iut_pid = rpc_getpid(pco_iut);
    rcf_rpc_server_fork(pco_iut, "iut_killer", &pco_killer);

    threads = tapi_calloc(num_threads, sizeof(*threads));

    TEST_STEP("Create epoll descriptor.");
    epfd = rpc_epoll_create(pco_iut, 1);

    TEST_STEP("Create @p num_threads * @p conns_per_thread connections "
              "between IUT and Tester.");
    iut_l = rpc_stream_server(pco_iut, RPC_PROTO_DEF, FALSE, iut_addr);
    if (iut_l == -1)
        TEST_FAIL("Failed to create IUT listener socket");

    for (i = 0; i < num_threads; i++)
    {
        char name[RCF_MAX_NAME] = {0};

        TE_SPRINTF(name, "pco_aux_iut%u", i);
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, name,
                                              &threads[i].iut_pco_th));
        TE_SPRINTF(name, "pco_aux_tst%u", i);
        CHECK_RC(rcf_rpc_server_thread_create(pco_tst, name,
                                              &threads[i].tst_pco_th));

        threads[i].iut_pco_th->op = RCF_RPC_CALL;
        rpc_many_accept(threads[i].iut_pco_th, iut_l, conns_per_thread, 0, 0,
                        NULL, NULL, &threads[i].iut_socks_handle);

        rpc_many_connect(threads[i].tst_pco_th, iut_addr, conns_per_thread,
                         0, 0, NULL, NULL, &threads[i].tst_socks_handle);

        rpc_many_accept(threads[i].iut_pco_th, iut_l,
                        conns_per_thread, 0, 0, NULL, NULL,
                        &threads[i].iut_socks_handle);
    }
    RPC_CLOSE(pco_iut, iut_l);

    TEST_STEP("For each connection send some data from Tester.");
    for (i = 0; i < num_threads; i++)
    {
        int data = 0xdeadbeef;
        int j = 0;
        int s = -1;

        for (j = 0; j < conns_per_thread; j++)
        {
            rpc_get_socket_from_array(threads[i].tst_pco_th,
                                      threads[i].tst_socks_handle,
                                      j, &s);
            rpc_send(threads[i].tst_pco_th, s, &data, sizeof(data), 0);
        }
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Run @p iter_num times:");
    for (iter = 0; iter < iter_num; iter++)
    {
        TEST_SUBSTEP("Start @p num_threads threads which add and delete "
                     "sockets to the epoll instance with "
                     "@b rpc_many_epoll_ctl_add_del() function.");

        for (i = 0; i < num_threads; i++)
        {
            threads[i].iut_pco_th->op = RCF_RPC_CALL;
            rpc_many_epoll_ctl_add_del(threads[i].iut_pco_th,
                                       threads[i].iut_socks_handle,
                                       conns_per_thread, epfd, RPC_EPOLLIN,
                                       check_epoll_wait, TIME2RUN);
        }

        TEST_SUBSTEP("Wait for threads finish and check the return value.");
        for (i = 0; i < num_threads; i++)
        {
            threads[i].iut_pco_th->op = RCF_RPC_WAIT;
            RPC_AWAIT_ERROR(threads[i].iut_pco_th);
            rc = rpc_many_epoll_ctl_add_del(threads[i].iut_pco_th,
                                            threads[i].iut_socks_handle,
                                            conns_per_thread, epfd,
                                            RPC_EPOLLIN, check_epoll_wait,
                                            TIME2RUN);

            if (rc < 0)
            {
                if (TE_RC_GET_ERROR(
                        RPC_ERRNO(threads[i].iut_pco_th)) == TE_ERPCTIMEOUT)
                {
                    /*
                     * Produce core dump when one of the threads times out,
                     * it makes easier to debug Onload issue ON-13048.
                     */
                    rpc_kill(pco_killer, iut_pid, RPC_SIGQUIT);
                }

                TEST_VERDICT("many_epoll_ctl_add_del() failed with error "
                             RPC_ERROR_FMT,
                             RPC_ERROR_ARGS(threads[i].iut_pco_th));
            }
        }
    }

    TEST_STEP("Read all the data on IUT.");
    for (i = 0; i < num_threads; i++)
    {
        int data = 0;
        int j = 0;
        int s = -1;

        for (j = 0; j < conns_per_thread; j++)
        {
            rpc_get_socket_from_array(threads[i].iut_pco_th,
                                      threads[i].iut_socks_handle,
                                      j, &s);
            rpc_recv(threads[i].iut_pco_th, s, &data, sizeof(data), 0);
        }
    }

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < num_threads; i++)
    {
        rpc_many_close(threads[i].iut_pco_th, threads[i].iut_socks_handle,
                       conns_per_thread);
        rpc_many_close(threads[i].tst_pco_th, threads[i].tst_socks_handle,
                       conns_per_thread);

        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(threads[i].iut_pco_th));
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(threads[i].tst_pco_th));
    }
    free(threads);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut, epfd);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_killer));
    TEST_END;
}
