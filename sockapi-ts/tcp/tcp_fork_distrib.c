/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 *
 * $Id$
 */

/** @page tcp-tcp_fork_distrib  Connection requests distribution between two processes
 *
 * @objective  Check that the child and parent accept more-or-less the same
 *             number of connection requests.
 *
 * @type conformance
 *
 * @param pco_iut  PCO on IUT
 * @param pco_tst  PCO on TESTER
 * @param num      Connection requests number
 * @param thread   Aux thread is created for the competition if @c TRUE,
 *                 else - process.
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_fork_distrib"

#include "sockapi-test.h"

/* Determines allowed difference in accepted connections. */
#define DEVIATION 0.4

/* Check and print rpc_many_accept() call status. */
#define CHECK_MANY_ACCEPT_STATUS(_rpcs) \
    do {                                                                \
        te_bool is_done;                                                \
        CHECK_RC(rcf_rpc_server_is_op_done(_rpcs, &is_done));           \
        if (is_done)                                                    \
        {                                                               \
            RPC_AWAIT_ERROR(_rpcs);                                     \
            _rpcs->op = RCF_RPC_WAIT;                                   \
            rc = rpc_many_accept_gen(_rpcs, iut_s, num + 1, 128, 1,     \
                                     NULL, NULL, &sock_iut_h, NULL);    \
            ERROR("rpc_many_accept() on %s finished with errno %s",     \
                  _rpcs->name, errno_rpc2str(RPC_ERRNO(_rpcs)));        \
        }                                                               \
        else                                                            \
        {                                                               \
            RING("rpc_many_accept() on %s has not been done yet.",      \
                 _rpcs->name);                                          \
        }                                                               \
    } while(0)


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_child = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    int                    num;
    te_bool                thread;
    int                    saved_klog_level = -1;
    int                    loop_mode = 0;

    int iut_s = -1;
    int tst_s = -1;
    int cnt1 = 0;
    int cnt2 = 0;
    int i;

    size_t rlim;

    rpc_ptr sock_tst_h = RPC_NULL;
    rpc_ptr sock_iut_h = RPC_NULL;
    rpc_ptr sock_iut_child_h = RPC_NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(num);
    TEST_GET_BOOL_PARAM(thread);

    TEST_STEP("Create lsitener socket on IUT.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, -1);

    TEST_STEP("Increase RLIMIT to be possible create a lot of sockets.");
    rlim = num * 3;
    sockts_inc_rlimit(pco_tst, RPC_RLIMIT_NOFILE, rlim);

    TEST_STEP("Fork IUT process.");
    if (thread)
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_iut_child",
                                              &pco_iut_child));
    else
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_child",
                                     &pco_iut_child));

    sockts_inc_rlimit(pco_iut, RPC_RLIMIT_NOFILE, rlim);
    sockts_inc_rlimit(pco_iut_child, RPC_RLIMIT_NOFILE, rlim);

    /* Onload in loop4 mode writes too many messages */
    if (tapi_sh_env_get_int(pco_iut, "EF_TCP_CLIENT_LOOPBACK",
                            &loop_mode) == 0 && loop_mode == 4)
        TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &saved_klog_level);

    TEST_STEP("Accept connections in loop on both IUT processes.");
    pco_iut->op = RCF_RPC_CALL;
    /* We need num + 1 here to get ECONNRESET even in case when only one
     * thread accepts all connections.
     */
    rpc_many_accept(pco_iut, iut_s, num + 1, 128, 1, NULL, NULL, &sock_iut_h);
    pco_iut_child->op = RCF_RPC_CALL;
    rpc_many_accept(pco_iut_child, iut_s, num + 1, 128, 1, NULL, NULL,
                    &sock_iut_child_h);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Send @p num connection requests from tester.");
    pco_tst->timeout = 60000;
    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_many_connect(pco_tst, iut_addr, num, 128, 1, NULL, NULL,
                          &sock_tst_h);
    if (rc < 0)
    {
        CHECK_MANY_ACCEPT_STATUS(pco_iut);
        CHECK_MANY_ACCEPT_STATUS(pco_iut_child);
        TEST_VERDICT("many_connect() on tester failed with errno %r",
                     RPC_ERRNO(pco_tst));
    }

    TEST_STEP("Connect from tester and close the socket without datagram "
              "transmission to break IUT accepting loops. Call @b rpc_many_accept "
              "should fail with @c ECONNRESET in this case.");
    for (i = 0; i < 2; i++)
    {
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s, iut_addr);
        /* Wait for incoming data to guarantee that RST is sent */
        TAPI_WAIT_NETWORK;
        RPC_CLOSE(pco_tst, tst_s);
    }

    TEST_STEP("Finish connections accepting and count statistics.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    RPC_AWAIT_IUT_ERROR(pco_iut_child);
    if (rpc_many_accept_gen(pco_iut, iut_s, num + 1, 128, 1, NULL, NULL,
                            &sock_iut_h, &cnt1) != -1 ||
        RPC_ERRNO(pco_iut) != RPC_ECONNRESET ||
        rpc_many_accept_gen(pco_iut_child, iut_s, num + 1, 128, 1, NULL, NULL,
                            &sock_iut_child_h, &cnt2) != -1 ||
        RPC_ERRNO(pco_iut_child) != RPC_ECONNRESET)
        TEST_VERDICT("rpc_many_accept_gen must fail with ECONNRESET");

    RING("Accepted connections number %d:%d, div %f", cnt1, cnt2,
         cnt1 / (num * 1.0));

    if (cnt1 + cnt2 != num)
        TEST_VERDICT("Accepted connections number differs from the "
                     "requested one");

    TEST_STEP("Both IUT processes must accept connections.");
    if ((cnt1 / (num * 1.0) < 0.5 - DEVIATION) ||
        (cnt1 / (num * 1.0) > 0.5 + DEVIATION))
        TEST_VERDICT("Too much difference in accepted connections between "
                     "processes");


    TEST_SUCCESS;

cleanup:
    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, saved_klog_level);

    rpc_many_close(pco_tst, sock_tst_h, num);
    rpc_many_close(pco_iut_child, sock_iut_child_h, num + 1);
    if (pco_iut_child != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_child));
    rpc_many_close(pco_iut, sock_iut_h, num + 1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    /* Loopback iterations create many stacks in case of Onload's loop4 mode.
     * Kill them to avoid run out of memory.
     */
    sockts_kill_zombie_stacks(pco_iut);

    TEST_END;
}
