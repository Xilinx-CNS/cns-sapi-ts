/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reuseport
 */

/** @page reuseport-tcp_close_listener Closing listener and accepted sockets in different order
 *
 * @objective Close listener sockets in different order in relation to
 *            accepted sockets. Check that after sockets closing it is
 *            possible to bind to the same/different port on the same
 *            address using SO_REUSEPORT.
 *
 * @type use case
 *
 * @param wildcard                  Listener socket binding address type.
 *                                  - @c FALSE: specific address
 *                                  - @c TRUE: INADDR_ANY
 * @param first_listener_early      Close the first created listener socket
 *                                  earlier than its accepted socket if
 *                                  @c TRUE.
 * @param second_listener_early     Close the second created listener
 *                                  socket earlier than its accepted socket
 *                                  if @c TRUE.
 * @param listeners_closing_order   Close the first created listener socket
 *                                  earlier than the second one if @c TRUE.
 * @param orphaned                  Keep IUT sockets orphaned if @c TRUE.
 * @param same_port                 Bind new listener sockets to the same
 *                                  port if @c TRUE.
 * @param ef_cluster_restart        Set the value to EF_CLUSTER_RESTART:
 *                                  - @c 0
 *                                  - @c 1
 * @param tp                        Create aux processes/threads or not.
 *                                  - @c none: create sockets in the same
 *                                             thread
 *                                  - @c thread: create sockets in different
 *                                               threads
 *                                  - @c process: create sockets in
 *                                                different processes
 *
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/tcp_close_listener"

#include "sockapi-test.h"
#include "reuseport.h"

/**
 * Close sockets associated with a given connection.
 *
 * @param ctx             Pointer to structure with sockets.
 * @param listener_first  Whether to close listener socket before
 *                        accepted socket on IUT.
 * @param orphaned        Whether IUT accepted socket should become
 *                        orphaned after calling close() on it.
 */
static void
close_sockets(reuseport_socket_ctx *ctx, te_bool listener_first,
              te_bool orphaned)
{
    if (listener_first)
        RPC_CLOSE(ctx->pco_iut, ctx->iut_s);

    if (!orphaned)
    {
        RPC_CLOSE(ctx->pco_tst, ctx->tst_s);
        TAPI_WAIT_NETWORK;
    }
    RPC_CLOSE(ctx->pco_iut, ctx->iut_acc);

    if (!listener_first)
        RPC_CLOSE(ctx->pco_iut, ctx->iut_s);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server          *pco_iut = NULL;
    rcf_rpc_server          *pco_tst = NULL;
    const struct sockaddr   *iut_addr = NULL;
    const struct sockaddr   *tst_addr = NULL;

    struct sockaddr_storage  iut_addr_bind1;
    struct sockaddr_storage  iut_addr_connect2;
    struct sockaddr_storage  iut_addr_bind2;
    rcf_rpc_server          *pco_iut2 = NULL;

    reuseport_socket_ctx s1 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s2 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s3 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s4 = REUSEPORT_SOCKET_CTX_INIT;

    te_bool wildcard;
    te_bool first_listener_early;
    te_bool second_listener_early;
    te_bool listeners_closing_order;
    te_bool orphaned;
    te_bool same_port;
    int     ef_cluster_restart;
    int     tp;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(wildcard);
    TEST_GET_BOOL_PARAM(first_listener_early);
    TEST_GET_BOOL_PARAM(second_listener_early);
    TEST_GET_BOOL_PARAM(listeners_closing_order);
    TEST_GET_BOOL_PARAM(orphaned);
    TEST_GET_BOOL_PARAM(same_port);
    TEST_GET_INT_PARAM(ef_cluster_restart);
    TEST_GET_ENUM_PARAM(tp, THREAD_PROCESS);

    TEST_STEP("If @p orphaned=TRUE and @p same_port=TRUE, set a cluster name using "
              "env EF_CLUSTER_NAME.");
    if (orphaned && same_port)
    {
        CHECK_RC(tapi_sh_env_set(pco_iut, "EF_CLUSTER_NAME",
                                 SOCKTS_CLUSTER_NAME, TRUE, FALSE));
    }

    TEST_STEP("Set env EF_CLUSTER_RESTART to value @p ef_cluster_restart.");
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_RESTART",
                                 ef_cluster_restart, TRUE, TRUE));

    TEST_STEP("Kill zombie stacks to make sure there is no orphaned sockets from the "
              "previous test runs for itertaions @p ef_cluster_restart=0.");
    if (ef_cluster_restart == 0)
        sockts_kill_check_zombie_stack(pco_iut, FALSE);

    TEST_STEP("Create auxiliary RPC server @b pco_iut2 if @p tp "
              "requires it.");
    init_aux_rpcs(pco_iut, &pco_iut2, tp);

    tapi_sockaddr_clone_exact(iut_addr, &iut_addr_bind1);
    if (wildcard)
        te_sockaddr_set_wildcard(SA(&iut_addr_bind1));

    TEST_STEP("Create two listener sockets, bound with SO_REUSEPORT to the "
              "same address/port chosen according to @p wildcard.");
    TEST_STEP("Accept TCP connections using both listeners to get at least one "
              "established connection for each listener. Close extra connections "
              "(from both sides, avoiding TIME_WAIT state on IUT) to keep only one "
              "connection for each listener.");

    reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr, tst_addr, &s1);
    reuseport_init_socket_ctx(pco_iut2, pco_tst, iut_addr, tst_addr, &s2);
    s1.iut_addr_bind = SA(&iut_addr_bind1);
    s2.iut_addr_bind = SA(&iut_addr_bind1);
    reuseport_pair_connection(RPC_SOCK_STREAM, &s1, &s2);

    TEST_STEP("Close listeners and accepted sockets in order chosen "
              "according to @p listeners_closing_order, @p first_listener_early, "
              "@p second_listener_early. If @p orphaned is @c TRUE, do not "
              "close Tester sockets, so that IUT sockets will hang orphaned in "
              "FIN_WAIT2 state; otherwise close Tester sockets before closing "
              "IUT accepted sockets to avoid hanging in TIME_WAIT state.");
    if (listeners_closing_order)
    {
        close_sockets(&s1, first_listener_early, orphaned);
        close_sockets(&s2, second_listener_early, orphaned);
    }
    else
    {
        close_sockets(&s2, second_listener_early, orphaned);
        close_sockets(&s1, first_listener_early, orphaned);
    }

    tapi_sockaddr_clone_exact(iut_addr, &iut_addr_bind2);
    if (!same_port)
        CHECK_RC(tapi_allocate_set_port(pco_iut, SA(&iut_addr_bind2)));
    tapi_sockaddr_clone_exact(SA(&iut_addr_bind2), &iut_addr_connect2);
    if (wildcard)
        te_sockaddr_set_wildcard(SA(&iut_addr_bind2));

    TEST_STEP("Create two new listener sockets binding them with SO_REUSEPORT "
              "to the same port as the previous listener sockets or to "
              "different port in dependence on @p same_port.");
    TEST_STEP("Accept connections using new listeners. -");

    reuseport_init_socket_ctx(pco_iut, pco_tst, SA(&iut_addr_connect2),
                              tst_addr, &s3);
    reuseport_init_socket_ctx(pco_iut2, pco_tst, SA(&iut_addr_connect2),
                              tst_addr, &s4);
    s3.iut_addr_bind = SA(&iut_addr_bind2);
    s4.iut_addr_bind = SA(&iut_addr_bind2);
    reuseport_pair_connection(RPC_SOCK_STREAM, &s3, &s4);

    TEST_STEP("Transmit data in both directions using the connections.");
    sockts_test_connection(s3.pco_iut, s3.iut_acc, pco_tst, s3.tst_s);
    sockts_test_connection(s4.pco_iut, s4.iut_acc, pco_tst, s4.tst_s);

    TEST_SUCCESS;

cleanup:

    reuseport_close_pair(&s1, &s2);
    reuseport_close_pair(&s3, &s4);

    if (pco_iut2 != NULL && pco_iut2 != pco_iut)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut2));

    TEST_END;
}
