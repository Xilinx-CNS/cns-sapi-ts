/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Recreating a stack in an SO_REUSEPORT cluster
 */

/**
 * @page reuseport-cluster_restart_all_orphaned Recreating clustered stack while all sockets are orphaned
 *
 * @objective Check that orphaned sockets are destroyed after cluster stack
 *            recreating if set EF_CLUSTER_RESTART=1, otherwise binding of new
 *            socket in the same cluster fails.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_gw
 * @param ef_cluster_restart Set the value to EF_CLUSTER_RESTART:
 *      - @c 0
 *      - @c 1
 * @param state              Get IUT sockets in one of the listed states:
 *      - LAST_ACK
 *      - FIN_WAIT1
 *      - FIN_WAIT2
 *      - CLOSING
 *      - TIME_WAIT
 * @param kill_iut           Close IUT socket instead of killing the process
 *                           if @c FALSE, else - kill one of IUT processes.
 * @param wildcard           IUT socket binding address type:
 *      - FALSE: specific address
 *      - TRUE: @c INADRR_ANY
 * @param close_listeners   If @c TRUE - close IUT listener sockets before
 *                          accepted sockets closing or killing IUT processes.
 * @param tp                Create aux processes/threads or not:
 *      - none: create sockets in the same thread;
 *      - thread: create sockets in different threads;
 *      - process: create sockets in different processes.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "reuseport/cluster_restart_all_orphaned"

#include "sockapi-test.h"
#include "reuseport.h"

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    tapi_route_gateway gateway;
    struct sockaddr   *iut_addr_bind = NULL;
    rcf_rpc_server    *pco_iut2;

    struct sockaddr_storage tst_addr_bind1;
    struct sockaddr_storage tst_addr_bind2;
    socklen_t               addr_len;

    reuseport_socket_ctx s1 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s2 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s3 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s4 = REUSEPORT_SOCKET_CTX_INIT;

    rpc_tcp_state   state;
    te_bool         kill_iut;
    te_bool         wildcard;
    te_bool         close_listeners;
    int             ef_cluster_restart;
    int             tp;
    int             iut_s = -1;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_INT_PARAM(ef_cluster_restart);
    TEST_GET_TCP_STATE(state);
    TEST_GET_BOOL_PARAM(kill_iut);
    TEST_GET_BOOL_PARAM(wildcard);
    TEST_GET_BOOL_PARAM(close_listeners);
    TEST_GET_ENUM_PARAM(tp, THREAD_PROCESS);

    if (wildcard)
    {
        CHECK_RC(tapi_sockaddr_clone2(iut_addr, &iut_addr_bind));
        te_sockaddr_set_wildcard(iut_addr_bind);
    }
    else
    {
        iut_addr_bind = SA(iut_addr);
    }

    /*- Configure connection between IUT and Tester through gateway host. */
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);

    /*- Specify a cluster name using env EF_CLUSTER_NAME. */
    CHECK_RC(tapi_sh_env_set(pco_iut, "EF_CLUSTER_NAME", SOCKTS_CLUSTER_NAME,
                             TRUE, FALSE));

    /*- Set env EF_CLUSTER_RESTART to value @p ef_cluster_restart. */
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_RESTART",
                                 ef_cluster_restart, TRUE, TRUE));

    /*- Kill zombie stacks to make sure there is no orphaned sockets from the
     * previous test runs for itertaions @p ef_cluster_restart=0. */
    if (ef_cluster_restart == 0)
        sockts_kill_check_zombie_stack(pco_iut, FALSE);

    /*- Create aux thread or process in dependence on @p tp. */
    init_aux_rpcs(pco_iut, &pco_iut2, tp);

    /*- Create two listener sockets, for each:
     *  -# socket();
     *  -# setsockopt(SO_REUSEPORT, 1);
     *  -# bind to an address in dependence on @p bind_to;
     *  -# listen(). */
    /*- Accept TCP connection on both listeners. */
    reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr, tst_addr, &s1);
    reuseport_init_socket_ctx(pco_iut2, pco_tst, iut_addr, tst_addr, &s2);
    s1.iut_addr_bind = iut_addr_bind;
    s2.iut_addr_bind = iut_addr_bind;
    reuseport_pair_connection(RPC_SOCK_STREAM, &s1, &s2);

    addr_len = sizeof(tst_addr_bind1);
    rpc_getsockname(pco_tst, s1.tst_s, SA(&tst_addr_bind1), &addr_len);
    addr_len = sizeof(tst_addr_bind2);
    rpc_getsockname(pco_tst, s2.tst_s, SA(&tst_addr_bind2), &addr_len);

    /*- Close listener sockets now using close() if
     * @p close_listeners=TRUE. */
    if (close_listeners)
    {
        RPC_CLOSE(s1.pco_iut, s1.iut_s);
        RPC_CLOSE(s2.pco_iut, s2.iut_s);
    }

    /*- Put accepted IUT sockets to one of the states in dependence on
     * iteration parameter @p state: */
    /*-- Do required activity on tester side, control traffic using gateway
     * host. */
    reuseport_close_state_prepare(&gateway, state, &s1, &s2);

    if (kill_iut)
    {
        /*-- If @p kill_iut is @c TRUE:
         *   - kill the one or both IUT processes with accepted sockets and
         *     start new processes/threads. */
        switch (tp)
        {
            case TP_PROCESS:
                CHECK_RC(rcf_rpc_server_restart(s1.pco_iut));
                CHECK_RC(rcf_rpc_server_restart(s2.pco_iut));
                break;

            case TP_THREAD:
                CHECK_RC(rcf_rpc_server_destroy(pco_iut2));
                CHECK_RC(rcf_rpc_server_restart(s1.pco_iut));
                init_aux_rpcs(pco_iut, &pco_iut2, tp);
                s2.pco_iut = pco_iut2;
                break;

            case TP_NONE:
                CHECK_RC(rcf_rpc_server_restart(pco_iut));
                break;

            default:
                TEST_FAIL("Unexpected value of test parameter tp: %d", tp);
        }

        s1.iut_s = -1;
        s1.iut_acc = -1;
        s2.iut_s = -1;
        s2.iut_acc = -1;
    }
    else
    {
        /*-- Else: */
        /*--- close both accepted sockets; */
        RPC_CLOSE(s1.pco_iut, s1.iut_acc);
        RPC_CLOSE(s2.pco_iut, s2.iut_acc);

        /*--- close listener sockets now using close() if
         * @p close_listeners=FALSE. */
        if (!close_listeners)
        {
            RPC_CLOSE(s1.pco_iut, s1.iut_s);
            RPC_CLOSE(s2.pco_iut, s2.iut_s);
        }
    }

    TAPI_WAIT_NETWORK;

    reuseport_close_state_finish(state, &s1, &s2);

    /*- Create two new listener sockets in the same way as above: */
    if (ef_cluster_restart == 0)
    {
        /*-- bind() should fail if EF_CLUSTER_RESTART=0, orphaned sockets keep
         * alive: */
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr_bind),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_REUSEPORT, 1);
        TAPI_CALL_CHECK_RC(pco_iut, bind, -1, RPC_ENOSPC, iut_s,
                           iut_addr_bind);

        reuseport_check_sockets_closing(pco_iut, iut_addr,
                                        SA(&tst_addr_bind1), FALSE);
        reuseport_check_sockets_closing(pco_iut, iut_addr,
                                        SA(&tst_addr_bind2), FALSE);

        /*--- Fix channel to peer. */
        reuseport_fix_connection(state, &gateway);

        /*--- Close the rest opened sockets. */
        /*--- Stop the test. */
        TEST_SUCCESS;
    }

    /*- Continue the test execution if bind() is ok, check that all orphaned
     * sockets are destroyed. */
    reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr, tst_addr, &s3);
    reuseport_init_socket_ctx(pco_iut2, pco_tst, iut_addr, tst_addr, &s4);

    s3.iut_s = reuseport_create_bind_socket(s3.pco_iut, RPC_SOCK_STREAM,
                                             iut_addr_bind, TRUE);
    s4.iut_s = reuseport_create_bind_socket(s4.pco_iut, RPC_SOCK_STREAM,
                                             iut_addr_bind, TRUE);

    rpc_listen(s3.pco_iut, s3.iut_s, 1);
    rpc_listen(s4.pco_iut, s4.iut_s, 1);
    rpc_fcntl(s3.pco_iut, s3.iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);
    rpc_fcntl(s4.pco_iut, s4.iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    reuseport_check_sockets_closing(pco_iut, iut_addr, SA(&tst_addr_bind1),
                                    TRUE);
    reuseport_check_sockets_closing(pco_iut, iut_addr, SA(&tst_addr_bind2),
                                    TRUE);

    /*- Fix channel to peer: */
    reuseport_fix_connection(state, &gateway);

    /*-- Accept new connections on new listeners. */
    try_connect_pair(&s3, &s4);

    /*-- Transmit data in both directions using the connections. */
    sockts_test_connection(s3.pco_iut, s3.iut_acc, pco_tst, s3.tst_s);
    sockts_test_connection(s4.pco_iut, s4.iut_acc, pco_tst, s4.tst_s);

    TEST_SUCCESS;

cleanup:
    reuseport_close_pair(&s1, &s2);
    reuseport_close_pair(&s3, &s4);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
