/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Recreating clustered stack after sockets closing
 */

/**
 * @page reuseport-cluster_restart_one_closed Recreating clustered stack after sockets closing
 *
 * @objective Check that if set EF_CLUSTER_RESTART=1 then orphaned socket is
 *            destroyed after cluster stack recreating, but non-orphaned socket
 *            is not affected. Orphaned socket is obtained by closing both
 *            listener and accepted sockets.
 *
 * @param wildcard              Listener sockets binding address type:
 *      - False: specific address
 *      - True: INADRR_ANY
 * @param second_state          Get socket accepted on the second listener in
 *                              one of the listed states:
 *      - LAST_ACK
 *      - FIN_WAIT1
 *      - FIN_WAIT2
 *      - CLOSING
 *      - TIME_WAIT
 * @param first_close           Determines the first listener and accepted
 *                              sockets story:
 *      - alive: both sockets stay alive;
 *      - listener: close listener socket;
 *      - accepted: close accepted socket.
 * @param second_close_listener Determines the order of closing the second
 *                              listener and accepted sockets:
 *      - False: close accepted socket first;
 *      - True: close listener socket first.
 * @param tp                    Create aux processes/threads or not:
 *      - none: create sockets in the same thread;
 *      - thread: create sockets in different threads;
 *      - process: create sockets in different processes.
 * @param new_bind_first        Bind new listener socket using the first or the
 *                              second process/thread first, iterating makes
 *                              sense only for @p tp={thread,process}:
 *      - True: use the first process/thread;
 *      - False: use the second process/thread.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "reuseport/cluster_restart_one_closed"

#include "sockapi-test.h"
#include "reuseport.h"

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    tapi_route_gateway gateway;
    struct sockaddr   *iut_addr_bind = NULL;
    rcf_rpc_server    *pco_iut2 = NULL;
    rcf_rpc_server    *pco_iut_ref = NULL;

    struct sockaddr_storage tst_addr_bind;
    socklen_t               addr_len;
    reuseport_close_type    first_close;

    reuseport_socket_ctx s1 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s2 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s3 = REUSEPORT_SOCKET_CTX_INIT;

    rpc_tcp_state   second_state;
    te_bool         second_close_listener;
    te_bool         new_bind_first;
    te_bool         wildcard;
    int             tp;
    int             iut_s = -1;
    int             tst_s = -1;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(wildcard);
    TEST_GET_TCP_STATE(second_state);
    TEST_GET_ENUM_PARAM(first_close, REUSEPORT_CLOSE);
    TEST_GET_BOOL_PARAM(second_close_listener);
    TEST_GET_ENUM_PARAM(tp, THREAD_PROCESS);
    TEST_GET_BOOL_PARAM(new_bind_first);

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

    /*- Set env EF_CLUSTER_RESTART=1. */
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_RESTART", 1, TRUE,
                                 TRUE));

    /*- Create auxiliary thread or process for the second listener socket in
     *  dependence on @p tp. */
    init_aux_rpcs(pco_iut, &pco_iut2, tp);

    /*- Create two listener sockets, for each */
    /*-- socket(); */
    /*-- setsockopt(SO_REUSEPORT, 1); */
    /*-- bind to an address in dependence on @p wildcard; */
    /*-- listen(). */
    /*- Accept TCP connections using both listeners to get at least one
     * established connection for each listener. Close extra connections
     * (from both sides, avoiding TIME_WAIT state on IUT) to keep only one
     * connection for each listener. */
    reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr, tst_addr, &s1);
    reuseport_init_socket_ctx(pco_iut2, pco_tst, iut_addr, tst_addr, &s2);
    s1.iut_addr_bind = iut_addr_bind;
    s2.iut_addr_bind = iut_addr_bind;
    reuseport_pair_connection(RPC_SOCK_STREAM, &s1, &s2);

    addr_len = sizeof(tst_addr_bind);
    rpc_getsockname(pco_tst, s2.tst_s, SA(&tst_addr_bind), &addr_len);

    /*- If @p first_close=listener */
    /*-- Close the first listener socket. */
    if (first_close == REUSEPORT_CLOSE_LISTENER)
        RPC_CLOSE(s1.pco_iut, s1.iut_s);

    /*- If @p first_close=accept */
    /*-- Close socket accepted using the first listener. */
    if (first_close == REUSEPORT_CLOSE_ACCEPTED)
        RPC_CLOSE(s1.pco_iut, s1.iut_acc);

    /*- Put socket accepted on the second listener to one of the states in
     *  dependence on iteration parameter @p second_state */
     reuseport_close_state_prepare(&gateway, second_state, NULL, &s2);

    /*-- Close both the second listener and its accepted sockets, the closing
     *   sequence depends on @p second_close_listener. */
     if (second_close_listener)
     {
         RPC_CLOSE(s2.pco_iut, s2.iut_s);
         RPC_CLOSE(s2.pco_iut, s2.iut_acc);
     }
     else
     {
         RPC_CLOSE(s2.pco_iut, s2.iut_acc);
         RPC_CLOSE(s2.pco_iut, s2.iut_s);
     }

    /*-- Do required activity on tester side, control traffic using gateway
     *   host. */
    reuseport_close_state_finish(second_state, NULL, &s2);

    /*- Create new listener socket in the first or the second process/thread
     *  in dependence on @p new_bind_first */
    reuseport_init_socket_ctx(new_bind_first ? pco_iut : pco_iut2, pco_tst,
                              iut_addr, tst_addr, &s3);
    s3.iut_s = reuseport_create_bind_socket(s3.pco_iut, RPC_SOCK_STREAM,
                                             iut_addr_bind, TRUE);
    rpc_listen(s3.pco_iut, s3.iut_s, 1);
    rpc_fcntl(s3.pco_iut, s3.iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    /*- Create one more new socket (in another thread/process if they are): */
    pco_iut_ref = new_bind_first ? pco_iut2 : pco_iut;
    iut_s = rpc_socket(pco_iut_ref, rpc_socket_domain_by_addr(iut_addr_bind),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_iut_ref, iut_s, RPC_SO_REUSEPORT, 1);

    /*-- If the first listener was closed - create new listener socket binding
     * to the same address. */
    if (first_close == REUSEPORT_CLOSE_LISTENER)
    {
        rpc_bind(pco_iut_ref, iut_s, iut_addr_bind);
        rpc_listen(pco_iut_ref, iut_s, 1);
        rpc_fcntl(pco_iut_ref, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);
        s1.pco_iut = pco_iut_ref;
        s1.iut_s = iut_s;
    }
    /*-- Otherwise attempt to bind it should fail. */
    else
    {
        TAPI_CALL_CHECK_RC(pco_iut_ref, bind, -1, RPC_ENOSPC, iut_s,
                           iut_addr_bind);
        RPC_CLOSE(pco_iut_ref, iut_s);
    }

    /*- Check that orphaned socket was destroyed. */
    reuseport_check_sockets_closing(s2.pco_iut, s2.iut_addr,
                                    SA(&tst_addr_bind), TRUE);

    /*- Fix channel to peer if it was broken to get @p second_state. */
    reuseport_fix_connection(second_state, &gateway);

    /*- Accept connections using both opened listener sockets. */
    pco_iut_ref = pco_iut;
    iut_s = s1.iut_acc;
    tst_s = s1.tst_s;
    s1.iut_acc = -1;
    s1.tst_s = -1;

    try_connect_pair(&s1, &s3);

    /*- Check data transmission in both directions on all existing
     *  connections. */
    sockts_test_connection(s1.pco_iut, s1.iut_acc, s1.pco_tst, s1.tst_s);
    sockts_test_connection(s3.pco_iut, s3.iut_acc, s3.pco_tst, s3.tst_s);
    if (first_close != REUSEPORT_CLOSE_ACCEPTED)
        sockts_test_connection(pco_iut_ref, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    reuseport_close_pair(&s1, &s3);
    CLEANUP_RPC_CLOSE(pco_iut_ref, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
