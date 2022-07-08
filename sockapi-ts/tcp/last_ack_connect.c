/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-last_ack_connect New connection when the previous one is in LAST_ACK state
 *
 * @objective  Check that a new connection can be accepted when a socket
 *             from the previous one is still in LAST_ACK state.
 *
 * @type conformance
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_gw
 * @param active    If @c TRUE, connect() should be called
 *                  on IUT side, otherwise - on Tester side.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/last_ack_connect"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "tapi_sockets.h"

/*
 * How long to wait for termination of TIME_WAIT socket, in seconds.
 */
#define TIME_WAIT_TIMEOUT 200

/*
 * How long to wait for listener socket to become readable after
 * network connectivity is restored, in seconds.
 */
#define ACCEPT_TIMEOUT 10

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    rcf_rpc_server             *pco_clnt = NULL;
    rcf_rpc_server             *pco_srv = NULL;
    const struct sockaddr      *clnt_addr = NULL;
    const struct sockaddr      *srv_addr = NULL;

    int           clnt_s = -1;
    int           srv_s = -1;
    int           listener_s = -1;
    te_bool       active;
    te_bool       readable;
    int           epfd = -1;
    uint32_t      timeout;
    rpc_tcp_state tcp_state;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(active);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p active is @c TRUE, let's refer to Tester as Server and "
              "to IUT as Client. Otherwise refer to Tester as Client "
              "and to IUT as Server.");

    TEST_STEP("Create TCP sockets on Server and Client. Make Server socket "
              "listener, establish TCP connection calling @b connect() from "
              "Client.");

    if (active)
    {
        pco_clnt = pco_iut;
        pco_srv = pco_tst;
        clnt_addr = iut_addr;
        srv_addr = tst_addr;
    }
    else
    {
        pco_clnt = pco_tst;
        pco_srv = pco_iut;
        clnt_addr = tst_addr;
        srv_addr = iut_addr;
    }

    listener_s = rpc_socket(pco_srv, rpc_socket_domain_by_addr(srv_addr),
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_srv, listener_s, srv_addr);
    rpc_listen(pco_srv, listener_s, SOCKTS_BACKLOG_DEF);

    clnt_s = rpc_socket(pco_clnt, rpc_socket_domain_by_addr(clnt_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_clnt, clnt_s, clnt_addr);

    rpc_connect(pco_clnt, clnt_s, srv_addr);
    srv_s = rpc_accept(pco_srv, listener_s, NULL, NULL);

    TEST_STEP("Call @b shutdown(@c SHUT_WR) on connected socket on Client, so that "
              "Server socket receives @c FIN and moves to @c CLOSE_WAIT state.");

    rpc_shutdown(pco_clnt, clnt_s, RPC_SHUT_WR);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Break network connectivity from Client to Server.");

    if (active)
        CHECK_RC(tapi_route_gateway_break_gw_tst(&gateway));
    else
        CHECK_RC(tapi_route_gateway_break_tst_gw(&gateway));

    CFG_WAIT_CHANGES;

    TEST_STEP("Call @b shutdown(@c SHUT_WR) on accepted socket on Server, to move "
              "it to @c LAST_ACK state.");

    rpc_shutdown(pco_srv, srv_s, RPC_SHUT_WR);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that server socket is in @c LAST_ACK state now.");

    if (tapi_get_tcp_sock_state(pco_srv, srv_s) != RPC_TCP_LAST_ACK)
        TEST_VERDICT("LAST_ACK state was not achieved on server");

    tcp_state = tapi_get_tcp_sock_state(pco_clnt, clnt_s);
    if (tcp_state != RPC_TCP_CLOSE)
    {
        RING_VERDICT("Client socket is observed in %s state,"
                     " but should be in TCP_CLOSE",
                     tcp_state_rpc2str(tcp_state));
    }


    TEST_STEP("Now break connectivity from Server to Client too, so that "
              "@c FIN retransmits will not interfere with @c TIME_WAIT state "
              "disappearance.");

    if (active)
        CHECK_RC(tapi_route_gateway_break_tst_gw(&gateway));
    else
        CHECK_RC(tapi_route_gateway_break_gw_tst(&gateway));

    CFG_WAIT_CHANGES;

    TEST_STEP("Wait until Client socket is moved to @c CLOSED state. "
              "If previous state is @c TCP_TIME_WAIT probably ZF shim is runned, "
              "try to perform transition to @c CLOSED.");
    timeout = TE_SEC2MS(TIME_WAIT_TIMEOUT);

    if (tcp_state == RPC_TCP_TIME_WAIT)
    {
        /* epoll_wait() with the empty set is a way to call reactor */
        epfd = rpc_epoll_create(pco_clnt, 1);
        rpc_epoll_wait(pco_clnt, epfd, NULL, 0, timeout);

        tcp_state = tapi_get_tcp_sock_state(pco_clnt, clnt_s);
        if (tcp_state != RPC_TCP_CLOSE)
            rc = -1;
    }
    else
    {
        pco_clnt->timeout = timeout;
        RPC_AWAIT_ERROR(pco_clnt);
        rc = rpc_wait_tcp_socket_termination(pco_clnt, clnt_addr, srv_addr,
                                             NULL, NULL, NULL);
    }
    if (rc < 0)
    {
        TEST_VERDICT("Client socket failed to shutdown completely %r",
                     RPC_ERRNO(pco_clnt));
    }

    TEST_STEP("Restore network connectivity from Server to Client.");

    if (active)
        CHECK_RC(tapi_route_gateway_repair_tst_gw(&gateway));
    else
        CHECK_RC(tapi_route_gateway_repair_gw_tst(&gateway));

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that Server socket is still in @c LAST_ACK state.");

    if (tapi_get_tcp_sock_state(pco_srv, srv_s) != RPC_TCP_LAST_ACK)
        TEST_VERDICT("After waiting for client socket termination "
                     "server socket is no longer in LAST_ACK state");

    TEST_STEP("Create another TCP socket on Client, @b bind() it to the same "
              "address. Call nonblocking @b connect() to the same address on "
              "Server, check that it hangs.");

    RPC_CLOSE(pco_clnt, clnt_s);
    clnt_s = rpc_socket(pco_clnt, rpc_socket_domain_by_addr(clnt_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_clnt, clnt_s, clnt_addr);
    rpc_fcntl(pco_clnt, clnt_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    RPC_AWAIT_ERROR(pco_clnt);
    rc = rpc_connect(pco_clnt, clnt_s, srv_addr);

    if (rc == 0)
    {
        TEST_VERDICT("Nonblocking connect() succeeded unexpectedly");
    }
    else if (RPC_ERRNO(pco_clnt) != RPC_EINPROGRESS)
    {
        TEST_VERDICT("Nonblocking connect() failed with unexpected "
                     "errno %r", RPC_ERRNO(pco_clnt));
    }

    TAPI_WAIT_NETWORK;
    RPC_AWAIT_ERROR(pco_clnt);
    rc = rpc_connect(pco_clnt, clnt_s, srv_addr);

    /* Note: ZF shim returns EINPROGRESS errno instead EALREADY */
    if (rc == 0)
    {
        RING_VERDICT("Nonblocking connect() succeeded unexpectedly "
                     "when called the second time");
    }
    else if (RPC_ERRNO(pco_clnt) != RPC_EALREADY)
    {
        RING_VERDICT("Nonblocking connect() failed with unexpected "
                     "errno %r when called the second time",
                     RPC_ERRNO(pco_clnt));
    }

    TEST_STEP("Restore network connectivity from Client to Server.");

    if (active)
        CHECK_RC(tapi_route_gateway_repair_gw_tst(&gateway));
    else
        CHECK_RC(tapi_route_gateway_repair_tst_gw(&gateway));

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that listener on Server becomes readable.");

    RPC_GET_READABILITY(readable, pco_srv, listener_s,
                        TE_SEC2MS(ACCEPT_TIMEOUT));
    if (!readable)
        TEST_VERDICT("Listener socket is not readable after "
                     "restoring network connectivity");

    TEST_STEP("Check that connected server socket from the previous "
              "connection was moved from @c LAST_ACK to @c CLOSE state.");

    if (tapi_get_tcp_sock_state(pco_srv, srv_s) != RPC_TCP_CLOSE)
        TEST_VERDICT("Server socket hanging in LAST_ACK state "
                     "was not closed");

    TEST_STEP("Call @b accept() on Server.");

    RPC_CLOSE(pco_srv, srv_s);
    srv_s = rpc_accept(pco_srv, listener_s, NULL, NULL);

    TEST_STEP("Check that connection establishment is successfully finished "
              "on Client.");

    RPC_AWAIT_ERROR(pco_clnt);
    rc = rpc_connect(pco_clnt, clnt_s, srv_addr);
    if (rc < 0)
        TEST_VERDICT("Nonblocking connect() unexpectedly failed with "
                     "errno %r when called the third time",
                     RPC_ERRNO(pco_clnt));

    TEST_STEP("Check that data can be transmitted in both directions over "
              "established connection.");

    rpc_fcntl(pco_clnt, clnt_s, RPC_F_SETFL, 0);

    sockts_test_connection(pco_srv, srv_s, pco_clnt, clnt_s);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_srv, listener_s);
    CLEANUP_RPC_CLOSE(pco_srv, srv_s);
    CLEANUP_RPC_CLOSE(pco_clnt, clnt_s);
    CLEANUP_RPC_CLOSE(pco_clnt, epfd);

    TEST_END;
}
