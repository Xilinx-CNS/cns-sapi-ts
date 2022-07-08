/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-ipv6_recv_ip IPv6 socket receives IPv4 and IPv6 traffic
 *
 * @objective Check that IPv6 socket can receive both IPv4 and IPv6
 *            traffic.
 *
 * @type Conformance
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_p2p_ip4_ip6
 * @param sock_type   Socket type:
 *                    - @c SOCK_STREAM
 *                    - @c SOCK_DGRAM
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/ipv6_recv_ip"

#include "sockapi-test.h"
#include "onload.h"
#include "sockapi-ts_monitor.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *tst_addr6 = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *iut_addr6 = NULL;
    const struct sockaddr      *iut_addr = NULL;
    int                         iut_s6 = -1;
    int                         iut_acc6 = -1;
    int                         iut_acc4 = -1;
    int                         tst_s6 = -1;
    int                         tst_s4 = -1;
    int                         opt_val;
    rpc_socket_type             sock_type;

    struct sockaddr_storage ipv6_bind_addr;
    struct sockaddr_storage ipv6_conn_addr;
    struct sockaddr_storage ipv4_conn_addr;

    const struct if_nameindex  *iut_if;
    sockts_if_monitor           monitor4 = SOCKTS_IF_MONITOR_INIT;
    sockts_if_monitor           monitor6 = SOCKTS_IF_MONITOR_INIT;
    te_bool                     in4_detected = FALSE;
    te_bool                     out4_detected = FALSE;
    te_bool                     in6_detected = FALSE;
    te_bool                     out6_detected = FALSE;
    te_bool                     test_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr6);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IF(iut_if);

    tapi_sockaddr_clone_exact(iut_addr6, &ipv6_bind_addr);
    te_sockaddr_set_wildcard(SA(&ipv6_bind_addr));

    tapi_sockaddr_clone_exact(iut_addr6, &ipv6_conn_addr);
    tapi_sockaddr_clone_exact(iut_addr, &ipv4_conn_addr);
    SIN(&ipv4_conn_addr)->sin_port = SIN6(iut_addr6)->sin6_port;

    TEST_STEP("Create IPv6 socket of type @p sock_type on IUT.");
    iut_s6 = rpc_socket(pco_iut, RPC_PF_INET6, sock_type,
                        RPC_PROTO_DEF);

    TEST_STEP("Create IPv4 and IPv6 sockets of type @p sock_type "
              "on Tester, binding them to @p tst_addr and @p tst_addr6.");
    tst_s4 = rpc_socket(pco_tst, RPC_PF_INET, sock_type,
                        RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s4, tst_addr);
    tst_s6 = rpc_socket(pco_tst, RPC_PF_INET6, sock_type,
                        RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s6, tst_addr6);

    TEST_STEP("Disable @c IPV6_V6ONLY option on IUT socket.");
    opt_val = 0;
    rpc_setsockopt(pco_iut, iut_s6, RPC_IPV6_V6ONLY, &opt_val);

    TEST_STEP("Bind IUT socket to a wildcard address. Call @b listen() "
              "on it if it is TCP socket.");
    rpc_bind(pco_iut, iut_s6, SA(&ipv6_bind_addr));
    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_iut, iut_s6, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Check that IUT socket can receive datagram (in case of UDP) "
              "or accept connection request (in case of TCP) sent from "
              "IPv6 socket on Tester to IPv6 IUT address. Check that "
              "source address of received data (connection request) "
              "matches @p tst_addr6.");

    CHECK_RC(sockts_check_recv_accept(
                             pco_tst, tst_s6,
                             pco_iut, iut_s6,
                             tst_addr6, SA(&ipv6_conn_addr), RPC_PF_INET6,
                             sock_type, &iut_acc6, "IPv6 socket"));

    TEST_STEP("Check that IUT socket can receive datagram (in case of UDP) "
              "or accept connection request (in case of TCP) sent from "
              "IPv4 socket on Tester to IPv4 IUT address. Check that "
              "source address of received data (connection request) "
              "matches @p tst_addr.");

    CHECK_RC(sockts_check_recv_accept(
                             pco_tst, tst_s4,
                             pco_iut, iut_s6,
                             tst_addr, SA(&ipv4_conn_addr), RPC_PF_INET6,
                             sock_type, &iut_acc4, "IPv4 socket"));

    if (sock_type == RPC_SOCK_DGRAM)
        TEST_SUCCESS;

    TEST_STEP("Check that traffic over created IP6 and IP4 tcp connections "
              "is accelerated.");

    CHECK_RC(sockts_if_monitor_init(&monitor4,
                                    pco_iut->ta, iut_if->if_name, AF_INET,
                                    RPC_SOCK_STREAM,
                                    NULL, NULL,
                                    TRUE, TRUE));
    CHECK_RC(sockts_if_monitor_init(&monitor6,
                                    pco_iut->ta, iut_if->if_name, AF_INET6,
                                    RPC_SOCK_STREAM,
                                    NULL, NULL,
                                    TRUE, TRUE));

    sockts_test_connection(pco_iut, iut_acc4, pco_tst, tst_s4);
    sockts_test_connection(pco_iut, iut_acc6, pco_tst, tst_s6);

    CHECK_RC(sockts_if_monitor_check(&monitor4, FALSE, &in4_detected,
                                     &out4_detected));
    CHECK_RC(sockts_if_monitor_check(&monitor6, FALSE, &in6_detected,
                                     &out6_detected));

    if (tapi_onload_run())
    {
        if (in6_detected)
        {
            RING_VERDICT("Incoming IP6 traffic was not accelerated");
            test_failed = TRUE;
        }
        if (out6_detected)
        {
            RING_VERDICT("Outgoing IP6 traffic was not accelerated");
            test_failed = TRUE;
        }
        if (in4_detected)
        {
            RING_VERDICT("Incoming IP4 traffic was not accelerated");
            test_failed = TRUE;
        }
        if (out4_detected)
        {
            RING_VERDICT("Outgoing IP4 traffic was not accelerated");
            test_failed = TRUE;
        }
    }
    else
    {
        if (!in6_detected)
        {
            RING_VERDICT("Incoming IP6 traffic was not detected");
            test_failed = TRUE;
        }
        if (!out6_detected)
        {
            RING_VERDICT("Outgoing IP6 traffic was not detected");
            test_failed = TRUE;
        }
        if (!in4_detected)
        {
            RING_VERDICT("Incoming IP4 traffic was not detected");
            test_failed = TRUE;
        }
        if (!out4_detected)
        {
            RING_VERDICT("Outgoing IP4 traffic was not detected");
            test_failed = TRUE;
        }
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&monitor4));
    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&monitor6));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s6);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc4);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc6);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s4);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s6);

    TEST_END;
}
