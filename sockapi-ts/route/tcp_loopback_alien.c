/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-tcp_loopback_alien Accepting connections on an IP believed to be loopback
 *
 * @objective Check that external incoming connections are handled correctly
 *            if the destination address belongs to loopback interface.
 *
 * @type Conformance.
 *
 * @param env           Testing environment:
 *                      - @c arg_types_env_peer2peer
 *                      - @c arg_types_env_peer2peer_ipv6
 * @param bind_to       Address to bind listener socket to.
 *                      - @c wildcard
 *                      - @c specific
 * @param iut_if_addr   If @c TRUE, assign an address both to loopback
 *                      interface and @p iut_if.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/tcp_loopback_alien"

#include "sockapi-test.h"
#include "sockapi-ts_net_conns.h"
#include "tapi_route_gw.h"

/**
 * Value to which /proc/sys/net/ipv4/tcp_syn_retries should be set
 * on Tester.
 */
#define TCP_SYN_RETRIES 3

/** How long to wait for connection establishment, in seconds. */
#define CONN_TIMEOUT    60

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_iut_aux = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr  *alien_addr = NULL;
    const struct sockaddr  *iut_lladdr = NULL;

    cfg_handle                net_handle = CFG_HANDLE_INVALID;
    unsigned int              net_prefix = 0;
    struct sockaddr          *iut_addr = NULL;
    struct sockaddr          *tst_addr = NULL;
    struct sockaddr_storage   iut_bind_addr;

    int       iut_s_listener = -1;
    int       iut_s_acc = -1;
    int       iut_s = -1;
    int       tst_s = -1;
    te_bool   done = FALSE;

    sockts_addr_type          bind_to;
    te_bool                   iut_if_addr;
    int                       af;
    rpc_socket_addr_family    rpc_af;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, alien_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    SOCKTS_GET_ADDR_TYPE(bind_to);
    TEST_GET_BOOL_PARAM(iut_if_addr);

    TEST_STEP("In the following steps check IPv4 or IPv6 depending "
              "on family of addresses passed in environment.");

    af = alien_addr->sa_family;
    rpc_af = addr_family_h2rpc(af);

    TEST_STEP("Create auxiliary @b pco_iut_aux RPC server on IUT.");

    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut_aux",
                                   &pco_iut_aux));

    TEST_STEP("Remove all existing IP addresses from @p iut_if and "
              "@p tst_if.");

    if (af == AF_INET)
    {
        CHECK_RC(tapi_cfg_del_if_ip4_addresses(pco_iut->ta,
                                               iut_if->if_name,
                                               NULL));
        CHECK_RC(tapi_cfg_del_if_ip4_addresses(pco_tst->ta,
                                               tst_if->if_name,
                                               NULL));
    }
    else
    {
        CHECK_RC(tapi_cfg_del_if_ip6_addresses(pco_iut->ta,
                                               iut_if->if_name,
                                               NULL));
        CHECK_RC(tapi_cfg_del_if_ip6_addresses(pco_tst->ta,
                                               tst_if->if_name,
                                               NULL));
    }

    TEST_STEP("Allocate two IP addresses, @b iut_addr and @b tst_addr, "
              "belonging to the same network.");

    sockts_allocate_network(&net_handle, &net_prefix, af);

    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, NULL, &iut_addr));
    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, NULL, &tst_addr));

    CHECK_RC(tapi_allocate_set_port(pco_iut, iut_addr));
    CHECK_RC(tapi_allocate_set_port(pco_tst, tst_addr));

    TEST_STEP("IUT: ip addr add @b iut_addr dev lo");

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta,
                                           "lo", iut_addr, net_prefix,
                                           TRUE, NULL));

    TEST_STEP("If @p iut_if_addr, also assign @b iut_addr to @p iut_if.");

    if (iut_if_addr)
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta,
                                               iut_if->if_name, iut_addr,
                                               net_prefix, TRUE, NULL));

    TEST_STEP("IUT: ip route add @b tst_addr dev lo");

    CHECK_RC(tapi_cfg_add_route(pco_iut->ta, af,
                                te_sockaddr_get_netaddr(tst_addr),
                                te_netaddr_get_bitsize(af),
                                NULL, "lo", NULL,
                                0, 0, 0, 0, 0, 0, NULL));

    TEST_STEP("TST: ip addr add @b tst_addr dev @p tst_if");

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta,
                                           tst_if->if_name, tst_addr,
                                           net_prefix, TRUE, NULL));

    TEST_STEP("TST: ip route add @b iut_addr dev @p tst_if");

    CHECK_RC(tapi_cfg_add_route(pco_tst->ta, af,
                                te_sockaddr_get_netaddr(iut_addr),
                                te_netaddr_get_bitsize(af),
                                NULL, tst_if->if_name, NULL,
                                0, 0, 0, 0, 0, 0, NULL));

    TEST_STEP("On Tester add a neighbor entry for @b iut_addr associating "
              "it with @p iut_lladdr.");

    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             iut_addr, CVT_HW_ADDR(iut_lladdr),
                             TRUE));

    tapi_sockaddr_clone_exact(iut_addr, &iut_bind_addr);
    if (bind_to == SOCKTS_ADDR_WILD)
        te_sockaddr_set_wildcard(SA(&iut_bind_addr));

    TEST_STEP("Create TCP socket @b iut_s_listener on IUT, bind it to "
              "wildcard address or @b iut_addr according to @p bind_to.");

    iut_s_listener = rpc_socket(pco_iut, rpc_af, RPC_SOCK_STREAM,
                                RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s_listener, SA(&iut_bind_addr));

    TEST_STEP("Call listen() on @b iut_s_listener and call accept() "
              "on it with @c RCF_RPC_CALL (it should hang).");

    rpc_listen(pco_iut, iut_s_listener, SOCKTS_BACKLOG_DEF);

    pco_iut->op = RCF_RPC_CALL;
    rpc_accept(pco_iut, iut_s_listener, NULL, NULL);

    TEST_STEP("Set /proc/sys/net/ipv4/tcp_syn_retries on Tester to "
              "@c TCP_SYN_RETRIES to adjust time connect() hangs before "
              "timing out.");

    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_tst->ta, TCP_SYN_RETRIES, NULL,
                                     "net/ipv4/tcp_syn_retries"));

    TEST_STEP("Create TCP socket @b tst_s on Tester, bind it to @b tst_addr "
              "and connect to @b iut_addr. Check that connect() fails with "
              "@c ETIMEDOUT.");

    tst_s = rpc_socket(pco_tst, rpc_af, RPC_SOCK_STREAM,
                       RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    RPC_AWAIT_ERROR(pco_tst);
    pco_tst->timeout = TE_SEC2MS(CONN_TIMEOUT);
    rc = rpc_connect(pco_tst, tst_s, iut_addr);
    if (rc >= 0)
        TEST_VERDICT("connect() from Tester succeeded unexpectedly");
    else if (RPC_ERRNO(pco_tst) != RPC_ETIMEDOUT)
        ERROR_VERDICT("connect() from Tester failed with unexpected "
                      "errno %r", RPC_ERRNO(pco_tst));

    TEST_STEP("Check that accept() call on IUT still hangs.");

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_accept(pco_iut, iut_s_listener, NULL, NULL);
        if (rc >= 0)
            TEST_VERDICT("accept() succeeded unexpectedly after connect() "
                         "from Tester");
        else
            TEST_VERDICT("accept() unexpectedly failed with errno %r "
                         "after connect() from Tester",
                         RPC_ERRNO(pco_iut));
    }

    TEST_STEP("Create TCP socket @b iut_s on @b pco_iut_aux, connect it to "
              "@b iut_addr.");

    iut_s = rpc_socket(pco_iut_aux, rpc_af, RPC_SOCK_STREAM,
                       RPC_PROTO_DEF);
    RPC_AWAIT_ERROR(pco_iut_aux);
    rc = rpc_connect(pco_iut_aux, iut_s, iut_addr);
    if (rc < 0)
        TEST_VERDICT("connect() from IUT unexpectedly failed with errno %r",
                     RPC_ERRNO(pco_iut_aux));

    TEST_STEP("Check that accept() on IUT successfully returns connected "
              "@b iut_s_acc socket.");

    RPC_AWAIT_ERROR(pco_iut);
    iut_s_acc = rpc_accept(pco_iut, iut_s_listener, NULL, NULL);
    if (iut_s_acc < 0)
        TEST_VERDICT("After connect() from IUT accept() unexpectedly "
                     "failed with errno %r", RPC_ERRNO(pco_iut));

    TEST_STEP("Check data transmission between @b iut_s and @b iut_s_acc.");

    sockts_test_connection(pco_iut, iut_s_acc,
                           pco_iut_aux, iut_s);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut_aux, iut_s);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_aux));
    if (pco_iut->last_op == RCF_RPC_CALL)
    {
        rcf_rpc_server_restart(pco_iut);
    }
    else
    {
        CLEANUP_RPC_CLOSE(pco_iut, iut_s_acc);
        CLEANUP_RPC_CLOSE(pco_iut, iut_s_listener);
    }

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_cfg_free_entry(&net_handle));

    free(iut_addr);
    free(tst_addr);

    TEST_END;
}
