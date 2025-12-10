/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-pbr_oif_src Using outgoing interface rule to determine source address
 *
 * @objective Check that outgoing interface rule works for a socket which
 *            was bound to an interface, so that a route from selected table
 *            is used to determine source address.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_mcast
 *                      - @ref arg_types_env_peer2peer_ipv6
 *                      - @ref arg_types_env_peer2peer_mcast_ipv6
 * @param multicast     If @c TRUE, check multicast traffic and
 *                      @c IP_MULTICAST_IF (or @c IPV6_MULTICAST_IF);
 *                      otherwise check unicast traffic and
 *                      @c SO_BINDTODEVICE.
 * @param rt_sock_type  Socket types:
 *                      - tcp_active
 *                      - udp
 *                      - udp_connect
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/pbr_oif_src"

#include "sockapi-test.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"
#include "ts_route.h"
#include "multicast.h"

/** Socket on IUT. */
int iut_s = -1;

/** Socket on Tester. */
int tst_s = -1;

/** Listener socket on Tester. */
int tst_listener = -1;

/**
 * Compare addresses (ignoring ports), print verdict and stop
 * testing if real address differs from expected one.
 *
 * @param exp_addr        Expected address.
 * @param real_addr       Obtained address.
 * @param real_addr_len   Obtained address length.
 * @param format          Format string to be used in verdict.
 * @param ...             Arguments for the format string.
 */
static void
compare_src_addr(const struct sockaddr *exp_addr,
                 const struct sockaddr *real_addr,
                 socklen_t real_addr_len,
                 const char *format, ...)
{
#define MAX_VERDICT_LEN 1000

    char        verdict_buf[MAX_VERDICT_LEN];
    te_string   str = TE_STRING_BUF_INIT(verdict_buf);
    va_list     ap;

    va_start(ap, format);
    te_string_append_va(&str, format, ap);
    va_end(ap);

    if (te_sockaddrcmp_no_ports(real_addr, real_addr_len,
                                exp_addr,
                                te_sockaddr_get_size(
                                  exp_addr)) != 0)
    {
        TEST_VERDICT("Unexpected source address was reported %s",
                     str.ptr);
    }
}

/**
 * Check that source address of a packet sent from IUT
 * depends on whether a socket is bound to an interface.
 *
 * @param pco_iut         RPC server on IUT.
 * @param pco_tst         RPC server on Tester.
 * @param rt_sock_type    Socket type to check.
 * @param iut_if          IUT network interface.
 * @param tst_if          Tester network interface.
 * @param iut_addr1       The first IP address assigned to IUT interface.
 * @param iut_addr2       The second IP address assigned to IUT interface.
 * @param dst_addr        IP address to which packets should be sent from
 *                        IUT.
 * @oaram bind_to_device  Whether IUT socket should be bound to IUT
 *                        interface. It is expected that if it is bound,
 *                        source address will be iut_addr2; otherwise it
 *                        will be iut_addr1.
 * @param multicast       If @c TRUE, check multicast traffic and
 *                        IP_MULTICAST_IF; otherwise check unicast traffic
 *                        and SO_BINDTODEVICE.
 */
static void
check_src_addr(rcf_rpc_server *pco_iut,
               rcf_rpc_server *pco_tst,
               sockts_socket_type rt_sock_type,
               const struct if_nameindex *iut_if,
               const struct if_nameindex *tst_if,
               const struct sockaddr *iut_addr1,
               const struct sockaddr *iut_addr2,
               const struct sockaddr *dst_addr,
               te_bool bind_to_device,
               te_bool multicast)
{
    struct sockaddr_storage  src_addr;
    socklen_t                src_addr_len;
    struct sockaddr_storage  tst_bind_addr;
    const struct sockaddr   *exp_src_addr = NULL;

    rpc_socket_type sock_type;
    int             rc;

    char    send_buf[SOCKTS_MSG_DGRAM_MAX];
    char    recv_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t  send_len;
    int     i;

    sock_type = sock_type_sockts2rpc(rt_sock_type);

    CHECK_RC(tapi_sockaddr_clone(pco_tst, dst_addr, &tst_bind_addr));

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                       sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(dst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, SA(&tst_bind_addr));

    if (multicast)
    {
        rpc_mcast_join(pco_tst, tst_s, SA(&tst_bind_addr),
                       tst_if->if_index, TARPC_MCAST_JOIN_LEAVE);
        TAPI_WAIT_NETWORK;
    }

    if (bind_to_device)
    {
        if (multicast)
        {
            sockts_set_multicast_if(pco_iut, iut_s, iut_addr1->sa_family,
                                    iut_if->if_index);
        }
        else
        {
            rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                               iut_if->if_name,
                               strlen(iut_if->if_name) + 1);
        }
    }

    if (bind_to_device)
        exp_src_addr = iut_addr2;
    else
        exp_src_addr = iut_addr1;

    if (sock_type == RPC_SOCK_STREAM)
    {
        tst_listener = tst_s;
        tst_s = -1;
        rpc_listen(pco_tst, tst_listener, SOCKTS_BACKLOG_DEF);

        rpc_connect(pco_iut, iut_s, SA(&tst_bind_addr));

        src_addr_len = sizeof(src_addr);
        tst_s = rpc_accept(pco_tst, tst_listener,
                           SA(&src_addr), &src_addr_len);

        compare_src_addr(exp_src_addr, SA(&src_addr),
                         src_addr_len,
                         "by accept() when socket was %sbound "
                         "to an interface",
                         (bind_to_device ? "" : "not "));
    }
    else
    {
        if (rt_sock_type == SOCKTS_SOCK_UDP)
            rpc_connect(pco_iut, iut_s, SA(&tst_bind_addr));
    }

    for (i = 0; i < SOCKTS_SEND_PACKETS_NUM; i++)
    {
        send_len = rand_range(1, SOCKTS_MSG_DGRAM_MAX);
        te_fill_buf(send_buf, send_len);

        if (rt_sock_type == SOCKTS_SOCK_UDP)
            rpc_send(pco_iut, iut_s, send_buf, send_len, 0);
        else
            rpc_sendto(pco_iut, iut_s, send_buf, send_len, 0,
                       SA(&tst_bind_addr));

        src_addr_len = sizeof(src_addr);
        rc = rpc_recvfrom(pco_tst, tst_s, recv_buf, sizeof(recv_buf), 0,
                          SA(&src_addr), &src_addr_len);
        if (rc != (int)send_len ||
            memcmp(send_buf, recv_buf, send_len) != 0)
            TEST_FAIL("Received data does not match sent data");

        /* recvfrom() does not report an address for TCP. */
        if (sock_type == RPC_SOCK_DGRAM)
            compare_src_addr(exp_src_addr, SA(&src_addr),
                             src_addr_len,
                             "by recvfrom() when socket was %sbound "
                             "to an interface",
                             (bind_to_device ? "" : "not "));
    }

    RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_tst, tst_s);
    if (tst_listener >= 0)
        RPC_CLOSE(pco_tst, tst_listener);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    const struct sockaddr  *dst_addr = NULL;
    const struct sockaddr  *mcast_addr = NULL;
    struct sockaddr        *iut_addr2 = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    tapi_env_net    *net = NULL;

    sockts_socket_type    rt_sock_type;
    te_bool               multicast;

    cfg_handle      rh1 = CFG_HANDLE_INVALID;
    cfg_handle      rh2 = CFG_HANDLE_INVALID;
    cfg_handle      ah1 = CFG_HANDLE_INVALID;
    cfg_handle      ah2 = CFG_HANDLE_INVALID;

    sockts_if_monitor route1_monitor = SOCKTS_IF_MONITOR_INIT;
    sockts_if_monitor route2_monitor = SOCKTS_IF_MONITOR_INIT;

    te_conf_ip_rule ip_rule;
    te_bool         rule_added = FALSE;

    int     af;
    int     route_prefix;
    int     domain;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_BOOL_PARAM(multicast);

    GET_DOMAIN_AF_PREFIX(iut_addr, domain, af, route_prefix);

    TEST_STEP("If @p multicast is @c TRUE, set @b dst_addr to @p mcast_addr, "
              "else set is to @p tst_addr.");
    if (multicast)
    {
        TEST_GET_ADDR(pco_tst, mcast_addr);
        dst_addr = mcast_addr;
    }
    else
    {
        dst_addr = tst_addr;
    }

    TEST_STEP("Allocate additional IP address @b iut_addr2 and assign it "
              "to @p iut_if.");
    CHECK_RC(tapi_cfg_alloc_net_addr((af == AF_INET ? net->ip4net :
                                                      net->ip6net),
                                     &ah1, &iut_addr2));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(
                                        pco_iut->ta, iut_if->if_name,
                                        iut_addr2,
                                        (af == AF_INET ? net->ip4pfx :
                                                         net->ip6pfx),
                                        FALSE, &ah2));

    TEST_STEP("IUT: ip route add @b dst_addr dev @p iut_if "
              "src @p iut_addr");
    TEST_SUBSTEP("Add this route to the local table if IPv6 multicast is "
                 "checked because Linux adds routes for multicast IPv6 "
                 "addresses there.");

    if (af == AF_INET6 && multicast)
    {
        /*
         * For unknown reason Linux adds routes for IPv6 multicast
         * addresses over all the interfaces in the local table, to
         * which leads the IP rule of highest priority for all traffic.
         * So we need to add our route for multicast traffic in the local
         * table too to overwrite those IPv6 multicast routes. Otherwise
         * packets may be sent over unexpected interface and this test will
         * fail.
         */
        CHECK_RC(tapi_cfg_add_full_route(
                            pco_iut->ta, af,
                            te_sockaddr_get_netaddr(dst_addr),
                            route_prefix, NULL, iut_if->if_name,
                            te_sockaddr_get_netaddr(iut_addr),
                            NULL, 0, 0, 0, 0, 0, 0,
                            TAPI_RT_TABLE_LOCAL, &rh1));
    }
    else
    {
        CHECK_RC(tapi_cfg_add_route(
                            pco_iut->ta, af,
                            te_sockaddr_get_netaddr(dst_addr),
                            route_prefix, NULL, iut_if->if_name,
                            te_sockaddr_get_netaddr(iut_addr),
                            0, 0, 0, 0, 0, 0,
                            &rh1));
    }

    TEST_STEP("IUT: ip rule add oif @p iut_if table @c SOCKTS_RT_TABLE_FOO");

    te_conf_ip_rule_init(&ip_rule);
    ip_rule.mask |= TE_IP_RULE_FLAG_FAMILY;
    ip_rule.family = af;
    ip_rule.mask |= TE_IP_RULE_FLAG_OIFNAME;
    sprintf(ip_rule.oifname, iut_if->if_name);
    ip_rule.mask |= TE_IP_RULE_FLAG_TABLE;
    ip_rule.table = SOCKTS_RT_TABLE_FOO;
    CHECK_RC(tapi_cfg_add_rule(pco_iut->ta, af, &ip_rule));
    rule_added = TRUE;

    TEST_STEP("IUT: ip route add @b dst_addr "
              "dev @p iut_if src @b iut_addr2 table @c SOCKTS_RT_TABLE_FOO");

    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(dst_addr),
                        route_prefix, NULL, iut_if->if_name,
                        te_sockaddr_get_netaddr(iut_addr2),
                        NULL, 0, 0, 0, 0, 0, 0,
                        SOCKTS_RT_TABLE_FOO, &rh2));

    CFG_WAIT_CHANGES;

    CHECK_RC(sockts_if_monitor_init(&route1_monitor,
                                    pco_iut->ta,
                                    iut_if->if_name, af,
                                    sock_type_sockts2rpc(rt_sock_type),
                                    iut_addr, dst_addr,
                                    FALSE, TRUE));

    CHECK_RC(sockts_if_monitor_init(&route2_monitor,
                                    pco_iut->ta,
                                    iut_if->if_name, af,
                                    sock_type_sockts2rpc(rt_sock_type),
                                    iut_addr2, dst_addr,
                                    FALSE, TRUE));

    TEST_STEP("Create a pair of sockets on IUT and Tester according to "
              "@p rt_sock_type. Check that a packet sent from IUT to "
              "@b dst_addr has @p iut_addr as souce address.");
    check_src_addr(pco_iut, pco_tst, rt_sock_type, iut_if, tst_if,
                   iut_addr, iut_addr2, dst_addr, FALSE,
                   multicast);

    TEST_STEP("Create another pair of sockets on IUT and Tester according to "
              "@p rt_sock_type. Bind IUT socket to @p iut_if interface using "
              "@c SO_BINDTODEVICE or @c IP_MULTICAST_IF (according to "
              "@p multicast). Check that a packet sent from IUT to "
              "@b dst_addr has @b iut_addr2 as souce address.");
    check_src_addr(pco_iut, pco_tst, rt_sock_type, iut_if, tst_if,
                   iut_addr, iut_addr2, dst_addr, TRUE,
                   multicast);

    TEST_STEP("Check whether outgoing traffic was accelerated on IUT "
              "in case of Onload and not accelerated otherwise.");

    CHECK_IF_ACCELERATED(&env, &route1_monitor,
                         "The first route");

    CHECK_IF_ACCELERATED(&env, &route2_monitor,
                         "The second route");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_listener);

    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&route1_monitor));
    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&route2_monitor));

    free(iut_addr2);

    if (rh2 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh2));
    if (rh1 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh1));

    if (rule_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           ip_rule.mask, &ip_rule));

    CLEANUP_CHECK_RC(cfg_del_instance(ah2, FALSE));
    CLEANUP_CHECK_RC(tapi_cfg_free_entry(&ah1));

    CFG_WAIT_CHANGES;

    TEST_END;
}
