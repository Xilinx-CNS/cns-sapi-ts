/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-rt_same_addr_if_down_up_one_sock Pass traffic through two interfaces with the same IP address using one socket
 *
 * @objective Using the same IP address on two interfaces with two mutually
 *            substitutable routes. Check that opened socket (bound and possibly
 *            connected) can send and receive traffic using alternative route if
 *            one of interfaces goes down.
 *
 *  @param env            Testing environment:
 *                        - @ref arg_types_env_triangle_variants_with_ipv6
 * @param rt_sock_type    Type of sockets used in test
 *                        - @c tcp_active
 *                        - @c tcp_passive
 *                        - @c udp
 *                        - @c udp_connect
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/rt_same_addr_if_down_up_one_sock"

#include "ts_route.h"

/**
 * Send the first packet from IUT to Tester after changing
 * interface state and routes.
 *
 * @note This function is needed because for unknown reason
 *       sending/receiving the first packet can take longer
 *       than TAPI_WAIT_NETWORK_DELAY (500 ms) for IPv6,
 *       especially if there is no gateway host between IUT
 *       and Tester.
 *       Adding more delays after interface and routes
 *       configuration but before data sending does not solve
 *       this problem.
 *
 * @param pco_iut           RPC server on IUT.
 * @param iut_s             IUT socket.
 * @param pco_tst           RPC server on Tester.
 * @param tst_s             Tester socket.
 * @param rt_sock_type      Socket type.
 * @param tst_addr          Address to which Tester socket is bound.
 * @param msg               Message to print in verdicts.
 */
static void
send_first_packet(rcf_rpc_server *pco_iut, int iut_s,
                  rcf_rpc_server *pco_tst, int tst_s,
                  sockts_socket_type rt_sock_type,
                  const struct sockaddr *tst_addr,
                  const char *msg)
{
    char      snd_buf[1024];
    char      rcv_buf[sizeof(snd_buf)];
    size_t    pkt_len;
    te_bool   readable;
    int       rc;

    pkt_len = rand_range(1, sizeof(snd_buf));
    te_fill_buf(snd_buf, pkt_len);

    if (rt_sock_type == SOCKTS_SOCK_UDP_NOTCONN)
        rpc_sendto(pco_iut, iut_s, snd_buf, pkt_len, 0, tst_addr);
    else
        rpc_send(pco_iut, iut_s, snd_buf, pkt_len, 0);

    /* ST-2045: sender may fragment the TCP stream, so wait while
     * all segments are received before call rpc_get_rw_ability.
     * See also @note section for this function. */
    SLEEP(2);
    RPC_GET_READABILITY(readable, pco_tst, tst_s, 0);
    if (!readable)
    {
        TEST_VERDICT("%s: socket did not become readable after "
                     "sending data", msg);
    }

    rc = rpc_recv(pco_tst, tst_s, rcv_buf, sizeof(rcv_buf), 0);
    if(rc != (int)pkt_len || memcmp(snd_buf, rcv_buf, pkt_len) != 0)
    {
        TEST_VERDICT("%s: received data does not match sent data",
                     msg);
    }
}

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut1_if = NULL;
    const struct if_nameindex *iut2_if = NULL;
    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *iut_if2 = NULL;
    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;
    const struct if_nameindex *gwa_if = NULL;
    const struct if_nameindex *gwb_if = NULL;

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_gw = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;
    sockts_socket_type     rt_sock_type;

    struct sockaddr *iut_addr = NULL;
    struct sockaddr *tst_addr = NULL;
    const struct sockaddr *gwa_addr = NULL;
    const struct sockaddr *gwb_addr = NULL;

    cfg_handle new_net = CFG_HANDLE_INVALID;

    cfg_handle  iut_ah = CFG_HANDLE_INVALID;
    cfg_handle  tst_ah = CFG_HANDLE_INVALID;
    cfg_handle  iut1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle  iut2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle  tst_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle  rh1 = CFG_HANDLE_INVALID;
    cfg_handle  rh2 = CFG_HANDLE_INVALID;
    cfg_handle  rh3 = CFG_HANDLE_INVALID;
    cfg_handle  rh4 = CFG_HANDLE_INVALID;
    cfg_handle  rh_tst = CFG_HANDLE_INVALID;
    te_bool     single_peer = FALSE;
    te_bool     down = FALSE;
    te_bool     handover = FALSE;

    int iut_s = -1;
    int tst_s = -1;
    int route_prefix;
    int domain;
    int af = AF_INET;

    tarpc_linger  linger_val = { .l_onoff = 1, .l_linger = 0 };

    DECLARE_TWO_IFS_MONITORS;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);
    if (strcmp(pco_tst->ta, pco_gw->ta) == 0)
        single_peer = TRUE;

    TEST_GET_IF(iut1_if);
    TEST_GET_IF(iut2_if);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    if (!single_peer)
    {
        TEST_GET_IF(gwa_if);
        TEST_GET_IF(gwb_if);
    }
    TEST_GET_ADDR_NO_PORT(gwa_addr);
    TEST_GET_ADDR_NO_PORT(gwb_addr);
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    TEST_STEP("Allocate new addresses @b iut_addr and @b tst_addr.");

    af = gwa_addr->sa_family;
    CHECK_RC(tapi_cfg_alloc_net(af, &new_net));
    CHECK_RC(tapi_cfg_alloc_net_addr(new_net,
                                     &iut_ah, &iut_addr));
    CHECK_RC(tapi_cfg_alloc_net_addr(new_net,
                                     &tst_ah, &tst_addr));

    CHECK_RC(tapi_allocate_set_port(pco_iut, iut_addr));
    CHECK_RC(tapi_allocate_set_port(pco_tst, tst_addr));

    domain = rpc_socket_domain_by_addr(iut_addr);
    route_prefix = te_netaddr_get_bitsize(af);

    /* Set aliases to use generic macros. */
    iut_if1 = iut1_if;
    iut_if2 = iut2_if;
    pco_tst1 = pco_tst;
    pco_tst2 = pco_tst;

    if (sockts_if_accelerated(&env, pco_iut->ta, iut_if1->if_name) == FALSE)
        handover = TRUE;

    TEST_STEP("If IPv6 is checked, set @c keep_addr_on_down on @p iut1_if "
              "to @c 1 to avoid disappearance of assigned IPv6 address "
              "after setting interface down.");
    if (af == AF_INET6)
    {
        CHECK_RC(tapi_cfg_sys_set_int(
                              pco_iut->ta, 1, NULL,
                              "net/ipv6/conf:%s/keep_addr_on_down",
                              iut1_if->if_name));
    }

    TEST_STEP("Set up network:");

    TEST_SUBSTEP("IUT: ip addr add @b iut_addr dev @p iut1_if");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut1_if->if_name,
                                           iut_addr, -1, FALSE,
                                           &iut1_addr_hndl));
    TEST_SUBSTEP("IUT: ip addr add @b iut_addr dev @p iut2_if");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut2_if->if_name,
                                           iut_addr, -1, FALSE,
                                           &iut2_addr_hndl));

    TEST_SUBSTEP("TST: ip addr add @b tst_addr dev @p tst1_if");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst1_if->if_name,
                                           tst_addr, -1, FALSE,
                                           &tst_addr_hndl));

    if (af == AF_INET6)
    {
        /*
         * NDP proxy is required to make IUT to respond to NDP
         * requests for an address assigned on another
         * interface.
         */
        CHECK_RC(sockts_rt_enable_ndp_proxy(pco_tst->ta,
                                            tst2_if->if_name));
        CHECK_RC(tapi_cfg_add_neigh_proxy(pco_tst->ta,
                                          tst2_if->if_name,
                                          tst_addr, NULL));
    }

    TEST_SUBSTEP("IUT: ip route add @b tst_addr dev @p iut1_if metric 1");
    CHECK_RC(tapi_cfg_add_route(pco_iut->ta, af,
                                te_sockaddr_get_netaddr(tst_addr),
                                route_prefix,
                                te_sockaddr_get_netaddr(gwa_addr),
                                iut1_if->if_name,
                                NULL, 0, 1, 0, 0, 0, 0, &rh1));

    TEST_SUBSTEP("IUT: ip route add @b tst_addr dev @p iut2_if metric 2");
    CHECK_RC(tapi_cfg_add_route(pco_iut->ta, af,
                                te_sockaddr_get_netaddr(tst_addr),
                                route_prefix,
                                NULL,
                                iut2_if->if_name,
                                NULL, 0, 2, 0, 0, 0, 0, &rh2));

    TEST_SUBSTEP("GW: set up gateway connecting @p iut1_if and @p tst1_if "
                 "if @p pco_tst and @p pco_gw are on different "
                 "Test Agents.");
    if (!single_peer)
    {
        if (af == AF_INET)
            CHECK_RC(tapi_cfg_base_ipv4_fw(pco_gw->ta, TRUE));
        else
            CHECK_RC(tapi_cfg_base_ipv6_fw(pco_gw->ta, TRUE));

        CHECK_RC(tapi_cfg_add_route(pco_gw->ta, af,
                                    te_sockaddr_get_netaddr(iut_addr),
                                    route_prefix, NULL, gwa_if->if_name,
                                    NULL, 0, 0, 0, 0, 0, 0, &rh3));

        CHECK_RC(tapi_cfg_add_route(pco_gw->ta, af,
                                    te_sockaddr_get_netaddr(tst_addr),
                                    route_prefix, NULL, gwb_if->if_name,
                                    NULL, 0, 0, 0, 0, 0, 0, &rh4));
    }

    TEST_SUBSTEP("TST: ip route add @p iut_addr dev @p tst1_if");
    CHECK_RC(tapi_cfg_add_route(pco_tst->ta, af,
                                te_sockaddr_get_netaddr(iut_addr),
                                route_prefix,
                                te_sockaddr_get_netaddr(gwb_addr),
                                tst1_if->if_name,
                                NULL, 0, 0, 0, 0, 0, 0, &rh_tst));
    CFG_WAIT_CHANGES;

    INIT_TWO_IFS_MONITORS(tst_addr, af, rt_sock_type);

    TEST_STEP("Create socket on IUT according to @p rt_sock_type and its "
              "peer on Tester.");
    TEST_STEP("Bind IUT socket to @b iut_addr, Tester socket to "
              "@b tst_addr.");

    if (rt_sock_type == SOCKTS_SOCK_UDP_NOTCONN)
    {
        iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM,
                           RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s, iut_addr);
        tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM,
                           RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_s, tst_addr);
    }
    else
    {
        sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr,
                          rt_sock_type,
                          FALSE, FALSE, NULL, &iut_s, &tst_s, NULL,
                          SOCKTS_SOCK_FUNC_SOCKET);
    }

    TEST_STEP("Check data transmission in both directions between "
              "IUT and Tester sockets, check that traffic from IUT "
              "goes via the first interface.");

    send_first_packet(pco_iut, iut_s, pco_tst, tst_s,
                      rt_sock_type, tst_addr,
                      "Sending the first packet from IUT before setting "
                      "interface down");
    SOCKTS_RT_CHECK_ROUTE_ONE_SOCK(TRUE, handover, "The first route");

    TEST_STEP("Update network configuration:");
    TEST_SUBSTEP("Down @p iut1_if.");
    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if1->if_name));
    /* Avoid FAILED neighbor entry on peer */
    if (single_peer)
    {
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst1_if->if_name,
                                          gwb_addr));
    }
    else
    {
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_gw->ta, gwa_if->if_name,
                                          iut_addr));
    }
    down = TRUE;
    CFG_WAIT_CHANGES;

    TEST_SUBSTEP("TST: ip route del @b iut_addr dev @p tst1_if");
    CHECK_RC(tapi_cfg_del_route(&rh_tst));
    TEST_SUBSTEP("TST: ip route add @b iut_addr dev @p tst2_if");
    CHECK_RC(tapi_cfg_add_route(pco_tst->ta, af,
                                te_sockaddr_get_netaddr(iut_addr),
                                route_prefix,
                                NULL,
                                tst2_if->if_name,
                                NULL, 0, 0, 0, 0, 0, 0, &rh_tst));
    CFG_WAIT_CHANGES;

    TEST_STEP("Check data transmission in both directions using the "
              "previously created sockets; check that traffic goes "
              "over the second interface from IUT.");

    send_first_packet(pco_iut, iut_s, pco_tst, tst_s,
                      rt_sock_type, tst_addr,
                      "Sending the first packet from IUT after setting "
                      "interface down");
    SOCKTS_RT_CHECK_ROUTE_ONE_SOCK(FALSE, handover, "The second route");

    TEST_STEP("Update network configuration:");
    TEST_SUBSTEP("Up @p iut1_if.");
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if1->if_name));
    down = FALSE;
    CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if1->if_name));
    CFG_WAIT_CHANGES;

    TEST_SUBSTEP("TST: ip route del @b iut_addr dev @p tst2_if");
    CHECK_RC(tapi_cfg_del_route(&rh_tst));
    TEST_SUBSTEP("TST: ip route add @b iut_addr dev @p tst1_if");
    CHECK_RC(tapi_cfg_add_route(pco_tst->ta, af,
                                te_sockaddr_get_netaddr(iut_addr),
                                route_prefix,
                                te_sockaddr_get_netaddr(gwb_addr),
                                tst1_if->if_name,
                                NULL, 0, 0, 0, 0, 0, 0, &rh_tst));

    TEST_SUBSTEP("IUT: ip route add @b tst_addr dev @p iut1_if metric 1");
    CHECK_RC(tapi_cfg_add_route(pco_iut->ta, af,
                                te_sockaddr_get_netaddr(tst_addr),
                                route_prefix,
                                te_sockaddr_get_netaddr(gwa_addr),
                                iut1_if->if_name,
                                NULL, 0, 1, 0, 0, 0, 0, &rh1));
    CFG_WAIT_CHANGES;

    /* Re-create traffic monitors on @p iut_if1.  */
    CHECK_RC(sockts_if_monitor_destroy(&iut_if1_monitor));
    CHECK_RC(sockts_if_monitor_destroy(&tst1_if_monitor));
    CHECK_RC(sockts_if_monitor_init(
                            &iut_if1_monitor,
                            pco_iut->ta, iut_if1->if_name, af,
                            sock_type_sockts2rpc(rt_sock_type),
                            NULL, tst_addr, FALSE, TRUE));
    CHECK_RC(sockts_if_monitor_init(&tst1_if_monitor,
                            pco_tst1->ta, tst1_if->if_name, af,
                            sock_type_sockts2rpc(rt_sock_type),
                            tst_addr, NULL, TRUE, FALSE));

    TEST_STEP("Check data transmission in both directions using the "
              "previously created sockets; check that traffic goes "
              "over the first interface from IUT.");

    send_first_packet(pco_iut, iut_s, pco_tst, tst_s,
                      rt_sock_type, tst_addr,
                      "Sending the first packet from IUT after setting "
                      "interface up");
    SOCKTS_RT_CHECK_ROUTE_ONE_SOCK(TRUE, handover, "The third route");

    TEST_SUCCESS;

cleanup:
    CLEANUP_TWO_IFS_MONITORS;

    if (down)
    {
        CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if1->if_name));
        CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if1->if_name));
    }

    /*
     * Set SO_LINGER to zero before closing to avoid disturbing
     * the next iteration with retransmits.
     */
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &linger_val);
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER, &linger_val);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (rh1 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh1));
    if (rh2 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh2));
    if (rh3 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh3));
    if (rh4 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh4));
    if (rh_tst != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh_tst));

    if (iut1_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(iut1_addr_hndl, FALSE));
    if (iut2_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(iut2_addr_hndl, FALSE));
    if (tst_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst_addr_hndl, FALSE));

    if (iut_ah != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_free_entry(&iut_ah));
    if (tst_ah != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_free_entry(&tst_ah));

    if (new_net != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_free_entry(&new_net));

    if (af == AF_INET6)
        CLEANUP_CHECK_RC(sockts_restart_all_env_ifs(&env));

    free(iut_addr);
    free(tst_addr);

    TEST_END;
}
