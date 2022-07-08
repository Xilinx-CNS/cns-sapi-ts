/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-rt_same_addr_if_down_up Using the same IP address on two interfaces
 *
 * @objective Using the same IP address on two interfaces with two mutually
 *            substitutable routes. Check that if one of interfaces goes down
 *            the second one is used without visible changes for user.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_two_ifs_variants_with_ipv6
 * @param rt_sock_type  Type of sockets used in the test:
 *                      - @c tcp_active
 *                      - @c tcp_passive
 *                      - @c udp
 *                      - @c udp_connect
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/rt_same_addr_if_down_up"

#include "ts_route.h"

int
main(int argc, char *argv[])
{
    DECLARE_TWO_IFS_COMMON_PARAMS_PBR;
    sockts_socket_type      rt_sock_type;
    const struct sockaddr  *tst_addr = NULL;

    cfg_handle  tst1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle  tst2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle  iut1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle  iut2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle  rh1 = CFG_HANDLE_INVALID;
    cfg_handle  rh2 = CFG_HANDLE_INVALID;
    te_bool     down = FALSE;
    te_bool     keep_addr_on_down = FALSE;
    int         old_keep_addr = 0;

    int route_prefix;
    int domain;
    int af;

    DECLARE_TWO_IFS_MONITORS;

    TEST_START;
    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    GET_DOMAIN_AF_PREFIX(tst1_addr, domain, af, route_prefix);

    TEST_STEP("Set @p iut_addr to @p alien_addr.");
    iut_addr = alien_addr;
    /* These are set to hack TWO_IFS_CHECK_ROUTE_PBR_GEN(). */
    iut_addr1 = iut_addr;
    iut_addr2 = iut_addr;

    TEST_STEP("Set @p tst_addr to @p alien_gw.");
    tst_addr = alien_gw;

    TEST_STEP("If IPv6 is checked, set @b keep_addr_on_down on @p iut_if1 "
              "to @c 1 to avoid disappearance of assigned IPv6 address "
              "after setting interface down (if this option is "
              "available).");
    if (iut_addr->sa_family == AF_INET6)
    {
        rc = tapi_cfg_sys_get_int(pco_iut->ta, &old_keep_addr,
                                  "net/ipv6/conf:%s/keep_addr_on_down",
                                  iut_if1->if_name);
        if (rc == 0 && old_keep_addr <= 0)
        {
            CHECK_RC(tapi_cfg_sys_set_int(
                                  pco_iut->ta, 1, NULL,
                                  "net/ipv6/conf:%s/keep_addr_on_down",
                                  iut_if1->if_name));
            keep_addr_on_down = TRUE;
        }
    }

    TEST_STEP("Add @p tst_addr network address to @p tst1_if interface "
              "that is attached to the same subnetwork as @p iut_if1.");
    TEST_STEP("Add @p tst_addr network address to @p tst2_if interface "
              "that is attached to the same subnetwork as @p iut_if2 "
              "(unless it is on the same host as @p tst1_if).");

    TWO_IFS_ADD_TST_ADDRS(single_peer, tst_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    TEST_STEP("On IUT, assign @p iut_addr to both @p iut_if1 and "
              "@p iut_if2.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if1->if_name,
                                           iut_addr, -1, FALSE,
                                           &iut1_addr_hndl));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if2->if_name,
                                           iut_addr, -1, FALSE,
                                           &iut2_addr_hndl));

    INIT_TWO_IFS_MONITORS(tst_addr, af, rt_sock_type);

    TEST_STEP("IUT: ip route add @p tst_addr dev @p iut_if1 metric 1");
    CHECK_RC(tapi_cfg_add_route(pco_iut->ta, af,
                                te_sockaddr_get_netaddr(tst_addr),
                                route_prefix, NULL, iut_if1->if_name,
                                NULL, 0, 1, 0, 0, 0, 0, &rh1));

    TEST_STEP("IUT: ip route add @p tst_addr dev @p iut_if2 metric 2");
    CHECK_RC(tapi_cfg_add_route(pco_iut->ta, af,
                                te_sockaddr_get_netaddr(tst_addr),
                                route_prefix, NULL, iut_if2->if_name,
                                NULL, 0, 2, 0, 0, 0, 0, &rh2));


    TEST_STEP("Check that traffic goes via @p iut_if1:");
    TEST_SUBSTEP("TST1: ip route add @p iut_addr dev @p tst1_if");
    TEST_SUBSTEP("Create a socket of type @p rt_sock_type on IUT, "
                 "bind it to @p iut_addr, create its peer on TST1. "
                 "Check that packets sent from it to @p tst_addr go "
                 "via @p iut_if1. Close sockets.");
    TEST_SUBSTEP("TST1: ip route del @p iut_addr dev @p tst1_if");
    TWO_IFS_CHECK_ROUTE_PBR_GEN(TRUE, iut_addr, tst_addr,
                                -1, SOCKTS_ADDR_SPEC,
                                "Checking the first route");

    TEST_STEP("Down @p iut_if1.");
    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if1->if_name));
    if (iut_addr->sa_family == AF_INET6 && !keep_addr_on_down)
    {
        /*
         * Added IPv6 address will disappear after setting interface
         * down, if keep_addr_on_down is not turned on.
         */
        iut1_addr_hndl = CFG_HANDLE_INVALID;
    }
    down = TRUE;
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that traffic goes via @p iut_if2:");
    TEST_SUBSTEP("TST2: ip route add @p iut_addr dev @p tst2_if");
    TEST_SUBSTEP("Create a socket of type @p rt_sock_type on IUT, "
                 "bind it to @p iut_addr, create its peer on TST2. "
                 "Check that packets sent from it to @p tst_addr go "
                 "via @p iut_if2. Close sockets.");
    TEST_SUBSTEP("TST2: ip route del @p iut_addr dev @p tst2_if");
    TWO_IFS_CHECK_ROUTE_PBR_GEN(FALSE, iut_addr, tst_addr,
                                -1, SOCKTS_ADDR_SPEC,
                                "Checking the second route");

    TEST_STEP("Up @p iut_if1.");
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if1->if_name));
    down = FALSE;
    CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if1->if_name));

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

    TEST_STEP("IUT: ip route add @p tst_addr dev @p iut_if1 metric 1");
    CHECK_RC(tapi_cfg_add_route(pco_iut->ta, af,
                                te_sockaddr_get_netaddr(tst_addr),
                                route_prefix, NULL, iut_if1->if_name,
                                NULL, 0, 1, 0, 0, 0, 0, &rh1));

    TEST_STEP("Check that traffic goes via @p iut_if1:");
    TEST_SUBSTEP("TST1: ip route add @p iut_addr dev @p tst1_if");
    TEST_SUBSTEP("Create a socket of type @p rt_sock_type on IUT, "
                 "bind it to @p iut_addr, create its peer on TST1. "
                 "Check that packets sent from it to @p tst_addr go "
                 "via @p iut_if1. Close sockets.");
    TWO_IFS_CHECK_ROUTE_PBR_GEN(TRUE, iut_addr, tst_addr,
                                -1, SOCKTS_ADDR_SPEC,
                                "Checking the third route");

    TEST_SUCCESS;

cleanup:
    CLEANUP_TWO_IFS_MONITORS;

    if (old_keep_addr <= 0 && keep_addr_on_down)
    {
        CLEANUP_CHECK_RC(tapi_cfg_sys_set_int(
                                  pco_iut->ta, old_keep_addr, NULL,
                                  "net/ipv6/conf:%s/keep_addr_on_down",
                                  iut_if1->if_name));
    }

    if (down)
    {
        CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if1->if_name));
        CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if1->if_name));
    }

    if (iut1_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(iut1_addr_hndl, FALSE));
    if (iut2_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(iut2_addr_hndl, FALSE));
    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst1_addr_hndl, FALSE));
    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst2_addr_hndl, FALSE));

    if (rh1 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh1));
    if (rh2 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh2));

    TEST_END;
}
