/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Routing table
 * 
 * $Id$
 */

/** @page route-rt_prefix_vs_metric Priority of the route netmask and route metric
 *
 * @objective Check that the route netmask has higher priority than
 *            the route metric while making the routing decision.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on @p IUT
 * @param pco_tst1      PCO on @p TESTER1
 * @param pco_tst2      PCO on @p TESTER2
 * @param iut_if1       Network interface on @p IUT physically connected
 *                      with @p TESTER1
 * @param iut_if2       Network interface on @p IUT physically connected
 *                      with @p TESTER2
 * @param tst_if1       Tester network interface physically
 *                      connected with @p iut_if1
 * @param tst_if2       Tester network interface physically
 *                      connected with @p iut_if2
 * @param tst1_addr     Network address assigned on @p TESTER1 interface
 *                      that is on the same subnetwork as @p iut_if1
 * @param tst2_addr     Network address assigned on @p TESTER2 interface
 *                      that is on the same subnetwork as @p iut_if2
 * @param alien_addr    Some network address not assigned to any station
 *                      that takes part in the test
 * @param route_type    Type of the route to add (direct/indirect)
 * @param N             Default metric value
 * @param rt_sock_type  Type of sockets used in the test
 *
 * @note The test requires that @p TESTER1 and @p TESTER2 should be 
 *       on physically different stations.
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_prefix_vs_metric"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

int
main(int argc, char **argv)
{
    DECLARE_TWO_IFS_COMMON_PARAMS;

    route_type_t           route_type;
    int                    N;
    
    cfg_handle             tst1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             tst2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt1_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt2_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt3_hndl = CFG_HANDLE_INVALID;

    int                    af;
    rpc_socket_domain      domain;
    sockts_socket_type     rt_sock_type;

    DECLARE_TWO_IFS_MONITORS;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    TEST_GET_ROUTE_TYPE_PARAM(route_type);
    TEST_GET_INT_PARAM(N);
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    domain = rpc_socket_domain_by_addr(tst1_addr);

    af = addr_family_rpc2h(sockts_domain2family(domain));

    TEST_STEP("Add @p alien_addr network address to @p tst1_if interface.");
    TEST_STEP("Add @p alien_addr network address to @p tst2_if interface "
              "(unless it is on the same host as @p tst1_if).");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    TEST_STEP("Add route to @p alien_addr with metric equals to @c N and "
              "with netmask length equals to @c 24 via: "
              "- in case of @p route_type is direct: @p iut_if1; "
              "- in case of @p route_type is indirect: gateway @p tst1_addr.");
    TEST_STEP("Add route to @p alien_addr with metric equals to @c N / 2 "
              "(better than @c N metric) and with netmask length equals to "
              "@c 16 (worse netmask length) via: "
              "- in case of @p route_type is direct: @p iut_if2; "
              "- in case of @p route_type is indirect: gateway @p tst2_addr.");

    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_addr), 24,
            (route_type != DIRECT) ? te_sockaddr_get_netaddr(tst1_addr) : NULL,
            (route_type == DIRECT) ? iut_if1->if_name : NULL, NULL,
            0, N, 0, 0, 0, 0, &rt1_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' with metric "
                  "equals to %d and route prefix length %d", N, 24);
    }

    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_addr), 16,
            (route_type != DIRECT) ? te_sockaddr_get_netaddr(tst2_addr) : NULL,
            (route_type == DIRECT) ? iut_if2->if_name : NULL, NULL,
            0, N / 2, 0, 0, 0, 0, &rt2_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' with metric "
                  "equals to %d and route prefix length %d", N / 2, 16);
    }

    TWO_IFS_CNS_ROUTE(TRUE);

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that data sent to @p alien_addr from IUT goes via "
              "@p iut_if1.");

    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "The first check of the first route");

    CHECK_RC(cfg_touch_instance("/agent:%s/interface:%s/neigh_dynamic:",
                                pco_iut->ta, iut_if1->if_name));
    CFG_WAIT_CHANGES;

    TEST_STEP("Check once again to be sure that all works fine with "
              "ARP entry.");

    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "The second check of the first route");

    TEST_STEP("If @p route_type is direct, delete ARP entry for @p alien_addr "
              "on the interface @p iut_if1 of IUT host.");
    if (route_type == DIRECT)
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if1->if_name,
                                          alien_addr));

    TEST_STEP("Add route to @p alien_addr with metric equals to @c N * 2 "
              "(worse than @c N metric) and with netmask length equals to "
              "@c 28 (the best netmask length from three routes) via: "
              "- in case of @p route_type is direct: @p iut_if2; "
              "- in case of @p route_type is indirect: gateway @p tst2_addr.");

    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_addr), 28,
            (route_type != DIRECT) ? te_sockaddr_get_netaddr(tst2_addr) : NULL,
            (route_type == DIRECT) ? iut_if2->if_name : NULL, NULL,
            0, N * 2, 0, 0, 0, 0, &rt3_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' with metric "
                  "equals to %d and route prefix length %d", N * 2, 28);
    }

    TWO_IFS_CNS_ROUTE(FALSE);

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that data sent to @p alien_addr from IUT goes via "
              "@p iut_if2.");

    TWO_IFS_CHECK_ROUTE(FALSE, alien_addr,
                        "The first check of the second route");

    CHECK_RC(cfg_touch_instance("/agent:%s/interface:%s/neigh_dynamic:",
                                pco_iut->ta, iut_if2->if_name));
    CFG_WAIT_CHANGES;

    TEST_STEP("Check once again to be sure that all works fine with "
              "ARP entry.");

    TWO_IFS_CHECK_ROUTE(FALSE, alien_addr,
                        "The second check of the second route");

    TEST_SUCCESS;

cleanup:

    CLEANUP_TWO_IFS_MONITORS;

    if (rt3_hndl != CFG_HANDLE_INVALID && pco_iut != NULL)
        CLEANUP_CHECK_RC(tapi_cfg_del_route_tmp(pco_iut->ta, af, 
                             te_sockaddr_get_netaddr(alien_addr), 28,
                             (route_type != DIRECT) ?
                                 te_sockaddr_get_netaddr(tst2_addr) : NULL,
                             (route_type == DIRECT) ?
                                 iut_if2->if_name : NULL, NULL,
                             0, N * 2, 0, 0, 0, 0));
    if (rt2_hndl != CFG_HANDLE_INVALID && pco_iut != NULL)
        CLEANUP_CHECK_RC(tapi_cfg_del_route_tmp(pco_iut->ta, af, 
                             te_sockaddr_get_netaddr(alien_addr), 16,
                             (route_type != DIRECT) ?
                                 te_sockaddr_get_netaddr(tst2_addr) : NULL,
                             (route_type == DIRECT) ?
                                 iut_if2->if_name : NULL, NULL,
                             0, N / 2, 0, 0, 0, 0));
    if (rt1_hndl != CFG_HANDLE_INVALID && pco_iut != NULL)
        CLEANUP_CHECK_RC(tapi_cfg_del_route_tmp(pco_iut->ta, af, 
                             te_sockaddr_get_netaddr(alien_addr), 24,
                             (route_type != DIRECT) ?
                                 te_sockaddr_get_netaddr(tst1_addr) : NULL,
                             (route_type == DIRECT) ?
                                 iut_if1->if_name : NULL, NULL,
                             0, N, 0, 0, 0, 0));

    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst2_addr_hndl, FALSE);
    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst1_addr_hndl, FALSE);

    TWO_IFS_IP6_CLEANUP;
    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}

