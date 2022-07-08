/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Routing table
 * 
 * $Id$
 */

/** @page route-rt_metric Routing decision depends on route metric
 *
 * @objective Check that metric of the route is taken into account 
 *            while making the routing decision.
 *            The smaller the metric the better the route.
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
 * @param rt_sock_type  Type of sockets used in the test
 *
 * @note The test requires that @p TESTER1 and @p TESTER2 should be 
 *       on physically different stations.
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_metric"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

/*
 * Linux allows creating two routes with the same DST/PREFIX GW
 * but with different metric, so that test was initially written
 * to test this assumption.
 * Currently TE does not allow creating such routes, so that a part
 * of test can't be run with current version of TE.
 *
 * At least such "strange" feature is not supported on Windows.
 */
#undef METRIC_IS_ROUTE_KEY_PART
#undef L5LINUX_STRONG_DEBUGING_ONLY

int
main(int argc, char **argv)
{
    DECLARE_TWO_IFS_COMMON_PARAMS;

    route_type_t           route_type;

    cfg_handle             tst1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             tst2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt1_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt2_hndl = CFG_HANDLE_INVALID;
#if METRIC_IS_ROUTE_KEY_PART
    cfg_handle             rt3_hndl = CFG_HANDLE_INVALID;
#endif

    int                    af;
    int                    route_prefix;
    rpc_socket_domain      domain;
    sockts_socket_type     rt_sock_type;

    DECLARE_TWO_IFS_MONITORS;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    TEST_GET_ROUTE_TYPE_PARAM(route_type);
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    GET_DOMAIN_AF_PREFIX(tst1_addr, domain, af, route_prefix);

    TEST_STEP("Add @p alien_addr network address to @p tst1_if interface.");
    TEST_STEP("Add @p alien_addr network address to @p tst2_if interface "
              "(unless it is on the same host as @p tst1_if).");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    TEST_STEP("Add a route to @p alien_addr with metric equals to @c 3 via: "
              "- in case of @p route_type is direct: @p iut_if1; "
              "- in case of @p route_type is indirect: gateway @p tst1_addr.");
    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            (route_type != DIRECT) ? te_sockaddr_get_netaddr(tst1_addr) : NULL,
            (route_type == DIRECT) ? iut_if1->if_name : NULL, NULL,
            0, 3, 0, 0, 0, 0, &rt1_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' with "
                  "metric equals to 3");
    }

    TWO_IFS_CNS_ROUTE(TRUE);

    CFG_WAIT_CHANGES;
#if L5LINUX_STRONG_DEBUGING_ONLY
    rpc_system(pco_iut, "ip route");
    rpc_system(pco_iut, "ip neigh");
    rpc_system(pco_iut, "cat /proc/driver/onload_cplane/mib-fwd");
    rpc_system(pco_iut, "cat /proc/driver/onload_cplane/mib-mac");
#endif

    TEST_STEP("Check that data sent to @p alien_addr from IUT goes "
              "via @p iut_if1 interface.");
    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "Check of the first route");

#if L5LINUX_STRONG_DEBUGING_ONLY
    rpc_system(pco_iut, "ip route");
    rpc_system(pco_iut, "ip neigh");
    rpc_system(pco_iut, "cat /proc/driver/onload_cplane/mib-fwd");
    rpc_system(pco_iut, "cat /proc/driver/onload_cplane/mib-mac");
#endif

    TEST_STEP("Add a route to @p alien_addr with metric equals to @c 2 via: "
              "- in case of @p route_type is direct: @p iut_if2; "
              "- in case of @p route_type is indirect: gateway @p tst2_addr.");
    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            (route_type != DIRECT) ? te_sockaddr_get_netaddr(tst2_addr) : NULL,
            (route_type == DIRECT) ? iut_if2->if_name : NULL, NULL,
            0, 2, 0, 0, 0, 0, &rt2_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' with "
                  "metric equals to 2");
    }

    TWO_IFS_CNS_ROUTE(FALSE);

    CFG_WAIT_CHANGES;
#if L5LINUX_STRONG_DEBUGING_ONLY
    rpc_system(pco_iut, "ip route");
    rpc_system(pco_iut, "ip neigh");
    rpc_system(pco_iut, "cat /proc/driver/onload_cplane/mib-fwd");
    rpc_system(pco_iut, "cat /proc/driver/onload_cplane/mib-mac");
#endif

    TEST_STEP("Check that data sent to @p alien_addr from IUT goes "
              "via @p iut_if2 interface.");
    TWO_IFS_CHECK_ROUTE(FALSE, alien_addr,
                        "Check of the second route");

#if L5LINUX_STRONG_DEBUGING_ONLY
    rpc_system(pco_iut, "ip route");
    rpc_system(pco_iut, "ip neigh");
    rpc_system(pco_iut, "cat /proc/driver/onload_cplane/mib-fwd");
    rpc_system(pco_iut, "cat /proc/driver/onload_cplane/mib-mac");
#endif

#if METRIC_IS_ROUTE_KEY_PART

    TEST_STEP("Add route to @p alien_addr with metric equals to @c 1 via: "
              "- in case of @p route_type is direct: @p iut_if1; "
              "- in case of @p route_type is indirect: gateway @p tst1_addr.");
    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            (route_type != DIRECT) ? te_sockaddr_get_netaddr(tst1_addr) : NULL,
            (route_type == DIRECT) ? iut_if1->if_name : NULL,
            0, 1, 0, 0, 0, &rt3_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' with "
                  "metric equals to 1");
    }

    TWO_IFS_CNS_ROUTE(TRUE);

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that data sent to @p alien_addr from IUT goes "
              "via @p iut_if1 interface.");
    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "Check of the third route");

    TEST_STEP("Delete the last added route (route with metric 1).");
    CHECK_RC(cfg_del_instance(rt3_hndl, FALSE));
    rt3_hndl = CFG_HANDLE_INVALID;

    TWO_IFS_CNS_ROUTE(FALSE);

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that data sent to @p alien_addr from IUT goes "
              "via @p iut_if2 interface.");
    TWO_IFS_CHECK_ROUTE(FALSE, alien_addr,
                        "Check after removing the third route");

#endif /* METRIC_IS_ROUTE_KEY_PART */

    TEST_STEP("Delete the second route (with metric 2).");
    CHECK_RC(cfg_del_instance(rt2_hndl, FALSE));
    rt2_hndl = CFG_HANDLE_INVALID;
    TWO_IFS_CNS_ROUTE(TRUE);
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that data sent to @p alien_addr from IUT goes "
              "via @p iut_if1 interface.");
    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "Check after removing the second route");

    TEST_SUCCESS;

cleanup:

#if METRIC_IS_ROUTE_KEY_PART
    tapi_cfg_del_route(&rt3_hndl);
#endif
    tapi_cfg_del_route(&rt2_hndl);
    tapi_cfg_del_route(&rt1_hndl);

    CLEANUP_TWO_IFS_MONITORS;

    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst1_addr_hndl, FALSE);
    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst2_addr_hndl, FALSE);

    TWO_IFS_IP6_CLEANUP;
    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
