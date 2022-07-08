/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-pbr_tos_two_rules Using of two TOS to split traffic
 *
 * @objective Use two rules with different TOS to match the same
 *            route table, but split traffic to two interfaces
 *            there using TOS.
 *
 * @type Conformance.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst1      PCO on Tester1
 * @param pco_tst2      PCO on Tester2
 * @param iut_addr      Address on IUT
 * @param alien_addr    Common address for both Testers
 * @param iut_if1       Interface on IUT connected to Tester1
 * @param iut_if2       Interface on IUT connected to Tester2
 * @param tst1_if       Interface on Tester1
 * @param tst2_if       Interface on Tester2
 * @param tst1_addr     Address of Tester1
 * @param tst2_addr     Address of Tester2
 * @param rt_sock_type  Type of sockets used in the test
 * @param first_tos     The first TOS value.
 * @param second_tos    The second TOS value.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/pbr_tos_two_rules"

#include "sockapi-test.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

int
main(int argc, char *argv[])
{
    DECLARE_TWO_IFS_COMMON_PARAMS;

    cfg_handle                 tst1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle                 tst2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle                 rh1 = CFG_HANDLE_INVALID;
    cfg_handle                 rh2 = CFG_HANDLE_INVALID;

    int     af;
    int     route_prefix;
    int     domain;

    te_conf_ip_rule rule1;
    te_bool         rule1_added = FALSE;
    te_conf_ip_rule rule2;
    te_bool         rule2_added = FALSE;

    DECLARE_TWO_IFS_MONITORS;

    sockts_socket_type      rt_sock_type;
    int                     first_tos;
    int                     second_tos;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_INT_PARAM(first_tos);
    TEST_GET_INT_PARAM(second_tos);

    GET_DOMAIN_AF_PREFIX(tst1_addr, domain, af, route_prefix);

    TEST_STEP("Add @p alien_addr on Tester interfaces.");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    TEST_STEP("IUT: ip rule add tos @p first_tos table @c SOCKTS_RT_TABLE_FOO.");
    CHECK_RC(sockts_rt_add_tos_rule(pco_iut, &rule1, af,
                                    SOCKTS_RT_TABLE_FOO, first_tos));
    rule1_added = TRUE;

    TEST_STEP("IUT: ip rule add tos @p second_tos table @c SOCKTS_RT_TABLE_FOO.");
    CHECK_RC(sockts_rt_add_tos_rule(pco_iut, &rule2, af,
                                    SOCKTS_RT_TABLE_FOO, second_tos));
    rule2_added = TRUE;

    TEST_STEP("IUT: ip route add @p alien_addr dev @p iut_if1 tos @p first_tos "
              "table @c SOCKS_RT_TABLE_FOO.");
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        route_prefix, NULL, iut_if1->if_name, NULL,
                        NULL, 0, 0, first_tos, 0, 0, 0,
                        SOCKTS_RT_TABLE_FOO, &rh1));

    TEST_STEP("IUT: ip route add @p alien_addr dev @p iut_if2 tos @p second_tos "
              "table @c SOCKS_RT_TABLE_FOO.");
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        route_prefix, NULL, iut_if2->if_name, NULL,
                        NULL, 0, 0, second_tos, 0, 0, 0,
                        SOCKTS_RT_TABLE_FOO, &rh2));

    TWO_IFS_CNS_ROUTE(TRUE);

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that when IP_TOS = @p first_tos, traffic goes via the first "
              "IUT interface.");
    sockts_rt_opt_tos = first_tos;
    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "Checking the first route");

    if (SOCKTS_RT_CNS_TEST)
    {
        TWO_IFS_CNS_ROUTE(FALSE);
        CFG_WAIT_CHANGES;
    }

    TEST_STEP("Check that when IP_TOS = @p second_tos, traffic goes via the second "
              "IUT interface.");
    sockts_rt_opt_tos = second_tos;
    TWO_IFS_CHECK_ROUTE(FALSE, alien_addr,
                        "Checking the second route");

    TEST_SUCCESS;

cleanup:

    CLEANUP_TWO_IFS_MONITORS;

    if (rule1_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           rule1.mask, &rule1));

    if (rule2_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           rule2.mask, &rule2));

    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst1_addr_hndl, FALSE));
    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst2_addr_hndl, FALSE));

    if (rh1 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh1));
    if (rh2 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh2));

    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
