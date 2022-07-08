/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-pbr_tos Policy based routing with TOS (ip rule tos)
 *
 * @objective Check that route rule is matched correctly in dependence
 *            on TOS.
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
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/pbr_tos"

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
    int     i;

    te_conf_ip_rule rule1;
    te_bool         rule1_added = FALSE;
    te_conf_ip_rule rule2;
    te_bool         rule2_added = FALSE;

    DECLARE_TWO_IFS_MONITORS;

    sockts_socket_type     rt_sock_type;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    GET_DOMAIN_AF_PREFIX(tst1_addr, domain, af, route_prefix);

    TEST_STEP("Add @p alien_addr on Tester interfaces.");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    TEST_STEP("For table @c SOCKTS_RT_TABLE_FOO, add a route via @p iut_if1 "
              "to @p alien_addr.");
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        route_prefix, NULL, iut_if1->if_name, NULL,
                        NULL, 0, 0, 0, 0, 0, 0, SOCKTS_RT_TABLE_FOO, &rh1));

    TEST_STEP("For table @c SOCKTS_RT_TABLE_BAR, add a route via @p iut_if2 "
              "to @p alien_addr.");
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        route_prefix, NULL, iut_if2->if_name, NULL,
                        NULL, 0, 0, 0, 0, 0, 0, SOCKTS_RT_TABLE_BAR, &rh2));

    TEST_STEP("In a loop iterating "
              "@b tos_val=([1; 7] << SOCKTS_IPTOS_OFFSET):");
    for (i = 1; i <= 7; i++)
    {
        te_bool        first_route;
        int            tos_val;
        int            table;

        te_conf_ip_rule *rule = NULL;
        te_bool         *rule_added = NULL;

        tos_val = SOCKTS_IPTOS_VAL(i);

        TEST_SUBSTEP("If iteration counter is uneven, select "
                     "@c SOCKTS_RT_TABLE_FOO for testing, otherwise select "
                     "@c SOCKTS_RT_TABLE_BAR.");
        if (i % 2 == 1)
        {
            rule = &rule1;
            first_route = TRUE;
            table = SOCKTS_RT_TABLE_FOO;
            rule_added = &rule1_added;
        }
        else
        {
            rule = &rule2;
            first_route = FALSE;
            table = SOCKTS_RT_TABLE_BAR;
            rule_added = &rule2_added;
        }

        TEST_STEP("If a rule was already added for that table, "
                  "remove it.");
        if (*rule_added)
        {
            CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                       rule->mask,
                                       rule));

            *rule_added = FALSE;
        }

        TEST_STEP("Add a rule for the chosen table with TOS = @b tos_val.");
        CHECK_RC(sockts_rt_add_tos_rule(pco_iut, rule, af, table, tos_val));
        *rule_added = TRUE;

        TWO_IFS_CNS_ROUTE(first_route);
        CFG_WAIT_CHANGES;

        TEST_SUBSTEP("Create a pair of sockets on IUT and Tester, set "
                     "@c IP_TOS (in case of IPv4) or @c IPV6_TCLASS "
                     "(in case of IPv6) to @b tos_val for them, establish "
                     "connection if required, send some data from IUT, "
                     "check that it goes via the route from the chosen "
                     "table.");
        sockts_rt_opt_tos = tos_val;
        TWO_IFS_CHECK_ROUTE(first_route, alien_addr,
                            "Checking a new route");
    }

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

    TWO_IFS_IP6_CLEANUP;
    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
