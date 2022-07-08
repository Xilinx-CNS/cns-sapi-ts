/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-pbr_rules_order Route rules order
 *
 * @objective Check that the choice of route depends on rules order.
 *
 * @type Conformance.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_two_ifs_variants_with_ipv6
 * @param rt_sock_type  Type of sockets used in the test:
 *                      - @c udp
 *                      - @c udp_notconn
 *                      - @c tcp_active
 *                      - @c tcp_passive
 * @param criterion     IP rule criterion:
 *                      - @c from
 *                      - @c to
 *                      - @c tos
 * @param set_pref      If @c TRUE, set IP rule preference value
 *                      explicitly.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/pbr_rules_order"

#include "sockapi-test.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

int
main(int argc, char *argv[])
{
    DECLARE_TWO_IFS_COMMON_PARAMS_PBR;

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

    sockts_socket_type        rt_sock_type;
    sockts_rt_rule_criterion  criterion;
    te_bool                   set_pref;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_RT_RULE_CRITERION_PARAM(criterion);
    TEST_GET_BOOL_PARAM(set_pref);

    GET_DOMAIN_AF_PREFIX(tst1_addr, domain, af, route_prefix);

    TEST_STEP("Set @b iut_addr to either @p iut_addr1 or @p iut_addr2, "
              "choosing address on Solarflare interface if possible.");
    PBR_GET_IUT_ADDR;

    TEST_STEP("Add @p alien_addr on Tester interfaces.");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    if (set_pref)
    {
        TEST_STEP("If @p set_pref is @c TRUE: "
                  "- IUT: Add a new rule according to @p criterion with "
                  "pref @c 1000 to table @c SOCKTS_RT_TABLE_BAR; "
                  "- IUT: Add a new rule according to @p criterion with "
                  "pref @c 1001 to table @c SOCKTS_RT_TABLE_FOO.");

        sockts_rt_fill_add_rule(pco_iut, af, criterion,
                                SOCKTS_RT_TABLE_BAR,
                                iut_addr, route_prefix,
                                alien_addr, route_prefix,
                                SOCKTS_RT_DEF_TOS,
                                1000, &rule1,
                                &rule1_added);

        sockts_rt_fill_add_rule(pco_iut, af, criterion,
                                SOCKTS_RT_TABLE_FOO,
                                iut_addr, route_prefix,
                                alien_addr, route_prefix,
                                SOCKTS_RT_DEF_TOS,
                                1001, &rule2,
                                &rule2_added);
    }
    else
    {
        TEST_STEP("If @p set_pref is @c FALSE: "
                  "- IUT: Add a new rule according to @p criterion "
                  "to table @c SOCKTS_RT_TABLE_FOO; "
                  "- IUT: Add a new rule according to @p criterion "
                  "to table @c SOCKTS_RT_TABLE_BAR.");

        sockts_rt_fill_add_rule(pco_iut, af, criterion,
                                SOCKTS_RT_TABLE_FOO,
                                iut_addr, route_prefix,
                                alien_addr, route_prefix,
                                SOCKTS_RT_DEF_TOS,
                                -1, &rule2,
                                &rule2_added);

        sockts_rt_fill_add_rule(pco_iut, af, criterion,
                                SOCKTS_RT_TABLE_BAR,
                                iut_addr, route_prefix,
                                alien_addr, route_prefix,
                                SOCKTS_RT_DEF_TOS,
                                -1, &rule1,
                                &rule1_added);
    }

    TEST_STEP("IUT: ip route add @p alien_addr dev @p iut_if1 "
              "table @c SOCKTS_RT_TABLE_FOO.");
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        route_prefix, NULL, iut_if1->if_name, NULL,
                        NULL, 0, 0, 0, 0, 0, 0,
                        SOCKTS_RT_TABLE_FOO, &rh1));

    TEST_STEP("IUT: ip route add @p alien_addr dev @p iut_if2 "
              "table @c SOCKTS_RT_TABLE_BAR.");
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        route_prefix, NULL, iut_if2->if_name, NULL,
                        NULL, 0, 0, 0, 0, 0, 0,
                        SOCKTS_RT_TABLE_BAR, &rh2));

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that traffic goes via @p iut_if2.");
    TWO_IFS_CHECK_ROUTE_PBR(FALSE, iut_addr, alien_addr,
                            SOCKTS_RT_DEF_TOS,
                            criterion, "Checking the second channel");

    TEST_STEP("IUT: Delete the rule for table @c SOCKTS_RT_TABLE_FOO.");
    CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                       rule2.mask, &rule2));
    rule2_added = FALSE;

    if (set_pref)
    {
        TEST_STEP("If @p set_pref is @c TRUE, add a rule according to "
                  "@p criterion with pref @c 999 to table "
                  "@c SOCKTS_RT_TABLE_FOO.");
        sockts_rt_fill_add_rule(pco_iut, af, criterion,
                                SOCKTS_RT_TABLE_FOO,
                                iut_addr, route_prefix,
                                alien_addr, route_prefix,
                                SOCKTS_RT_DEF_TOS,
                                999, &rule2,
                                &rule2_added);
    }
    else
    {
        TEST_STEP("If @p set_pref is @c FALSE, add the same rule as the "
                  "previously removed one to table @c SOCKTS_RT_TABLE_FOO.");
        sockts_rt_fill_add_rule(pco_iut, af, criterion,
                                SOCKTS_RT_TABLE_FOO,
                                iut_addr, route_prefix,
                                alien_addr, route_prefix,
                                SOCKTS_RT_DEF_TOS,
                                -1, &rule2,
                                &rule2_added);
    }

    CFG_WAIT_CHANGES;

    TEST_STEP("Check that traffic goes via @p iut_if1.");
    TWO_IFS_CHECK_ROUTE_PBR(TRUE, iut_addr, alien_addr,
                            SOCKTS_RT_DEF_TOS,
                            criterion, "Checking the first channel");

    TEST_SUCCESS;

cleanup:

    CLEANUP_TWO_IFS_MONITORS;

    if (rh1 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh1));
    if (rh2 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh2));
    if (rh_tester_fix != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh_tester_fix));

    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst1_addr_hndl, FALSE));
    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst2_addr_hndl, FALSE));

    if (rule1_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           rule1.mask, &rule1));
    if (rule2_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           rule2.mask, &rule2));

    TWO_IFS_IP6_CLEANUP;
    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
