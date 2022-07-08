/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-pbr_prefix Prefix value in policy based routes
 *
 * @objective Check that the greater prefix value is set, the higher
 *            priority the route has.
 *
 * @type Conformance.
 *
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_two_ifs_variants_with_ipv6
 * @param rt_sock_type    Type of sockets used in the test
 *                        - @c udp
 *                        - @c udp_connect
 *                        - @c tcp_active
 *                        - @c tcp_passive
 * @param criterion       IP rule criterion
 *                        - @c from
 *                        - @c to
 *                        - @c tos
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/pbr_prefix"

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

    te_conf_ip_rule rule;
    te_bool         rule_added = FALSE;

    DECLARE_TWO_IFS_MONITORS;

    sockts_socket_type        rt_sock_type;
    sockts_rt_rule_criterion  criterion;
    int                       first_prefix;
    int                       second_prefix;
    int                       max_prefix;
    int                       min_prefix;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_RT_RULE_CRITERION_PARAM(criterion);

    GET_DOMAIN_AF_PREFIX(iut_addr1, domain, af, route_prefix);

    TEST_STEP("Choose @b first_prefix, @b second_prefix randomly so "
              "that @b second_prefix > @b first_prefix.");

    max_prefix = te_netaddr_get_bitsize(af);

    /* This is done to avoid Linux issue described in Bug 88891. */
    if (criterion == SOCKTS_RT_RULE_TOS &&
        af == AF_INET && SOCKTS_RT_CNS_TEST)
        min_prefix = 5;
    else
        min_prefix = 0;

    first_prefix = rand_range(min_prefix, max_prefix - 1);
    second_prefix = rand_range(first_prefix + 1, max_prefix);
    RING("first_prefix=%d second_prefix=%d", first_prefix, second_prefix);

    TEST_STEP("Set @b iut_addr to one of the IUT addresses passed in "
              "environment, choosing address on Solarflare interface "
              "if possible.");
    PBR_GET_IUT_ADDR;

    TEST_STEP("Add @p alien_addr on Tester interfaces.");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    TEST_STEP("IUT: Add new rule according to @p criterion to "
              "table @c SOCKTS_RT_TABLE_FOO.");
    sockts_rt_fill_add_rule(pco_iut, af, criterion,
                            SOCKTS_RT_TABLE_FOO,
                            iut_addr, route_prefix,
                            alien_addr, route_prefix,
                            SOCKTS_RT_DEF_TOS,
                            -1, &rule,
                            &rule_added);

    TEST_STEP("IUT: ip route add @p alien_addr / @b second_prefix "
              "dev @p iut_if2 table @c SOCKTS_RT_TABLE_FOO.");
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        second_prefix, NULL, iut_if2->if_name, NULL,
                        NULL, 0, 0, 0, 0, 0, 0,
                        SOCKTS_RT_TABLE_FOO, &rh1));

    TEST_STEP("IUT: ip route add @p alien_addr / @b first_prefix "
              "dev @p iut_if1 table @c SOCKTS_RT_TABLE_FOO.");
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        first_prefix, NULL, iut_if1->if_name, NULL,
                        NULL, 0, 0, 0, 0, 0, 0,
                        SOCKTS_RT_TABLE_FOO, &rh2));

    CFG_WAIT_CHANGES;

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    TEST_STEP("Check that traffic goes via @p iut_if2 - the route "
              "via it has greater prefix.");
    TWO_IFS_CHECK_ROUTE_PBR(FALSE, iut_addr, alien_addr,
                            SOCKTS_RT_DEF_TOS,
                            criterion, "Checking the second channel");

    TEST_STEP("IUT: ip route del @p alien_addr dev @p iut_if2 "
              "table @c SOCKTS_RT_TABLE_FOO.");
    CHECK_RC(tapi_cfg_del_route(&rh1));
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

    if (rule_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           rule.mask, &rule));

    TWO_IFS_IP6_CLEANUP;
    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
