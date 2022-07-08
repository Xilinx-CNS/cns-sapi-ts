/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-pbr_rule_combined Combining two rule criteria
 *
 * @objective Check that a rule can be matched using a few criteria.
 *
 * @type Conformance.
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_two_ifs_variants_with_ipv6
 * @param rt_sock_type    Type of sockets used in the test
 *                        - @c udp
 *                        - @c udp_connect
 *                        - @c tcp_active
 *                        - @c tcp_passive
 * @param cr_first        The first IP rule criterion to make
 *                        the decision, value is set in couple with
 *                        @p cr_second
 *                        - @c from
 *                        - @c to
 *                        - @c tos
 * @param cr_second       The second IP rule criterion to make the
 *                        decision, value is set in couple with
 *                        @p cr_first
 *                        - @c from
 *                        - @c to
 *                        - @c tos
 * @param match           Whether both criteria match tested channel
 *                        - @c correct: Both criteria match the channel
 *                        - @c incorrect: The second criterion does not
 *                                        match the channel
 *                        - @c not: Both criteria match the channel, but
 *                                  also rule inversion flag is set.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/pbr_rule_combined"

#include "sockapi-test.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

/**
 * Possible types of correspondence between
 * two rule criteria and outgoing traffic.
 */
typedef enum {
    SOCKTS_RT_MATCH_CORRECT,    /**< Both criteria match. */
    SOCKTS_RT_MATCH_INCORRECT,  /**< One of criteria does not match. */
    SOCKTS_RT_MATCH_NOT,        /**< Both criteria match, but
                                     rule inversion flag is set. */
} sockts_rt_match_type;

/**  Mapping of sockts_rt_match_type values to strings. */
#define SOCKTS_RT_MATCH_TYPES \
    { "correct",          SOCKTS_RT_MATCH_CORRECT },    \
    { "incorrect",        SOCKTS_RT_MATCH_INCORRECT },  \
    { "not",              SOCKTS_RT_MATCH_NOT }

/** Macro for getting value of match test argument. */
#define SOCKTS_GET_RT_MATCH_TYPE(_match_type) \
    TEST_GET_ENUM_PARAM(_match_type, SOCKTS_RT_MATCH_TYPES)

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

    const struct sockaddr *second_src_addr = NULL;
    const struct sockaddr *second_dst_addr = NULL;
    int                    second_tos = -1;
    int                    tos = -1;

    te_bool check_first = FALSE;

    sockts_socket_type        rt_sock_type;
    sockts_rt_rule_criterion  cr_first;
    sockts_rt_rule_criterion  cr_second;
    sockts_rt_match_type      match;
    const struct sockaddr *iut_if1_hwaddr = NULL;
    const struct sockaddr *iut_if2_hwaddr = NULL;
    const struct sockaddr *tst1_hwaddr = NULL;
    const struct sockaddr *tst2_hwaddr = NULL;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_RT_RULE_CRITERION_PARAM(cr_first);
    TEST_GET_RT_RULE_CRITERION_PARAM(cr_second);
    SOCKTS_GET_RT_MATCH_TYPE(match);
    TEST_GET_LINK_ADDR(iut_if1_hwaddr);
    TEST_GET_LINK_ADDR(iut_if2_hwaddr);
    TEST_GET_LINK_ADDR(tst1_hwaddr);
    TEST_GET_LINK_ADDR(tst2_hwaddr);

    GET_DOMAIN_AF_PREFIX(iut_addr1, domain, af, route_prefix);

    TEST_STEP("Set @b iut_addr to either @p iut_addr1 or @p iut_addr2, "
              "choosing address on Solarflare interface if possible.");
    PBR_GET_IUT_ADDR;

    TEST_STEP("Add @p alien_addr on Tester interfaces.");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    TEST_STEP("IUT: ip route add @p alien_addr dev @p iut_if1.");
    CHECK_RC(tapi_cfg_add_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        route_prefix, NULL, iut_if1->if_name,
                        NULL, 0, 0, 0, 0, 0, 0,
                        &rh1));

    TEST_STEP("IUT: Add a rule with two criteria according to @p cr_first, "
              "@p cr_second and @p match.");

    te_conf_ip_rule_init(&rule);

    sockts_rt_fill_rule(&rule, iut_addr->sa_family, cr_first,
                        SOCKTS_RT_TABLE_FOO,
                        iut_addr, route_prefix,
                        alien_addr, route_prefix,
                        SOCKTS_RT_DEF_TOS, -1);

    if (match == SOCKTS_RT_MATCH_INCORRECT)
    {
        if (iut_addr == iut_addr1)
            second_src_addr = iut_addr2;
        else
            second_src_addr = iut_addr1;

        second_dst_addr = tst2_addr;
        second_tos = SOCKTS_RT_ANOTHER_TOS;
    }
    else
    {
        second_src_addr = iut_addr;
        second_dst_addr = alien_addr;
        second_tos = SOCKTS_RT_DEF_TOS;
    }

    sockts_rt_fill_rule(&rule, second_src_addr->sa_family, cr_second,
                        SOCKTS_RT_TABLE_FOO,
                        second_src_addr, route_prefix,
                        second_dst_addr, route_prefix,
                        second_tos, -1);

    if (match == SOCKTS_RT_MATCH_NOT)
        te_conf_ip_rule_set_invert(&rule, TRUE);

    CHECK_RC(tapi_cfg_add_rule(pco_iut->ta, af, &rule));
    rule_added = TRUE;

   TEST_STEP("IUT: ip route add @p alien_addr dev @p iut_if2 "
             "table @c SOCKTS_RT_TABLE_FOO.");
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(alien_addr),
                        route_prefix, NULL, iut_if2->if_name, NULL,
                        NULL, 0, 0, 0, 0, 0, 0,
                        SOCKTS_RT_TABLE_FOO, &rh2));

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    /* Wait while CSAPs really started (see ST-2252) */
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that traffic goes to the second channel if @p match "
              "is @c correct, otherwise traffic goes to the first channel.");

    if (match == SOCKTS_RT_MATCH_CORRECT)
        check_first = FALSE;
    else
        check_first = TRUE;

    if (cr_first == SOCKTS_RT_RULE_TOS ||
        cr_second == SOCKTS_RT_RULE_TOS)
        tos = SOCKTS_RT_DEF_TOS;

    /*
     * Add entries to ARP table for alien address on IUT and Tester to avoid
     * ARP-related issues on some hosts. See ST-2509.
     */
    if (check_first)
    {
        CHECK_RC(tapi_update_arp(pco_tst1->ta, tst1_if->if_name, NULL, NULL,
                                 iut_addr, CVT_HW_ADDR(iut_if1_hwaddr), TRUE));
        CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if1->if_name, NULL, NULL,
                                 alien_addr, CVT_HW_ADDR(tst1_hwaddr), TRUE));
    }
    else
    {
        CHECK_RC(tapi_update_arp(pco_tst2->ta, tst2_if->if_name, NULL, NULL,
                                 iut_addr, CVT_HW_ADDR(iut_if2_hwaddr), TRUE));
        CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if2->if_name, NULL, NULL,
                                 alien_addr, CVT_HW_ADDR(tst2_hwaddr), TRUE));
    }

    TWO_IFS_CHECK_ROUTE_PBR_GEN(check_first, iut_addr, alien_addr,
                                tos, SOCKTS_ADDR_SPEC,
                                NULL);

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
