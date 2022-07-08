/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-pbr_rule_from Binding role in source based routing
 *
 * @objective Check that it is necessary to bind socket to a
 *            specific address to determine the route by source
 *            address.
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
 * @param bind_to         Type of address to bind IUT socket:
 *                        - @c none (do not bind; inapplicable for
 *                          passive TCP)
 *                        - @c specific
 *                        - @c wildcard
 *                        - @c multicast (only for UDP sockets)
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/pbr_rule_from"

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

    sockts_socket_type      rt_sock_type;
    sockts_addr_type        bind_to;

    struct sockaddr_storage wildcard_addr;

    te_bool     check_first = FALSE;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    SOCKTS_GET_ADDR_TYPE(bind_to);

    GET_DOMAIN_AF_PREFIX(tst1_addr, domain, af, route_prefix);

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

    TEST_STEP("IUT: ip rule add from @b iut_addr "
              "table @c SOCKTS_RT_TABLE_FOO.");
    sockts_rt_fill_add_rule(pco_iut, af, SOCKTS_RT_RULE_FROM,
                            SOCKTS_RT_TABLE_FOO,
                            iut_addr, route_prefix,
                            alien_addr, route_prefix,
                            -1, -1, &rule, &rule_added);

    TEST_STEP("IUT: ip route add default dev @p iut_if2 "
              "table @c SOCKTS_RT_TABLE_FOO.");
    tapi_sockaddr_clone_exact(alien_addr, &wildcard_addr);
    te_sockaddr_set_wildcard(SA(&wildcard_addr));
    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(SA(&wildcard_addr)),
                        0, NULL, iut_if2->if_name, NULL,
                        NULL, 0, 0, 0, 0, 0, 0,
                        SOCKTS_RT_TABLE_FOO, &rh2));

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    /* Wait while CSAPs really started (see ST-2252) */
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that traffic goes from IUT over @p iut_if2 in the "
              "following cases: (1) IUT socket is explicitly bound to "
              "@b iut_addr; (2) it is passive TCP connection "
              "establishment, connection request is received for "
              "@b iut_addr; (3) it is @c AF_INET socket not bound to "
              "unicast address, on which connect(@p alien_addr) is "
              "called, which binds it to address on @p iut_if1 "
              "(@p iut_addr1), while @b iut_addr == @p iut_addr1; "
              "(4) test is run with --ool=netns_calico.");

    if (SOCKTS_RT_CNS_TEST)
    {
        check_first = FALSE;
    }
    else if (af == AF_INET)
    {
        if (bind_to == SOCKTS_ADDR_SPEC ||
            rt_sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL ||
            ((rt_sock_type == SOCKTS_SOCK_TCP_ACTIVE ||
              rt_sock_type == SOCKTS_SOCK_UDP) &&
             iut_addr == iut_addr1))
            check_first = FALSE;
        else
            check_first = TRUE;
    }
    else
    {
        TEST_SUBSTEP("Note that (3) does not work for IPv6 for unknown "
                     "reason, traffic continues to be sent over the "
                     "first interface despite the IP rule.");

        if (bind_to == SOCKTS_ADDR_SPEC ||
            rt_sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL)
            check_first = FALSE;
        else
            check_first = TRUE;
    }

    TWO_IFS_CHECK_ROUTE_PBR_GEN(check_first, iut_addr, alien_addr,
                                -1, bind_to, NULL);

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
