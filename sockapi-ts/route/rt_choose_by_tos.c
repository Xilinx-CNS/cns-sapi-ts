/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-rt_choose_by_tos IP packet routing using TOS (ip route tos)
 *
 * @objective Check that IP traffic classified with TOS is directed to
 *            correct channel according to @b tos value in defined
 *            routes.
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
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_choose_by_tos"

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

    TEST_STEP("In a loop iterating tos_val=([1; 7] << SOCKTS_IPTOS_OFFSET):");
    for (i = 1; i <= 7; i++)
    {
        const struct if_nameindex *iut_if = NULL;

        cfg_handle    *rh = NULL;
        te_bool        first_route;
        int            tos_val;

        tos_val = SOCKTS_IPTOS_VAL(i);

        TEST_SUBSTEP("If iteration counter is uneven, select "
                     "@p iut_if1 for testing, otherwise select "
                     "@p iut_if2.");
        if (i % 2 == 1)
        {
            rh = &rh1;
            iut_if = iut_if1;
            first_route = TRUE;
        }
        else
        {
            rh = &rh2;
            iut_if = iut_if2;
            first_route = FALSE;
        }

        TEST_SUBSTEP("If a route was already added on chosen interface, "
                     "remove it.");
        if (*rh != CFG_HANDLE_INVALID)
            CHECK_RC(tapi_cfg_del_route(rh));

        TEST_SUBSTEP("Add a new route with current tos_val via "
                     "the chosen interface.");
        CHECK_RC(tapi_cfg_add_route(
                            pco_iut->ta, af,
                            te_sockaddr_get_netaddr(alien_addr),
                            route_prefix, NULL, iut_if->if_name, NULL,
                            0, 0, tos_val, 0, 0, 0, rh));

        TWO_IFS_CNS_ROUTE(first_route);

        CFG_WAIT_CHANGES;

        TEST_SUBSTEP("Create a pair of sockets on IUT and Tester, "
                     "set IP_TOS to tos_val for sockets, "
                     "establish connection if required, send some data from IUT, "
                     "check that it goes via the route determined by current "
                     "IP_TOS value.");
        sockts_rt_opt_tos = tos_val;
        TWO_IFS_CHECK_ROUTE(first_route, alien_addr,
                            "Checking a new route");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_TWO_IFS_MONITORS;

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
