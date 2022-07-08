/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Routing table
 * 
 * $Id$
 */

/** @page route-rt_if_by_dst_gw Determining outgoing interface based on destination address - case of indirect route
 *
 * @objective Check that outgoing interface is correctly chosen based on
 *            destination address according to the information in the
 *            routing table - the case of indirect route.
 *
 * @type conformance
 *
 * @reference @ref TCP-IP-ILLUSTRATED, section 9
 *
 * @param pco_iut       PCO on @p IUT
 * @param pco_tst1      PCO on @p TESTER1
 * @param pco_tst2      PCO on @p TESTER2
 * @param iut_if1       Network interface on @p IUT physically connected
 *                      with @p TESTER1
 * @param iut_if2       Network interface on @p IUT physically connected
 *                      with @p TESTER2
 * @param alien_addr    Some network address not assigned to any station
 *                      that takes part in the test
 * @param alien_gw      Some network address not assigned to any station
 *                      that takes part in the test
 * @param rt_sock_type  Type of sockets used in the test
 *
 * @note The test assumes that @p iut_if1 (@p iut_if2) has network address 
 *       that from the same subnetwork as the address assigned on the 
 *       interface of @p TESTER1 (@p TESTER2).
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_if_by_dst_gw"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"
#include "tapi_rpc_stdio.h"


int
main(int argc, char **argv)
{
    DECLARE_TWO_IFS_COMMON_PARAMS;

    cfg_handle tst1_addr_hndl[2] = {
        CFG_HANDLE_INVALID, CFG_HANDLE_INVALID
    };
    cfg_handle tst2_addr_hndl[2] = {
        CFG_HANDLE_INVALID, CFG_HANDLE_INVALID
    };
    cfg_handle             rt1_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt2_hndl = CFG_HANDLE_INVALID;

    int                    af;
    int                    route_prefix;
    int                    i;

    rpc_socket_domain     domain;
    sockts_socket_type    rt_sock_type;

    DECLARE_TWO_IFS_MONITORS;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    GET_DOMAIN_AF_PREFIX(tst1_addr, domain, af, route_prefix);

    TEST_STEP("Add @p alien_addr and @p alien_gw network addresses to "
              "@p tst1_if interface that is attached to the same "
              "subnetwork as @p iut_if1.");
    TEST_STEP("Add @p alien_addr and @p alien_gw network addresses to "
              "@p tst2_if interface that is attached to the same "
              "subnetwork as @p iut_if2 (unless it is on the same host "
              "as @p tst1_if).");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl[0], &tst2_addr_hndl[0]);
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_gw,
                          &tst1_addr_hndl[1], &tst2_addr_hndl[1]);

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    TEST_STEP("Add the following routes: "
              "- direct route to @p alien_gw via @p iut_if1 interface; "
              "- indirect route to @p alien_addr via @p alien_gw gateway.");

    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_gw), route_prefix,
            NULL, iut_if1->if_name, NULL,
            0, 0, 0, 0, 0, 0, &rt1_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_gw' via 'iut_if1'");
    }

    if (tapi_cfg_add_route(pco_iut->ta, af, 
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            te_sockaddr_get_netaddr(alien_gw), NULL, NULL,
            0, 0, 0, 0, 0, 0, &rt2_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' via 'alien_gw'");
    }

    TWO_IFS_CNS_ROUTE(TRUE);
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that data sent to @p alien_addr goes via "
              "the first IUT interface.");
    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "The first check of the first route");

    TEST_STEP("Check once more.");
    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "The second check of the first route");

    TEST_STEP("Delete direct route to @p alien_gw via @p iut_if1 interface.");
    CHECK_RC(tapi_cfg_del_route(&rt1_hndl));

    TEST_STEP("Add direct route to @p alien_gw via @p iut_if2 interface.");
    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_gw), route_prefix,
            NULL, iut_if2->if_name, NULL,
            0, 0, 0, 0, 0, 0, &rt1_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_gw' via 'iut_if2'");
    }
    CFG_WAIT_CHANGES;

    TEST_STEP("Check if changing underlying route leads to updating other "
              "routing information.");
    rc = sockts_rt_check_route(rt_sock_type, SOCKTS_RT_PCO_IUT_SOCK,
                               SOCKTS_RT_IUT_ADDR1,
                               pco_tst1, alien_addr,
                               SOCKTS_ADDR_NONE, FALSE, NULL);

    if (rc == 0)
    {
        TEST_STEP("If data still goes through the first interface:");

        CHECK_IF_ACCELERATED(&env, &iut_if1_monitor,
                             "The third check of the first route");

        TEST_SUBSTEP("Send/receive once more to be sure.");
        TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                            "The last check of the first route");

        TEST_SUBSTEP("Refresh indirect route by removing it and adding "
                     "again, because on some systems (including Linux) "
                     "it is not updated with updating underlying routes.");

        CHECK_RC(tapi_cfg_del_route(&rt2_hndl));

        if (tapi_cfg_add_route(pco_iut->ta, af, 
                te_sockaddr_get_netaddr(alien_addr), route_prefix,
                te_sockaddr_get_netaddr(alien_gw), NULL, NULL,
                0, 0, 0, 0, 0, 0, &rt2_hndl) != 0)
        {
            TEST_FAIL("Cannot add route to 'alien_addr' via 'alien_gw'");
        }
        CFG_WAIT_CHANGES;
    }
    else if (rt_error.err_code == SOCKTS_RT_ERR_NOT_ACCEPTED ||
             (rt_error.err_code == SOCKTS_RT_ERR_SEND_RECV &&
              rt_error.test_send_err == SOCKTS_TEST_SEND_NO_DATA))
    {
        RING_VERDICT("Changing underlying route resulted in updating "
                     "another route which uses it");

        CHECK_TWO_IFS_IN(&tst1_if_monitor, &tst2_if_monitor,
                         FALSE, TRUE,
                         "Check after changing underlying route");
        CHECK_IF_ACCELERATED(&env, &iut_if2_monitor,
                             "Check after changing underlying route");
    }
    else
    {
        TEST_FAIL("sockts_rt_check_route() reported "
                  "unexpected failure: %s",
                  sockts_rt_error2str(&rt_error));
    }

    TWO_IFS_CNS_ROUTE(FALSE);
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that now data goes via the second interface.");

    TWO_IFS_CHECK_ROUTE(FALSE, alien_addr,
                        "The first check of the second route");

    TEST_STEP("Check once more.");
    TWO_IFS_CHECK_ROUTE(FALSE, alien_addr,
                        "The second check of the second route");

    TEST_SUCCESS;

cleanup:

    tapi_cfg_del_route(&rt1_hndl);
    tapi_cfg_del_route(&rt2_hndl);

    for (i = 1; i >= 0; i--)
    {
        if (tst1_addr_hndl[i] != CFG_HANDLE_INVALID)
            cfg_del_instance(tst1_addr_hndl[i], FALSE);

        if (tst2_addr_hndl[i] != CFG_HANDLE_INVALID)
            cfg_del_instance(tst2_addr_hndl[i], FALSE);
    }

    CLEANUP_TWO_IFS_MONITORS;

    TWO_IFS_IP6_CLEANUP;
    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
