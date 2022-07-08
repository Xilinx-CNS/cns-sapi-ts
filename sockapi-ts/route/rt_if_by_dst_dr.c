/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Routing table
 * 
 * $Id$
 */

/** @page route-rt_if_by_dst_dr Determining outgoing interface based on destination address - case of direct route
 *
 * @objective Check that outgoing interface is correctly chosen based on
 *            destination address according to the information in the
 *            routing table - the case of direct route.
 *
 * @type conformance
 *
 * @reference @ref TCP-IP-ILLUSTRATED, section 9
 *
 * @param pco_iut       PCO on @p IUT
 * @param pco_tst1      PCO on @p TESTER1
 * @param pco_tst2      PCO on @p TESTER2
 * @param iut_if1       Network interface name on @p IUT physically
 *                      connected with @p TESTER1
 * @param iut_if2       Network interface name on @p IUT physically
 *                      connected with @p TESTER2
 * @param alien_addr    Some network address not assigned to any station
 *                      that takes part in the test
 * @param rt_sock_type  Type of sockets used in the test
 *
 * @note The test assumes that @p iut_if1 (@p iut_if2) has network address 
 *       that from the same subnetwork as the address assigned to the 
 *       interface of @p TESTER1 (@p TESTER2).
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_if_by_dst_dr"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

int 
main(int argc, char **argv)
{
    DECLARE_TWO_IFS_COMMON_PARAMS;

    cfg_handle             tst1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             tst2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt_hndl = CFG_HANDLE_INVALID;

    int                    af;
    int                    route_prefix;

    rpc_socket_domain       domain;
    sockts_socket_type      rt_sock_type;

    DECLARE_TWO_IFS_MONITORS;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    GET_DOMAIN_AF_PREFIX(tst1_addr, domain, af, route_prefix);

    TEST_STEP("Add @p alien_addr network address to @p tst1_if interface "
              "that is attached to the same subnetwork as @p iut_if1.");
    TEST_STEP("Add @p alien_addr network address to @p tst2_if interface "
              "that is attached to the same subnetwork as @p iut_if2 "
              "(unless it is on the same host as @p tst1_if).");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    TEST_STEP("Add direct route to @p alien_addr via @p iut_if1 interface "
              "on IUT.");
    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            NULL, iut_if1->if_name, NULL,
            0, 0, 0, 0, 0, 0, &rt_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' via 'iut_if1'");
    }

    TWO_IFS_CNS_ROUTE(TRUE);
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that data sent to @p alien_addr goes via @p iut_if1 "
              "interface.");
    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "The first check of the first route");

    CHECK_RC(cfg_touch_instance("/agent:%s/interface:%s/neigh_dynamic:",
                                pco_iut->ta, iut_if1->if_name));
    CFG_WAIT_CHANGES;

    TEST_STEP("Check the route via @p iut_if1 again (after ARP entry "
              "is added).");
    TWO_IFS_CHECK_ROUTE(TRUE, alien_addr,
                        "The second check of the first route");

    /* 
     * Delete neighbour entry for 'alien_addr' from 'iut_if1' since
     * it may be reused for 'iut_if2' by buggy implementation (like
     * Solaris 5.11).
     */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                      iut_if1->if_name, 
                                      alien_addr));

    TEST_STEP("Delete the previous route.");
    CHECK_RC(cfg_del_instance(rt_hndl, FALSE));
    rt_hndl = CFG_HANDLE_INVALID;

    TEST_STEP("Add direct route to @p alien_addr via @p iut_if2 interface "
              "on IUT.");
    if (tapi_cfg_add_route(pco_iut->ta, af, 
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            NULL, iut_if2->if_name, NULL,
            0, 0, 0, 0, 0, 0, &rt_hndl) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' via 'iut_if2'");
    }

    TWO_IFS_CNS_ROUTE(FALSE);
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that data sent to @p alien_addr goes via @p iut_if2 "
              "interface.");
    TWO_IFS_CHECK_ROUTE(FALSE, alien_addr,
                        "The first check of the second route");

    CHECK_RC(cfg_touch_instance("/agent:%s/interface:%s/neigh_dynamic:",
                                pco_iut->ta, iut_if2->if_name));
    CFG_WAIT_CHANGES;

    TEST_STEP("Check the route via @p iut_if2 again (after ARP entry is "
              "added).");
    TWO_IFS_CHECK_ROUTE(FALSE, alien_addr,
                        "The second check of the second route");

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if1->if_name,
                                              alien_addr));
    if (!single_peer)
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                                  iut_if2->if_name,
                                                  alien_addr));

    cfg_del_instance(rt_hndl, FALSE);

    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst1_addr_hndl, FALSE);
    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst2_addr_hndl, FALSE);

    CLEANUP_TWO_IFS_MONITORS;

    TWO_IFS_IP6_CLEANUP;
    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
