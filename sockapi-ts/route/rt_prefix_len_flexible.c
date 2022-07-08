/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-rt_prefix_len_flexible Routing decision depends on route netmask
 *
 * @objective Check that netmask of the route is taken into account
 *            while making the routing decision.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on @p IUT
 * @param pco_tst1      PCO on @p TESTER1
 * @param pco_tst2      PCO on @p TESTER2
 * @param iut_if1       Network interface on @p IUT physically
 *                      connected with @p TESTER1
 * @param iut_if2       Network interface on @p IUT physically
 *                      connected with @p TESTER2
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
 * @note We avoid using too short prefixes, to avoid rewriting paths to
 *       important system services which may be available via the default
 *       route.  If the test really needs to test /1 routes, then it should
 *       be marked with CHANGE_DEFAULT_ROUTE tester requirement.
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_prefix_len_flexible"

#include "ts_route.h"

/** Maximum length of network address in bits */
#define MAX_ADDR_BITS 128

/** How many routes to create */
#define ROUTES_NUM  5

/** Minimum prefix length */
#define MIN_PREFIX_LEN 3

int
main(int argc, char *argv[])
{
    DECLARE_TWO_IFS_COMMON_PARAMS;

    route_type_t           route_type;

    cfg_handle             tst1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             tst2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt_hndls[ROUTES_NUM];

    int                    af;
    sockts_socket_type     rt_sock_type;

    const char              *cur_if_name = NULL;
    const struct sockaddr   *cur_gw = NULL;
    struct sockaddr_storage  fixed_alien_addr;

    int                    all_prefixes[MAX_ADDR_BITS + 1] = { 0, };
    int                    prefixes[ROUTES_NUM] = { 0, };
    int                    i;
    int                    count;
    size_t                 addr_bits;

    DECLARE_TWO_IFS_MONITORS;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    TEST_GET_ROUTE_TYPE_PARAM(route_type);
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    af = alien_addr->sa_family;

    /*
     * Choose a few prefix lengths randomly, add them to
     * @b prefixes array in ascending order.
     */

    addr_bits = te_netaddr_get_bitsize(af);
    if (ROUTES_NUM > addr_bits - MIN_PREFIX_LEN + 1)
    {
        TEST_FAIL("Not enough prefix lengths for %d routes",
                  ROUTES_NUM);
    }

    count = 0;
    do {
        i = rand_range(MIN_PREFIX_LEN, addr_bits);
        if (all_prefixes[i] == 1)
            continue;
        all_prefixes[i] = 1;
        count++;
    } while (count < ROUTES_NUM);

    count = 0;
    for (i = MIN_PREFIX_LEN; i <= (int)addr_bits; i++)
    {
        if (all_prefixes[i] == 1)
        {
            prefixes[count] = i;
            count++;
        }
    }
    assert(count == ROUTES_NUM);

    /*
     * Make first bit of alien address non-zero to prevent
     * default/no-default routes mixing:
     *    route 1.2.3.4 | 1 is equal to 0.0.0.0 | 1
     * and some OS prohibit such routes.
     */
    tapi_sockaddr_clone_exact(alien_addr, &fixed_alien_addr);
    if (af == AF_INET)
    {
        SIN(&fixed_alien_addr)->sin_addr.s_addr |= htonl(1 << 31);
    }
    else
    {
        SIN6(&fixed_alien_addr)->sin6_addr.s6_addr[0] |= (1 << 7);
        /* Make sure that resulting address will not be link-local */
        SIN6(&fixed_alien_addr)->sin6_addr.s6_addr[0] &= (~(1 << 6));
    }
    alien_addr = SA(&fixed_alien_addr);

    TEST_STEP("Add @p alien_addr network address to @p tst1_if interface.");
    TEST_STEP("Add @p alien_addr network address to @p tst2_if interface "
              "(unless it is on the same host as @p tst1_if).");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    for (i = 0; i < ROUTES_NUM; i++)
    {
        rt_hndls[i] = CFG_HANDLE_INVALID;
    }

    TEST_STEP("Create a few routes to @p alien_addr on IUT, each new one "
              "with a bigger (randomly chosen) prefix length.");

    for (i = 0; i < ROUTES_NUM; i++)
    {
        TEST_SUBSTEP("If @p route_type is @c DIRECT, for every new route "
                     "set device to be different from the previous route "
                     "(i.e. @p iut_if1 for the first route, @p iut_if2 for "
                     "the second route, @p iut_if1 for the third route, "
                     "etc.).");
        TEST_SUBSTEP("IF @p route_type is @c INDIRECT, for every new route "
                     "set gateway to be different from the previous route "
                     "(i.e. @p tst1_addr for the fist route, @p tst2_addr "
                     "for the second route, @p tst1_addr for the third "
                     "route, etc.).");

        if (i % 2 == 0)
        {
            cur_if_name = iut_if1->if_name;
            cur_gw = tst1_addr;
        }
        else
        {
            cur_if_name = iut_if2->if_name;
            cur_gw = tst2_addr;
        }

        /* Add route to 'alien_addr' on IUT */
        if (tapi_cfg_add_route(pco_iut->ta, af,
                te_sockaddr_get_netaddr(alien_addr), prefixes[i],
                (route_type != DIRECT) ?
                    te_sockaddr_get_netaddr(cur_gw) : NULL,
                (route_type == DIRECT) ? cur_if_name : NULL, NULL,
                0, 0, 0, 0, 0, 0, &rt_hndls[i]) != 0)
        {
            TEST_FAIL("Cannot add route to 'alien_addr' "
                      "with prefix %d", prefixes[i]);
        }
        CFG_WAIT_CHANGES;

        TEST_SUBSTEP("After creating a route check that data sent to "
                     "@p alien_addr goes via interface chosen according to "
                     "the last created route, as it has the longest "
                     "prefix.");
        TWO_IFS_CHECK_ROUTE((i % 2 == 0 ? TRUE : FALSE), alien_addr,
                            "Checking a route after adding it");
    }

    TEST_STEP("Now remove previously created routes one by one, starting "
              "from the last one. After each removal check that data sent "
              "to @p alien_addr goes via IUT interface chosen according to "
              "the remaining route with the longest prefix length.");

    for (i = ROUTES_NUM - 1; i >= 0; i--)
    {
        /* Delete route with the longest prefix */
        CHECK_RC(cfg_del_instance(rt_hndls[i], FALSE));
        rt_hndls[i] = CFG_HANDLE_INVALID;

        RING("Route with prefix length %d was deleted", prefixes[i]);
        CFG_WAIT_CHANGES;

        /* All the routes are removed */
        if (i == 0)
            break;

        TWO_IFS_CHECK_ROUTE(((i - 1) % 2 == 0 ? TRUE : FALSE), alien_addr,
                            "Checking remaining routes after removing "
                            "a route");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_TWO_IFS_MONITORS;

    if (rt_hndls != NULL)
    {
        for (i = 0; i < ROUTES_NUM; i++)
        {
            if (rt_hndls[i] != CFG_HANDLE_INVALID)
                cfg_del_instance(rt_hndls[i], FALSE);
        }
    }

    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst1_addr_hndl, FALSE);
    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(tst2_addr_hndl, FALSE);

    TWO_IFS_IP6_CLEANUP;

    TEST_END;
}
