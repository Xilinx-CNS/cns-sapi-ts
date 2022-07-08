/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-multipath_del_add_same_conns Rechecking existing connections after removing/restoring a path of a multipath route
 *
 * @objective Check that existing connections remain functional after
 *            removing/restoring a path in a multipath route.
 *
 *  @param env            Testing environment.
 *                        - @ref arg_types_env_triangle_iut_iut
 *                        - @ref arg_types_env_triangle_iut_iut_ipv6
 *  @param first_if       If @c TRUE, remove/add the path over the first IUT
 *                        interface, otherwise remove/add the path over the
 *                        second IUT interface.
 *  @param conns_num      Number of connections to check.
 *  @param pkts_per_conn  How many packets to send in both directions
 *                        over every connection.
 *  @param weight_remain  Weight of the path which remains not changed.
 *                        - @c 3
 *  @param weight_del     Weight of the path which is to be removed.
 *                        - @c 1
 *  @param weight_add     Weight of the path which is re-added.
 *                        - @c 6
 *  @param sock_type      Socket type used in testing.
 *                        - @c udp
 *                        - @c udp_notconn
 *                        - @c tcp_active
 *                        - @c tcp_passive
 * @param diff_addrs      If @c TRUE, each new Tester socket should be bound
 *                        to a new network address.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/multipath_del_add_same_conns"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "ts_route.h"
#include "ts_route_mpath.h"

int
main(int argc, char *argv[])
{
    MULTIPATH_COMMON_PARAMS_DECL;

    te_bool                 first_if;
    unsigned int            weight_remain;
    unsigned int            weight_del;
    unsigned int            weight_add;

    multipath_check_state cstate = MULTIPATH_CHECK_STATE_INIT;

    TEST_START;
    MULTIPATH_COMMON_PARAMS_GET;
    TEST_GET_BOOL_PARAM(first_if);
    TEST_GET_UINT_PARAM(weight_remain);
    TEST_GET_UINT_PARAM(weight_del);
    TEST_GET_UINT_PARAM(weight_add);

    MULTIPATH_COMMON_PARAMS_SET(&cstate);
    cstate.reuse_conns = TRUE;
    if (first_if)
    {
        cstate.weight1 = weight_del;
        cstate.weight2 = weight_remain;
    }
    else
    {
        cstate.weight1 = weight_remain;
        cstate.weight2 = weight_del;
    }

    TEST_STEP("On IUT create a multipath route to @p tst_remote_net with "
              "paths over @p iut1_if and over @p iut2_if. If @p first_if "
              "is @c TRUE, set @p weight_del for the first path and "
              "@p weight_remain for the second path; otherwise set weights "
              "in the opposite way. Create a corresponding route on "
              "Tester.");

    configure_multipath_routes(&cstate);
    CFG_WAIT_CHANGES;

    TEST_STEP("Establish @p conns_num connections between IUT and Tester, "
              "creating sockets of type @p sock_type. Check that data can "
              "be transmitted in both directions over the connections and "
              "number of connections using every path of the multipath "
              "route is proportional to its weight.");

    CHECK_RC(check_multipath_route(&cstate, "The initial route"));

    if (first_if)
        cstate.weight1 = 0;
    else
        cstate.weight2 = 0;

    TEST_STEP("If @p first_if is @c TRUE, remove the first path from "
              "the multipath route on IUT; otherwise remove the second "
              "path. Change the route on Tester accordingly.");

    configure_multipath_routes(&cstate);
    CFG_WAIT_CHANGES;

    TEST_STEP("Recheck connections created in the previous step: they "
              "still should allow to send data in both directions, and "
              "they should not send packets over the removed path.");

    CHECK_RC(check_multipath_route(&cstate,
                                   "The route after removing a path"));

    TEST_STEP("Add again the previously removed path on IUT, this time "
              "assigning @p weight_add to it. Change the route on Tester "
              "accordingly.");

    if (first_if)
        cstate.weight1 = weight_add;
    else
        cstate.weight2 = weight_add;

    configure_multipath_routes(&cstate);
    CFG_WAIT_CHANGES;

    TEST_STEP("Recheck the connections again: they still should allow "
              "to send data in both directions, and number of "
              "connections using every path of the multipath route "
              "should be proportional to its weight.");

    CHECK_RC(check_multipath_route(&cstate,
                                   "The route after restoring a path"));

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(multipath_check_state_clean(&cstate));

    TEST_END;
}
