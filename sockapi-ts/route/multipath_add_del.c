/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-multipath_add_del Adding/removing paths of a multipath route
 *
 * @objective Check what happens when a path is added or removed in
 *            a multipath route.
 *
 *  @param env            Testing environment.
 *                        - @ref arg_types_env_triangle_iut_iut
 *                        - @ref arg_types_env_triangle_iut_iut_ipv6
 *  @param change         How to change a route:
 *                        - @c add (a new path);
 *                        - @c remove (an existing path).
 *  @param first_if       If @c TRUE, add/remove the path over the first IUT
 *                        interface, otherwise add/remove the path over the
 *                        second IUT interface.
 *  @param conns_num      Number of connections to check.
 *  @param pkts_per_conn  How many packets to send in both directions
 *                        over every connection.
 *  @param weight1        Weight of the first path.
 *                        - @c 1
 *  @param weight2        Weight of the second path.
 *                        - @c 1
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

#define TE_TEST_NAME "route/multipath_add_del"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "ts_route.h"
#include "ts_route_mpath.h"

/** Changes of a route to check */
enum {
    CHANGE_ADD = 1,   /**< Add a new nexthop */
    CHANGE_REMOVE,    /**< Remove an existing nexthop */
};

/** List of values for "change" parameter */
#define CHANGE_ACTIONS \
    { "add", CHANGE_ADD },        \
    { "remove", CHANGE_REMOVE }

int
main(int argc, char *argv[])
{
    MULTIPATH_COMMON_PARAMS_DECL;

    int                     change;
    te_bool                 first_if;
    unsigned int            weight1;
    unsigned int            weight2;

    multipath_check_state cstate = MULTIPATH_CHECK_STATE_INIT;

    TEST_START;
    MULTIPATH_COMMON_PARAMS_GET;
    TEST_GET_ENUM_PARAM(change, CHANGE_ACTIONS);
    TEST_GET_BOOL_PARAM(first_if);
    TEST_GET_UINT_PARAM(weight1);
    TEST_GET_UINT_PARAM(weight2);

    MULTIPATH_COMMON_PARAMS_SET(&cstate);
    cstate.weight1 = weight1;
    cstate.weight2 = weight2;
    if (change == CHANGE_ADD)
    {
        if (first_if)
            cstate.weight1 = 0;
        else
            cstate.weight2 = 0;
    }

    TEST_STEP("If @p change is @c add, create a single-path route to "
              "@p tst_remote_net over IUT interface chosen according to "
              "@p first_if (if @p first_if is @c TRUE, use the second "
              "interface, otherwise use the first one). If @p change is "
              "@c remove, create a multipath route over both IUT interfaces. "
              "Create corresponding route to IUT addresses on Tester.");

    configure_multipath_routes(&cstate);
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that created route works as expected: if there is only "
              "a single path, all packets on IUT should go through it, otherwise "
              "connections should be spread over both paths according to their "
              "weight.");

    CHECK_RC(check_multipath_route(&cstate, "The first route"));

    TEST_STEP("Add or remove a path for IUT route according to @p change "
              "and @p first_if. Modify route to IUT addresses on Tester "
              "in the same manner.");

    if (change == CHANGE_ADD)
    {
        cstate.weight1 = weight1;
        cstate.weight2 = weight2;
    }
    else
    {
        if (first_if)
            cstate.weight1 = 0;
        else
            cstate.weight2 = 0;
    }

    configure_multipath_routes(&cstate);
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that created route works as expected: if there is only "
              "a single path, all packets on IUT should go through it, otherwise "
              "connections should be spread over both paths according to their "
              "weight.");

    CHECK_RC(check_multipath_route(&cstate, "The second route"));

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(multipath_check_state_clean(&cstate));

    TEST_END;
}
