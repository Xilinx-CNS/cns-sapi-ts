/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-multipath_balancing Load balancing across paths of a multipath route
 *
 * @objective Check that all paths of a multipath route are used for
 *            network connections, and frequency of using a specific path
 *            is proportional to its weight.
 *
 ** @param env            Testing environment.
 *                        - @ref arg_types_env_triangle_iut_iut
 *                        - @ref arg_types_env_triangle_iut_iut_ipv6
 *  @param conns_num      Number of connections to check.
 *  @param pkts_per_conn  How many packets to send in both directions
 *                        over every connection.
 *  @param weight1        Weight of the first path.
 *                        - @c 1
 *                        - @c 3
 *  @param weight2        Weight of the second path.
 *                        - @c 1
 *                        - @c 3
 *  @param sock_type      Socket type used in testing.
 *                        - @c udp
 *                        - @c udp_notconn
 *                        - @c tcp_active
 *                        - @c tcp_passive
 * @param diff_addrs      If @c TRUE, each new Tester socket should be bound
 *                        to a new network address.
 * @param bind_iut        If @c TRUE, call @b bind() on IUT sockets.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/multipath_balancing"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "ts_route.h"
#include "ts_route_mpath.h"

int
main(int argc, char *argv[])
{
    MULTIPATH_COMMON_PARAMS_DECL;

    unsigned int            weight1;
    unsigned int            weight2;

    multipath_check_state cstate = MULTIPATH_CHECK_STATE_INIT;

    TEST_START;
    MULTIPATH_COMMON_PARAMS_GET;
    TEST_GET_UINT_PARAM(weight1);
    TEST_GET_UINT_PARAM(weight2);

    TEST_STEP("On IUT create a multipath route to @p tst_remote_net over @p iut1_if "
              "(with weight @p weight1) and over @p iut2_if (with weight "
              "@p weight2). Create a corresponding route on Tester.");

    MULTIPATH_COMMON_PARAMS_SET(&cstate);
    cstate.weight1 = weight1;
    cstate.weight2 = weight2;

    configure_multipath_routes(&cstate);
    CFG_WAIT_CHANGES;

    TEST_STEP("Establish @p conns_num connections, each time using different "
              "address or port on Tester according to @p diff_addrs. Over each "
              "connection send @p pkts_per_conn packets. "
              "Check that all packets for a single connection are sent through "
              "one of the paths. "
              "Check that total number of packets captured by CSAP on "
              "each Tester interface is proportional to weight of IUT "
              "route path leading to that interface.");

    CHECK_RC(check_multipath_route(&cstate, ""));

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(multipath_check_state_clean(&cstate));

    TEST_END;
}
