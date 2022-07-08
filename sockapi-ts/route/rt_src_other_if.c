/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-rt_src_other_if Route source address on another interface
 *
 * @objective Check what happens when route directs traffic over some
 *            interface but preferred source address specified for this
 *            route belongs to another interface.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_two_ifs_variants_with_ipv6
 * @param rt_sock_type  Type of sockets used in the test:
 *                      - @c tcp_active
 *                      - @c tcp_passive
 *                      - @c udp
 *                      - @c udp_connect
 * @param bind_to       To which address to bind IUT socket:
 *                      - @c no (do not perform binding)
 *                      - @c wildcard
 *                      - @c first (address on the first IUT interface)
 *                      - @c second (address on the second IUT interface)
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_src_other_if"

#include "ts_route.h"

/** Types of address to which IUT socket is bound */
enum {
    NO_BIND, /**< No bind at all */
    BIND_ADDR_WILDCARD, /**< Wildcard */
    BIND_ADDR_FIRST,    /**< Address on the first IUT interface */
    BIND_ADDR_SECOND,   /**< Address on the second IUT interface */
};

/** List of address types to use with TEST_GET_ENUM_PARAM() */
#define BIND_ADDR_TYPES \
    { "no", NO_BIND },     \
    { "wildcard", BIND_ADDR_WILDCARD },     \
    { "first",    BIND_ADDR_FIRST },        \
    { "second",   BIND_ADDR_SECOND }

int
main(int argc, char **argv)
{
    DECLARE_TWO_IFS_COMMON_PARAMS;
    DECLARE_TWO_IFS_MONITORS;

    struct sockaddr_storage     iut_addr;
    sockts_addr_type            addr_type = SOCKTS_ADDR_SPEC;
    int                         af;

    sockts_socket_type     rt_sock_type;
    int                    bind_to;

    UNUSED(single_peer);

    TEST_START;
    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_ENUM_PARAM(bind_to, BIND_ADDR_TYPES);

    af = alien_addr->sa_family;
    INIT_TWO_IFS_MONITORS(alien_addr, af, rt_sock_type);

    TEST_STEP("In this test IUT has two interfaces - @p iut_if1 (with "
              "address @p iut_addr1) and @p iut_if2 (with address "
              "@p iut_addr2). @p iut_if2 is connected to @p tst2_if "
              "interface on Tester2 host.");

    TEST_STEP("Assign @p alien_addr to @p tst2_if interface.");

    CHECK_RC(tapi_cfg_base_if_add_net_addr(
                           pco_tst2->ta,
                           tst2_if->if_name,
                           alien_addr,
                           te_netaddr_get_bitsize(af),
                           FALSE,
                           NULL));

    TEST_STEP("On IUT add a route to @p alien_addr over @p iut_if2 "
              "with preferred source address @p iut_addr1.");
    CHECK_RC(tapi_cfg_add_route(
                  pco_iut->ta, af,
                  te_sockaddr_get_netaddr(alien_addr),
                  te_netaddr_get_bitsize(af),
                  NULL,
                  iut_if2->if_name,
                  te_sockaddr_get_netaddr(iut_addr1),
                  0, 0, 0, 0, 0, 0, NULL));

    TEST_STEP("On Tester2 add a route to @p iut_addr1 over @p tst2_if "
              "with gateway @p iut_addr2.");
    CHECK_RC(tapi_cfg_add_route(
                  pco_tst2->ta, af,
                  te_sockaddr_get_netaddr(iut_addr1),
                  te_netaddr_get_bitsize(af),
                  te_sockaddr_get_netaddr(iut_addr2),
                  tst2_if->if_name,
                  NULL,
                  0, 0, 0, 0, 0, 0, NULL));

    CFG_WAIT_CHANGES;

    switch (bind_to)
    {
        case NO_BIND:
            tapi_sockaddr_clone_exact(iut_addr1, &iut_addr);
            addr_type = SOCKTS_ADDR_NONE;
            break;

        case BIND_ADDR_WILDCARD:
            tapi_sockaddr_clone_exact(iut_addr1, &iut_addr);
            addr_type = SOCKTS_ADDR_WILD;
            break;

        case BIND_ADDR_FIRST:
            tapi_sockaddr_clone_exact(iut_addr1, &iut_addr);
            break;

        case BIND_ADDR_SECOND:
            tapi_sockaddr_clone_exact(iut_addr2, &iut_addr);
            break;
    }

    TEST_STEP("Create a pair of sockets on IUT and Tester2 and establish "
              "connection if required according to @p rt_sock_type, "
              "binding IUT socket to an address chosen according to "
              "@p bind_to.");
    if (sock_type_sockts2rpc(rt_sock_type) == RPC_SOCK_STREAM)
    {
        TEST_SUBSTEP("If TCP is checked, call @b getpeername() on the "
                     "Tester socket. Check that it returns @p iut_addr2 "
                     "only if the IUT socket was explicitly bound to it, "
                     "and @p iut_addr1 otherwise.");
    }
    TEST_STEP("Send some data from the IUT socket to its peer.");
    if (sock_type_sockts2rpc(rt_sock_type) == RPC_SOCK_DGRAM)
    {
        TEST_SUBSTEP("If UDP is checked, check that @b recvfrom() on "
                     "Tester reports @p iut_addr2 as source address only "
                     "if the IUT socket was explicitly bound to it, and "
                     "@p iut_addr1 otherwise.");
    }

    sockts_rt_two_ifs_check_route(
                              FALSE, SA(&iut_addr),
                              alien_addr, -1, addr_type,
                              bind_to == NO_BIND ? FALSE : TRUE,
                              "Checking the route",
                              &env,
                              SOCKTS_RT_PCO_IUT_SOCK,
                              pco_tst1, pco_tst2,
                              rt_sock_type,
                              &iut_if1_monitor,
                              &iut_if2_monitor,
                              &tst1_if_monitor,
                              &tst2_if_monitor);

    TEST_SUCCESS;

cleanup:

    CLEANUP_TWO_IFS_MONITORS;

    TEST_END;
}
