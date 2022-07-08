/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_bind_down_use_other_if Bind socket to an address on a "downed" interface, send packets via another interface
 *
 * @objective Check what happens when socket is bound to a "downed"
 *            interface but packets are going via another interface.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_two_nets
 * @param sock_type     Socket type:
 *                      - @c udp
 *                      - @c udp_notconn
 *                      - @c tcp_active
 *                      - @c tcp_passive
 * @param bind_before   If @c TRUE, bind IUT socket before setting
 *                      interface DOWN.
 * @param conn_before   If @c TRUE, connect IUT socket before setting
 *                      interface DOWN.
 *
 * @par Test sequence
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_bind_down_use_other_if"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;

    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *tst2_if = NULL;

    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *tst2_addr = NULL;

    sockts_socket_type  sock_type;
    rpc_socket_type     rpc_sock_type;
    te_bool             bind_before;
    te_bool             conn_before;

    int                 iut_s = -1;
    int                 tst_s = -1;
    int                 listener = -1;
    cfg_handle          rh = CFG_HANDLE_INVALID;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(tst2_if);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(bind_before);
    TEST_GET_BOOL_PARAM(conn_before);

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    TEST_STEP("Create a socket on IUT and its peer on @p pco_tst2.");

    iut_s = rpc_socket(pco_iut,
                       rpc_socket_domain_by_addr(iut_addr1),
                       rpc_sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst2,
                       rpc_socket_domain_by_addr(tst2_addr),
                       rpc_sock_type, RPC_PROTO_DEF);

    TEST_STEP("If not @p bind_before, set @p iut_if1 DOWN.");

    if (!bind_before)
    {
        CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if1->if_name));
        CFG_WAIT_CHANGES;
    }

    TEST_STEP("Bind IUT socket to @p iut_addr1, bind Tester socket "
              "to @p tst2_addr.");

    rpc_bind(pco_iut, iut_s, iut_addr1);
    rpc_bind(pco_tst2, tst_s, tst2_addr);

    TEST_STEP("On a Tester host where @p pco_tst2 resides, create a route to "
              "@p iut_addr1 via @p tst2_if.");

    CHECK_RC(tapi_cfg_add_route(
                          pco_tst2->ta, iut_addr1->sa_family,
                          te_sockaddr_get_netaddr(iut_addr1),
                          te_netaddr_get_size(iut_addr1->sa_family) * 8,
                          NULL, tst2_if->if_name, NULL,
                          0, 0, 0, 0, 0, 0, &rh));

    TEST_STEP("If not @p conn_before, set @p iut_if1 DOWN if it is not already "
              "done.");

    if (!conn_before && bind_before)
    {
        CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if1->if_name));
        CFG_WAIT_CHANGES;
    }

    if (rpc_sock_type == RPC_SOCK_DGRAM)
    {
        TEST_STEP("If IUT socket is UDP, call connect(@p tst2_addr) on IUT "
                  "socket if @p sock_type is @c SOCKTS_SOCK_UDP. Connect "
                  "Tester socket to @p iut_addr1.");
        if (sock_type == SOCKTS_SOCK_UDP)
            rpc_connect(pco_iut, iut_s, tst2_addr);
        rpc_connect(pco_tst2, tst_s, iut_addr1);
    }
    else
    {
        TEST_STEP("If IUT socket is TCP, establish connection actively or "
                  "passively according to @p sock_type.");

        if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        {
            rpc_listen(pco_tst2, tst_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_iut, iut_s, tst2_addr);
            listener = tst_s;
            tst_s = rpc_accept(pco_tst2, listener, NULL, NULL);
        }
        else
        {
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_tst2, tst_s, iut_addr1);
            listener = iut_s;
            iut_s = rpc_accept(pco_iut, listener, NULL, NULL);
        }
    }

    TEST_STEP("Set @p iut_if1 DOWN if it is not done by now.");

    if (!bind_before && !conn_before)
    {
        CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if1->if_name));
        CFG_WAIT_CHANGES;
    }

    TEST_STEP("Check data transmission in both directions between IUT socket "
              "and its peer.");

    sockts_test_connection_ext(pco_iut, iut_s, pco_tst2, tst_s,
                               tst2_addr, sock_type);

    TEST_STEP("Set @p iut_if1 UP.");

    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if1->if_name));
    CFG_WAIT_CHANGES;

    TEST_STEP("Check data transmission in both directions between IUT socket "
              "and its peer.");

    sockts_test_connection_ext(pco_iut, iut_s, pco_tst2, tst_s,
                               tst2_addr, sock_type);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s);
    if (listener >= 0)
    {
        if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
            CLEANUP_RPC_CLOSE(pco_tst2, listener);
        else
            CLEANUP_RPC_CLOSE(pco_iut, listener);
    }

    if (rh != CFG_HANDLE_INVALID)
        cfg_del_instance(rh, FALSE);

    TEST_END;
}
