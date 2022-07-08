/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-rt_src_addr Route source address
 *
 * @objective Check that source address is taken into account for setting
 *            source address for outgoing packets and connecting.
 *
 * @type conformance
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_single_if_variants_with_ipv6
 * @param rt_sock_type      Type of sockets used in the test
 *                          - @c tcp_active
 *                          - @c tcp_passive
 *                          - @c udp
 *                          - @c udp_connect
 * @param bind_to_device    If @c TRUE, bind IUT socket to the IUT
 *                          interface with @c SO_BINDTODEVICE.
 *
 * @par Test sequence:
 *
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_src_addr"

#include "ts_route.h"

int
main(int argc, char **argv)
{
    rpc_socket_type            sock_type;
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;

    const struct sockaddr *tst_addr;
    const struct sockaddr *iut_addr;
    const struct sockaddr *alien_addr;
    const struct sockaddr *tst_alien_addr;

    struct sockaddr_storage alien_addr_no_port;

    cfg_handle             rh = CFG_HANDLE_INVALID;
    cfg_handle             tst_rh = CFG_HANDLE_INVALID;
    cfg_handle             ah = CFG_HANDLE_INVALID;
    cfg_handle             tah = CFG_HANDLE_INVALID;

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    tst_s_listener = -1;
    int                    iut_s_listener = -1;
    int                    af;
    int                    route_prefix;

    uint8_t               *sendbuf = NULL;
    uint8_t               *recvbuf = NULL;
    int                    buf_len = 1024;

    struct sockaddr_storage  from_addr;
    socklen_t                from_addrlen = sizeof(from_addr);

    sockts_if_monitor iut_if_monitor = SOCKTS_IF_MONITOR_INIT;

    rpc_socket_domain      domain;
    sockts_socket_type     rt_sock_type;

    te_bool bind_to_device;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, alien_addr);
    TEST_GET_ADDR(pco_tst, tst_alien_addr);

    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_BOOL_PARAM(bind_to_device);

    GET_DOMAIN_AF_PREFIX(tst_addr, domain, af, route_prefix);
    sock_type = sock_type_sockts2rpc(rt_sock_type);

    TEST_STEP("Create sockets iut_s on IUT and tst_s on Tester, "
              "of type specified by @p rt_sock_type.");
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);

    TEST_STEP("Add @p alien_addr on @p iut_if interface.");
    TEST_STEP("Add @p tst_alien_addr on @p tst_if interface.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           alien_addr, route_prefix, FALSE,
                                           &ah));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           tst_alien_addr, route_prefix,
                                           FALSE, &tah));
    CFG_WAIT_CHANGES;

    TEST_STEP("Bind Tester socket to @p tst_alien_addr.");
    rpc_bind(pco_tst, tst_s, tst_alien_addr);

    TEST_STEP("Add route to @p tst_alien_addr via @p tst_addr with "
              "@p alien_addr as source address on IUT.");

    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(tst_alien_addr), route_prefix,
            te_sockaddr_get_netaddr(tst_addr), NULL,
            te_sockaddr_get_netaddr(alien_addr),
            0, 0, 0, 0, 0, 0, &rh) != 0)
    {
        TEST_FAIL("Cannot add route on IUT");
    }
    CFG_WAIT_CHANGES;

    TEST_STEP("Add route to @p alien_addr on Tester (otherwise Tester kernel "
              "will drop packets from IUT).");

    if (tapi_cfg_add_route(pco_tst->ta, af,
            te_sockaddr_get_netaddr(alien_addr), route_prefix,
            NULL, tst_if->if_name, NULL,
            0, 0, 0, 0, 0, 0, &tst_rh) != 0)
    {
        TEST_FAIL("Cannot add route to IUT on Tester");
    }
    CFG_WAIT_CHANGES;

    CHECK_RC(sockts_if_monitor_init(&iut_if_monitor,
                                    pco_iut->ta, iut_if->if_name, af,
                                    sock_type,
                                    NULL, tst_alien_addr,
                                    FALSE, TRUE));

    if (bind_to_device)
    {
        TEST_STEP("If @p bind_to_device is @c TRUE, bind the IUT socket "
                  "to @p iut_if with @c SO_BINDTODEVICE.");
        rpc_bind_to_device(pco_iut, iut_s, iut_if->if_name);
    }

    if (sock_type == RPC_SOCK_DGRAM)
    {
        TEST_STEP("If UDP socket is tested, then use either @b sendto() or "
                  "@b connect() + @b send(), according to @p rt_sock_type.");

        sendbuf = (uint8_t *)te_make_buf_by_len(buf_len);
        recvbuf = (uint8_t *)malloc(buf_len);

        if (rt_sock_type == SOCKTS_SOCK_UDP)
        {
            rpc_connect(pco_iut, iut_s, tst_alien_addr);
            rpc_send(pco_iut, iut_s, sendbuf, buf_len, 0);
        }
        else
        {
            rpc_sendto(pco_iut, iut_s, sendbuf, buf_len, 0, tst_alien_addr);
        }

        TEST_STEP("Receive packet with @b recvfrom() on Tester.");

        rpc_recvfrom(pco_tst, tst_s, recvbuf, buf_len, 0,
                     SA(&from_addr), &from_addrlen);
        if (memcmp(sendbuf, recvbuf, buf_len) != 0)
        {
            TEST_FAIL("Data verification error");
        }
    }
    else
    {
        TEST_STEP("If TCP socket is tested, establish TCP "
                  "connection actively from IUT side.");

        if (rt_sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        {
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_iut, iut_s, tst_alien_addr);
            tst_s_listener = tst_s;
            tst_s = rpc_accept(pco_tst, tst_s_listener,
                               SA(&from_addr), &from_addrlen);
        }
        else
        {
            struct sockaddr_storage iut_bind_addr;

            tapi_sockaddr_clone_exact(alien_addr,
                                      &iut_bind_addr);
            te_sockaddr_set_wildcard(SA(&iut_bind_addr));

            rpc_bind(pco_iut, iut_s, SA(&iut_bind_addr));
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_tst, tst_s, alien_addr);
            iut_s_listener = iut_s;
            iut_s = rpc_accept(pco_iut, iut_s_listener,
                               NULL, NULL);
        }
    }

    if (rt_sock_type != SOCKTS_SOCK_TCP_PASSIVE_CL)
    {
        TEST_STEP("Check that @b recvfrom() or @b accept() returned "
                  "@p alien_addr address.");

        tapi_sockaddr_clone_exact(alien_addr, &alien_addr_no_port);
        te_sockaddr_clear_port(SA(&alien_addr_no_port));
        te_sockaddr_clear_port(SA(&from_addr));

        if (te_sockaddrcmp(SA(&from_addr), from_addrlen,
                           SA(&alien_addr_no_port),
                           te_sockaddr_get_size(
                                      SA(&alien_addr_no_port))) != 0)
        {
            TEST_VERDICT("Packet source address is not "
                         "route source address");
        }
    }

    TEST_STEP("Send additional packets to check for traffic acceleration, "
              "since the first packet may be not accelerated on Onload "
              "due to ARP resolution issues.");

    CHECK_SOCKTS_TEST_SEND_RC(
          sockts_rt_test_send(rt_sock_type, pco_iut, iut_s,
                              pco_tst, tst_s,
                              tst_alien_addr, NULL,
                              TRUE, "Sending data from IUT"));

    TEST_STEP("Check that traffic is accelerated or not as expected.");
    CHECK_IF_ACCELERATED(&env, &iut_if_monitor, "");

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(
        sockts_if_monitor_destroy(&iut_if_monitor));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listener);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listener);

    free(sendbuf);
    free(recvbuf);

    TEST_END;
}
