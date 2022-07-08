/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page tcp-packet_ack_drop Packet retransmission in TCP connection
 *
 * @objective Check that packet retransmission in TCP connection doesn't
 *            crash the system.
 *
 * @type Conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_gw        PCO on host in the tested network
 *                      that is able to forward incoming packets (router)
 * @param pco_tst       PCO on TST
 * @param pack_type     The type of packet to be retransmitted
 *                      (@c syn / @c synack / @c packet /
 *                      @c fin/@c fin_close_wait)
 *
 * @par Scenario:
 * -# Create TCP sockets @p iut_s on @p pco_iut and @p tst_s on @p pco_tst
 *    and bind them to @p iut_addr and tst_addr respectively.
 * -# Turn on forwarding on router host then add route on 'pco_iut':
 *    'tst_addr' via gateway 'gw_iut_addr' and add route on 'pco_tst':
 *    'iut_addr' via gateway 'gw_tst_addr'.
 * -# If @p pack_type is @c synack call @b listen() on @p iut_s socket in
 *    all other cases call @b listen() on @p tst_s socket.
 * -# If @p pack_type is @c syn or @c synack add static ARP entry.
 * -# If @p pack_type is @c syn add static ARP entry in @p pco_iut ARP table
 *    for @p gw_iut_addr protocol address with @p iut_alien_link hardware
 *    address.
 * -# If @p pack_type is @c synack add static ARP entry in @p pco_tst ARP
 *    table for @p gw_tst_addr protocol address with @p tst_alien_link
 *    hardware address.
 * -# If @p pack_type is @c synack call @b connect() on @p tst_s socket
 *    to connect to @p iut_s socket in all other cases call @b connect() on
 *    @p iut_s socket to connect to @p tst_s socket.
 * -# If @p pack_type is @c synack or @c syn delete static ARP entry.
 * -# Call @b accept() to get @p acc_s socket.
 * -# If @p pack_type is @c fin_close_wait call @b close() on @p acc_s
 *    socket.
 * -# If @p pack_type is @c packet, @c fin or @c fin_close_wait add static
 *    ARP entry in @p pco_iut ARP table for @p gw_iut_addr protocol address
 *    with @p iut_alien_link hardware address.
 * -# If @p pack_type is @c packet send data from @p iut_s to @p tst_s.
 * -# If @p pack_type is @c fin or @ fin_close_wait call @b close() on
 *    @p iut_s socket.
 * -# Delete static ARP entry.
 * -# Restore configuration and close all socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/packet_ack_drop"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"

#define DATA_BULK 8192

static uint8_t buf[DATA_BULK];    /**< Auxiliary buffer */

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;

    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    const char                *pack_type;

    rpc_socket_domain domain;
    te_bool test_retr_queue = FALSE;
    te_bool route1_set = FALSE;
    te_bool route2_set = FALSE;
    int sndbuf_len = 1;
    int total_sent = 0;
    int tst_s = -1;
    int iut_s = -1;
    int acc_s = -1;

    /* Test preambule */
    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_STRING_PARAM(pack_type);
    TEST_GET_BOOL_PARAM(test_retr_queue);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TAPI_INIT_ROUTE_GATEWAY(gw);

    /* Scenario */
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);

    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);

    if (strcmp(pack_type, "synack") == 0)
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    else
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    /* Turn on forwarding on router host */
    CHECK_RC(tapi_route_gateway_set_forwarding(&gw, TRUE));

    /* Add route on 'pco_iut': 'tst_addr' via gateway 'gw_iut_addr' */
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
                            tst_addr->sa_family,
                            te_sockaddr_get_netaddr(tst_addr),
                            te_netaddr_get_size(tst_addr->sa_family) * 8,
                            te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the dst");
    }
    route1_set = TRUE;

    /* Add route on 'pco_tst': 'iut_addr' via gateway 'gw_tst_addr' */
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
                            iut_addr->sa_family,
                            te_sockaddr_get_netaddr(iut_addr),
                            te_netaddr_get_size(iut_addr->sa_family) * 8,
                            te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the src");
    }
    route2_set = TRUE;
    CFG_WAIT_CHANGES;

    /* Add static ARP entry to prevent connection establishment */
    if (strcmp(pack_type, "synack") == 0)
    {
        CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name, NULL, NULL,
                                 tst_addr, CVT_HW_ADDR(alien_link_addr),
                                 TRUE));
    }
    else if (strcmp(pack_type, "syn") == 0)
    {
        CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                                 gw_tst_addr, CVT_HW_ADDR(alien_link_addr),
                                 TRUE));
    }

    if (strcmp(pack_type, "synack") == 0 || strcmp(pack_type, "syn") == 0)
        TAPI_WAIT_NETWORK;

    if (strcmp(pack_type, "synack") == 0)
    {
        pco_tst->op = RCF_RPC_CALL;
        rpc_connect(pco_tst, tst_s, iut_addr);
    }
    else
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_connect(pco_iut, iut_s, tst_addr);
    }

    if (strcmp(pack_type, "synack") == 0 || strcmp(pack_type, "syn") == 0)
    {
        SLEEP(1);
        if (strcmp(pack_type, "synack") == 0)
        {
            CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name,
                                     pco_tst->ta, tst_if->if_name,
                                     tst_addr, NULL, FALSE));
        }
        else
        {
            CHECK_RC(tapi_remove_arp(pco_tst->ta, tst_if->if_name,
                                     gw_tst_addr));
        }
    }

    if (strcmp(pack_type, "synack") == 0)
    {
        pco_tst->op = RCF_RPC_WAIT;
        rpc_connect(pco_tst, tst_s, iut_addr);
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    }
    else
    {
        pco_iut->op = RCF_RPC_WAIT;
        rpc_connect(pco_iut, iut_s, tst_addr);
        acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
    }

    if (strcmp(pack_type, "synack") == 0 || strcmp(pack_type, "syn") == 0)
        TEST_SUCCESS;

    if (strcmp(pack_type, "fin_close_wait") == 0)
        RPC_CLOSE(pco_tst, acc_s);

    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             gw_tst_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));

    if (strcmp(pack_type, "packet") == 0)
    {
        if (test_retr_queue)
        {
            rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &sndbuf_len);
            rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &sndbuf_len);

            total_sent = rpc_send(pco_iut, iut_s, buf, sndbuf_len,
                                  RPC_MSG_DONTWAIT);
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_send(pco_iut, iut_s, buf, sndbuf_len,
                          RPC_MSG_DONTWAIT);
            if (rc < sndbuf_len)
            {
                if( rc < 0 )
                    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "send() "
                                    "returned -1, but");
                else
                    total_sent += rc;
                RING_VERDICT("Size of retransmition queue was reduced by "
                             "changing SO_SNDBUF");
            }
            else
                total_sent += rc;
        }
        else
        {
            pco_iut->op = RCF_RPC_CALL;
            rpc_send(pco_iut, iut_s, buf, DATA_BULK, 0);
        }
    }
    else
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_close(pco_iut, iut_s);
    }

    SLEEP(1);
    CHECK_RC(tapi_remove_arp(pco_tst->ta, tst_if->if_name, gw_tst_addr));

    if (strcmp(pack_type, "packet") == 0)
    {
        if (test_retr_queue)
        {
            /* Waiting for retransmission */
            SLEEP(5);
            if (total_sent !=  rpc_recv(pco_tst, acc_s, buf, DATA_BULK, 0))
                TEST_FAIL("recv() returned incorrect amount of data");
        }
        else
        {
            pco_iut->op = RCF_RPC_WAIT;
            rpc_send(pco_iut, iut_s, buf, DATA_BULK, RPC_MSG_DONTWAIT);
        }
    }
    else
    {
        pco_iut->op = RCF_RPC_WAIT;
        rpc_close(pco_iut, iut_s);
        iut_s = -1;
    }

    TEST_SUCCESS;
cleanup:

    if (route1_set)
    {
        if (tapi_cfg_del_route_via_gw(pco_iut->ta,
            tst_addr->sa_family,
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(tst_addr->sa_family) * 8,
            te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
        {
            ERROR("Cannot delete first route");
            result = EXIT_FAILURE;
        }
    }

    if (route2_set)
    {
        if (tapi_cfg_del_route_via_gw(pco_tst->ta,
            iut_addr->sa_family,
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(iut_addr->sa_family) * 8,
            te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
        {
            ERROR("Cannot delete second route");
            result = EXIT_FAILURE;
        }
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE((strcmp(pack_type, "synack") == 0) ?
                      pco_iut : pco_tst, acc_s);

    TEST_END;
}
