/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-mcast_route Routing for multicast datagrams.
 *
 * @objective Check that routing table is taken into account for multicast packets.
 *
 * @type Conformance.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param tst_addr      Tester address
 * @param mcast_addr    Multicast address
 * @param iut_if        Interface on IUT
 * @param tst_if        Interface on Tester
 * @param data_len      Size of datagram
 * @param connect_iut   Connect @p iut_s and use @b send() instead of
 *                      @b sendto()
 * @param packet_number Number of datagrams to send for reliability.
 * @param use_gw        Whether to use route with gateway or without.
 *
 * @par Scenario:
 *
 * -# Open datagram socket @p tst_s on Tester.
 * -# Make it join @p mcast_addr multicast group.
 * -# Bind it to @p mcast_addr address.
 * -# Open datagram socket @p iut_s on IUT.
 * -# Reset default interface for multicast datagrams by calling
 *    @b setsockopt() with option @c IP_MULTICAST_IF and wildcard address
 *    as parameter.
 * -# Add route to @p mcast_addr with dev=<@p iut_if> on IUT.
 * -# Send @p packet_number datagrams from @p iut_s to @p tst_s.
 * -# Receive them on @p tst_s.
 * -# Make sure that their source address is address of @p iut_if.
 *    If it is, test is passed, otherwise test is failed.
 *
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_route"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

int
main(int argc, char *argv[])
{
    rpc_socket_domain      domain;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *mcast_addr = NULL;

    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;

    tarpc_mreqn            mrequest;

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    data_len = 0;
    int                    af;
    int                    route_prefix;
    int                    packet_number;
    int                    i;
    cfg_handle             route_handle;
    char                  *sendbuf = NULL;
    char                  *recvbuf = NULL;
    int                    inst;
    char                   src_addr_char[INET6_ADDRSTRLEN];
    te_bool                connect_iut;
    te_bool                sock_readable;
    te_bool                use_gw;
    tarpc_joining_method   method;

    struct sockaddr_storage   src_addr;
    unsigned int              src_addrlen = sizeof(struct sockaddr);

    mcast_listener_t listener = CSAP_INVALID_HANDLE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(use_gw);

    domain = rpc_socket_domain_by_addr(tst_addr);

    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    if (rpc_mcast_join(pco_tst, tst_s, mcast_addr, tst_if->if_index,
                       method) != 0)
    {
        TEST_FAIL("Cannot make socket on Tester join multicast group");
    }

    rpc_bind(pco_tst, tst_s, mcast_addr);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    memset(&mrequest, 0, sizeof(mrequest));
    mrequest.type = OPT_IPADDR;
    rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mrequest);

    af = addr_family_rpc2h(sockts_domain2family(domain));
    route_prefix = te_netaddr_get_size(af) * 8;
    if (use_gw)
    {
        if (tapi_cfg_add_route(pco_iut->ta, af, 
                               te_sockaddr_get_netaddr(mcast_addr),
                               route_prefix, te_sockaddr_get_netaddr(tst_addr),
                               NULL, NULL,
                               0, 0, 0, 0, 0, 0, &route_handle) < 0)
        {
            TEST_FAIL("Cannot add route to multicast address");
        }
    }
    else
    {
        if (tapi_cfg_add_route(pco_iut->ta, af, 
                               te_sockaddr_get_netaddr(mcast_addr),
                               route_prefix, NULL,
                               iut_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0, &route_handle) < 0)
        {
            TEST_FAIL("Cannot add route to multicast address");
        }

    }

    CFG_WAIT_CHANGES;

    sendbuf = te_make_buf_by_len(data_len);
    CHECK_NOT_NULL(recvbuf = (char *)malloc(data_len));

    if (connect_iut)
    {
        rpc_connect(pco_iut, iut_s, mcast_addr);
    }

    listener = mcast_listener_init(pco_iut, iut_if, mcast_addr, NULL, 0);
    mcast_listen_start(pco_iut, listener);

    for (i = 0; i < packet_number; i++)
    {
        if (connect_iut)
        {
            rpc_send(pco_iut, iut_s, sendbuf, data_len, 0);
        }
        else
        {
            rpc_sendto(pco_iut, iut_s, sendbuf, data_len, 0, mcast_addr);
        }

        RPC_GET_READABILITY(sock_readable, pco_tst, tst_s,
                            TAPI_WAIT_NETWORK_DELAY);
        if (connect_iut && !sock_readable)
        {
            TEST_VERDICT("connect() bound socket to a unicast address, "
                         "so data could not be delivered");
        }

        if (rpc_recvfrom(pco_tst, tst_s, recvbuf, data_len, 0,
                         SA(&src_addr), &src_addrlen) < data_len)
        {
            TEST_FAIL("Some data were lost");
        }

        if (memcmp(sendbuf, recvbuf, data_len) != 0)
        {
            TEST_FAIL("Data verification error");
        }
    }

    rc = mcast_listen_stop(pco_iut, listener, NULL);
    if (rc == packet_number)
        RING_VERDICT("All multicast packets were detected by system");

    CHECK_NOT_NULL(inet_ntop(af, te_sockaddr_get_netaddr(SA(&src_addr)),
                             src_addr_char, INET6_ADDRSTRLEN));

    if (cfg_get_instance_fmt(CVT_INTEGER, &inst,
                             "/agent:%s/interface:%s/net_addr:%s",
                             pco_iut->ta, iut_if->if_name,
                             src_addr_char) != 0)
    {
        TEST_FAIL("Some other interface was used to send");
    }

    TEST_SUCCESS;

cleanup:
    mcast_listener_fini(pco_iut, listener);
    tapi_cfg_del_route(&route_handle);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    free(sendbuf);
    free(recvbuf);

    TEST_END;
}
