/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-outgoing_if Outgoing interface for multicasting choice.
 *
 * @objective Check if route to multicast address overrides IP_MULTICAST_IF option.
 *
 * @type Conformance.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst1      PCO on Tester1
 * @param pco_tst2      PCO on Tester2
 * @param iut_if1       Interface on IUT connected to Tester1
 * @param tst1_if       Interface on Tester1
 * @param iut_if2       Interface on IUT connected to Tester2
 * @param tst2_if       Interface on Tester2
 * @param iut_addr1     Address on @p iut_if1
 * @param mcast_addr    Multicast address
 * @param data_len      Size of datagram
 * @param connect_iut   Connect @p iut_s and use @b send() instead of @b sendto
 * @param packet_number Number of datagrams to send for reliability.
 * @param sock_func     Socket creation function.
 *
 * @par Scenario:
 *
 * -# Create a datagram socket @p iut_s on @p pco_iut.
 * -# Set @c IP_MULTICAST_IF option with address of @p iut1_if as parameter.
 * -# Create datagram sockets: @p tst1_s on @p pco_tst1
 *    and @p tst2_s on @p pco_tst2.
 * -# Make them join multicast group @p mcast_addr.
 * -# Bind them to @p mcast_addr.
 * -# Add a route to @p mcast_addr via interface @p iut_if2 on IUT.
 * -# Send @p packet_number datagrams from @p iut_s to @p mcast_addr.
 * -# Wait 100 milliseconds.
 * -# Make sure that @p tst2_s is not readable.
 * -# Receive all datagrams on @p tst1_s. Verify them.
 * -# Close sockets.
 *
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/outgoing_if"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

int
main(int argc, char *argv[])
{
    rpc_socket_domain      domain;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;
    const struct sockaddr *mcast_addr = NULL;
    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;
    int                    iut_s = -1;
    int                    tst1_s = -1;
    int                    tst2_s = -1;
    int                    i;
    
    const struct if_nameindex   *iut_if1;
    const struct if_nameindex   *tst1_if;
    const struct if_nameindex   *iut_if2;
    const struct if_nameindex   *tst2_if;
 
    char                  *sendbuf = NULL;
    char                  *recvbuf = NULL;
    int                    data_len;
    te_bool                socket_readable;
    int                    af;
    int                    route_prefix;
    int                    packet_number;
    cfg_handle             route_handle = CFG_HANDLE_INVALID;
    struct tarpc_mreqn     mreq;
    te_bool                connect_iut;
    te_bool                bind_iut;
    tarpc_joining_method   method;
    sockts_socket_func     sock_func;

    mcast_listener_t listener1 = CSAP_INVALID_HANDLE;
    mcast_listener_t listener2 = CSAP_INVALID_HANDLE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_BOOL_PARAM(bind_iut);
    TEST_GET_MCAST_METHOD(method);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    domain = rpc_socket_domain_by_addr(iut_addr1);

    sendbuf = te_make_buf_by_len(data_len);
    CHECK_NOT_NULL(recvbuf = malloc(data_len));

    iut_s = sockts_socket(sock_func, pco_iut, domain,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    if (rpc_mcast_join(pco_tst1, tst1_s, mcast_addr, tst1_if->if_index,
                       method) != 0)
    {
        TEST_FAIL("Cannot join multicast group on Tester1");
    }

    if (rpc_mcast_join(pco_tst2, tst2_s, mcast_addr, tst2_if->if_index,
                       method) != 0)
    {
        TEST_FAIL("Cannot join multicast group on Tester2");
    }

    rpc_bind(pco_tst1, tst1_s, mcast_addr);
    rpc_bind(pco_tst2, tst2_s, mcast_addr);
    
    if (bind_iut)
        rpc_bind(pco_iut, iut_s, mcast_addr);

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    mreq.address = SIN(iut_addr1)->sin_addr.s_addr;
    rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);

    af = addr_family_rpc2h(sockts_domain2family(domain));
    route_prefix = te_netaddr_get_size(af) * 8;

    if (tapi_cfg_add_route(pco_iut->ta, af,
                           te_sockaddr_get_netaddr(mcast_addr),
                           route_prefix, te_sockaddr_get_netaddr(tst2_addr),
                           NULL, NULL,
                           0, 0, 0, 0, 0, 0, &route_handle) < 0)
    {
        TEST_FAIL("Cannot add route to multicast address");
    }

    CFG_WAIT_CHANGES;

    if (connect_iut)
    {
        rpc_connect(pco_iut, iut_s, mcast_addr);
    }

    listener1 = mcast_listener_init(pco_iut, iut_if1, mcast_addr, NULL, 0);
    listener2 = mcast_listener_init(pco_iut, iut_if2, mcast_addr, NULL, 0);

    mcast_listen_start(pco_iut, listener1);
    mcast_listen_start(pco_iut, listener2);

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
    }

    MSLEEP(100);

    rc = mcast_listen_stop(pco_iut, listener1, NULL);
    if (rc == packet_number)
        RING_VERDICT("All multicast packets were detected by system on "
                     "iut_if1 interface");
    rc = mcast_listen_stop(pco_iut, listener2, NULL);
    if (rc  > 0)
        RING_VERDICT("Multicast packets were detected by system on "
                     "iut_if2 intarface");

    RPC_GET_READABILITY(socket_readable, pco_tst2, tst2_s, 1);

    if (!socket_readable)
    {
        for (i = 0; i < packet_number; i++)
        {
            rc = rpc_recv(pco_tst1, tst1_s, recvbuf, data_len, 0);
            if (rc != data_len || memcmp(sendbuf, recvbuf, rc) != 0)
            {
                TEST_FAIL("Data verification failed");
            }
        }   
        RPC_CHECK_READABILITY(pco_tst1, tst1_s, FALSE); 
    }
    else
    {
        TEST_VERDICT("Route overrides IP_MULTICAST_IF");
    }

    TEST_SUCCESS;

cleanup:
    mcast_listener_fini(pco_iut, listener1);
    mcast_listener_fini(pco_iut, listener2);
    tapi_cfg_del_route(&route_handle);
    free(sendbuf);
    free(recvbuf);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
