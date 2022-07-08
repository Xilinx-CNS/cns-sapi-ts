/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-mcast_bind_recv Receive datagrams with socket bound to multicast address or to INADDR_ANY.
 *
 * @objective Make sure that socket bound to multicast address or to INADDR_ANY
 *            really receives datagrams for respective group
 *            and does not receive datagrams for other groups; and socket bound
 *            to unicast address does not receive any multicast datagrams.
 *
 * @type Conformance.
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on Tester
 * @param iut_addr              IUT address
 * @param tst_addr              Tester address
 * @param mcast_addr            Multicast address/es
 * @param iut_if                Interface on IUT
 * @param tst_if                Interface on Tester
 * @param mtu                   MTU to be set on interfaces
 * @param connect_socket        Whether receiving socket should be connected
 * @param bind_addr             Adress which @p iut_s should be bound to.
 * @param use_route             Specify interface for outgoing multicast
 *                              datagrams by a route instead of
 *                              IP_MULTICAST_IF socket option
 * @param packet_number         Number of datagrams to send for reliability.
 * @param connect_socket        Connect @p iut_s and use @b send().
 * @param sock_func             Socket creation function.
 * 
 * @par Scenario:
 *
 * -# Set MTU to @p mtu on both @p iut_if and @p tst_if. Packets of
 *    0.9 MTU length will be transmitted in the test.
 * -# Make port numbers of all used addresses equal.
 * -# Create datagram sockets: @p iut_s on @p pco_iut
 *    and @p tst_s on @p pco_tst.
 * -# Bind @p iut_s to @p bind_addr.
 * -# Bind @p tst_s to @p tst_addr.
 * -# If @p use_route, add route to @p mcast_addr on @p pco_tst.
 *    Otherwise set IP_MULTICAST_IF to @p tst_if.
 * -# Send @p packet_number datagrams from @p tst_s to @p mcast_addr.
 * -# Wait 100 milliseconds.
 * -# Make sure that @p iut_s did not receive them. If it does, test is failed.
 * -# Adjoin @p iut_s to group with address @p mcast_addr.
 * -# If @p connect_socket = @c TRUE, connect @p iut_s to @p tst_addr.
 * -# Send @packet_number datagrams from @p tst_s to @p mcast_addr.
 * -# If @p bind_addr = @p iut_addr, then:
 *     -# Wait 100 milliseconds;
 *     -# If @p iut_s has received datagrams, test is failed.
 *     -# If it has not, test is passed.
 * -# Receive them on @p iut_s, and verify the data.
 *  
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_bind_recv"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

int
main(int argc, char *argv[])
{
    rpc_socket_domain           domain; 
    rcf_rpc_server              *pco_iut = NULL;   
    rcf_rpc_server              *pco_tst = NULL;
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *tst_addr = NULL;
    const struct sockaddr       *mcast_addr = NULL;
    int                          iut_s = -1;
    int                          tst_s = -1;
    char                        *sendbuf = NULL;
    char                        *recvbuf = NULL;
    te_bool                      connect_socket;
    const struct sockaddr       *bind_addr;
    cfg_handle                   route_handle = CFG_HANDLE_INVALID;  
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;
    int                          data_len;
    int                          packet_number;
    int                          i;
    te_bool                      use_route;
    te_bool                      sock_readable;
    tarpc_joining_method         method;
    te_bool                      use_zc;
    sockts_socket_func           sock_func;

    int                 mtu;
    te_saved_mtus       iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus       tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    mcast_listener_t    listener;
    te_bool             listener_created = FALSE;
    int                 detected = 0;

    rpc_msghdr          msg;
    struct rpc_iovec   *vectors = NULL;
    int                 vector_len;
    int                 vectors_num;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_iut, bind_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(connect_socket);
    TEST_GET_BOOL_PARAM(use_route);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(use_zc);
    TEST_GET_INT_PARAM(mtu);
    SOCKTS_GET_SOCK_FUNC(sock_func);
    
    CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                    mtu, &iut_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                    mtu, &tst_mtus));

    /* Reset ARP dynamic entries */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr));

    domain = rpc_socket_domain_by_addr(iut_addr);
    
    te_sockaddr_set_port(SA(mcast_addr),
                         *(te_sockaddr_get_port_ptr(iut_addr)));
    te_sockaddr_set_port(SA(bind_addr),
                         *(te_sockaddr_get_port_ptr(iut_addr)));

    iut_s = sockts_socket(sock_func, pco_iut, domain,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_bind(pco_iut, iut_s, bind_addr);

    data_len = mtu * 0.9;
    sendbuf = te_make_buf_by_len(data_len);
    CHECK_NOT_NULL(recvbuf = (char *)malloc(data_len));

    if (use_route)
    {
        int   af;
        int   route_prefix;
        
        af = addr_family_rpc2h(sockts_domain2family(domain));
        route_prefix = te_netaddr_get_size(
                           addr_family_rpc2h(
                               sockts_domain2family(domain))) * 8;

        if (tapi_cfg_add_route(pco_tst->ta, af,
                               te_sockaddr_get_netaddr(mcast_addr),
                               route_prefix,
                               NULL, tst_if->if_name, NULL, 0, 0, 0, 0, 0, 0,
                               &route_handle) < 0)
        {
            TEST_FAIL("Cannot add route to multicast address");
        }
    }
    else
    {
        struct tarpc_mreqn mreq;
        
        memset(&mreq, 0, sizeof(mreq));
        mreq.type = OPT_IPADDR;
        memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
               sizeof(struct in_addr));
        
        rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);
    }


    if (connect_socket)
    {
        rpc_connect(pco_iut, iut_s, tst_addr);
        TAPI_WAIT_NETWORK;
    }

    if (SIN(mcast_addr)->sin_addr.s_addr != htonl(INADDR_ALLHOSTS_GROUP))
    {
        CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst, iut_if, tst_s,
                                   mcast_addr);
    }

    listener = mcast_listener_init(pco_iut, iut_if, mcast_addr,
                                   tst_addr, 1);
    listener_created = TRUE;
    TAPI_WAIT_NETWORK;

    if (rpc_mcast_join(pco_iut, iut_s,  mcast_addr, iut_if->if_index,
                       method) < 0)
    {
        TEST_FAIL("Socket on IUT cannot join multicast group");
    }

    if (strcmp(pco_iut->ta, pco_tst->ta) == 0)
        detected = 1;

    for (i = 0; i < packet_number; i++)
    {
        if (!use_zc)
        {
            mcast_listen_start(pco_iut, listener);
            /* Make sure that CSAP really started */
            TAPI_WAIT_NETWORK;
        }

        rpc_sendto(pco_tst, tst_s, sendbuf, data_len, 0, mcast_addr);

        MSLEEP(100);
        if (!use_zc)
        {
            rc = mcast_listen_stop(pco_iut, listener, NULL);
            if (rc > 0 && !detected)
            {
                detected = 1;
                RING_VERDICT("Multicast packet was detected by system");
            }
        }

        if (memcmp(&(SIN(bind_addr)->sin_addr),
                   &(SIN(mcast_addr)->sin_addr),
                   sizeof(SIN(mcast_addr)->sin_addr)) != 0 &&
            SIN(bind_addr)->sin_addr.s_addr != INADDR_ANY)
        {
            RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);
            TEST_SUCCESS;
        }

        RPC_GET_READABILITY(sock_readable, pco_iut, iut_s, 1);
        if (memcmp(&(SIN(bind_addr)->sin_addr),
                   &(SIN(mcast_addr)->sin_addr),
                   sizeof(SIN(mcast_addr)->sin_addr)) == 0 &&
            connect_socket && !sock_readable)
        {
            TEST_VERDICT("connect() bound iut_s to unicast address, "
                         "so data could not be delivered");
        }
        if (use_zc)
        {
            memset(&msg, 0, sizeof(msg));
            vectors_num = data_len / 1000 + 1;
            vector_len = 2000;
            create_plain_iovecs(&vectors, vector_len, vectors_num);

            msg.msg_iov = vectors;
            msg.msg_iovlen = msg.msg_riovlen = vectors_num;

            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_simple_zc_recv_acc(pco_iut, iut_s, &msg, 0);
            if (rc == -1)
            {
                CHECK_RPC_ERRNO(pco_iut, RPC_ENOTEMPTY,
                                "onload_zc_recv() returns %d, but",
                                rc);
                rc = rpc_simple_zc_recv(pco_iut, iut_s, &msg, 0);
                if (rc > 0 && !detected)
                {
                    detected = 1;
                    RING_VERDICT("Multicast packet was detected by system");
                }
            }

            iovecs_to_buf(vectors, vectors_num, recvbuf, data_len);
        }
        else
            rc = rpc_recv(pco_iut, iut_s, recvbuf, data_len, 0);

        if (rc < data_len)
        {
            TEST_FAIL("Some data were lost");
        }

        if (memcmp(sendbuf, recvbuf, data_len) != 0)
        {
            TEST_FAIL("Data verification error");
        }
    }

    TEST_SUCCESS;

cleanup:

    if (listener_created)
        mcast_listener_fini(pco_iut, listener);

    free(sendbuf);
    sockts_free_iovecs(vectors, vectors_num);
    free(recvbuf);

    if (route_handle != CFG_HANDLE_INVALID)
    {
        tapi_cfg_del_route(&route_handle);
    }

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
