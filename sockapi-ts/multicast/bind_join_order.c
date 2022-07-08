/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-bind_join_order Joining group and bind() different orders.
 *
 * @objective Check that @b bind() call and joining multicast group can be
 *            performed in any order, and the result does not depend on it.
 * 
 * @type Conformance.
 *
 * @param pco_tst           PCO on Tester
 * @param pco_iut           PCO on IUT
 * @param tst_if            Interface on Tester
 * @param iut_addr          IUT address
 * @param iut_if            IUT interface connected to Tester
 * @param mcast_addr        Multicast address
 * @param data_len          Datagram length.
 * @param use_route         Specify interface for outgoing multicast datagrams
 *                          using a route instead of IP_MULTICAST_IF option.
 * @param bind_multiaddr    If @c TRUE, bind @p iut_s to @p multiaddr, otherwise
 *                          to @c INADDR_ANY.
 * @param packet_number     Number of datagrams to send for reliability.
 * @param sock_func         Socket creation function.
 *
 * @par Scenario:
 * -# Open datagram sockets: @p iut_s on @p pco_iut and @p tst_s
 *    on @p pco_tst.
 * -# Check that joining before @b bind() works:
 *     -# Open datagram socket @p iut_s on @p pco_iut.
 *     -# Adjoin @p iut_s to @p mcast_addr group on @p iut_if interface.
 *     -# Bind it to @p mcast_addr or to @p INADDR_ANY.
 *     -# Send a datagram from @p tst_s to @p mcast_addr.
 *     -# Receive it on @p iut_s and verify it.
 *     -# Close @p iut_s.
 * -# Check that joining after @b bind() works:
 *     -# Open @p iut_s again.
 *     -# @b bind() it to @p mcast_addr.
 *     -# Adjoin it to @p mcast_addr group on @p iut_if interface.
 *     -# Send @p packet_number datagrams from @p tst_s to @p mcast_addr.
 *     -# Receive them on @p iut_s and verify them.
 *     -# Close @p iut_s.
 * -# On any error during these actions, test is failed.
 *    If no error occured, test is passed.
 *                 
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */
#define TE_TEST_NAME "multicast/bind_join_order"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *mcast_addr = NULL;
    int                        iut_s = -1;
    int                        tst_s = -1;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;
    int                        i;
    rpc_socket_domain          domain;
    char                      *sendbuf = NULL;
    char                      *recvbuf = NULL;
    int                        data_len;
    int                        packet_number;
    int                        af;
    int                        route_prefix;
    cfg_handle                 route_handle = CFG_HANDLE_INVALID;
    te_bool                    use_route;
    te_bool                    bind_multiaddr;
    tarpc_joining_method       method;

    mcast_listener_t listener = CSAP_INVALID_HANDLE;
    int              detected = 0;

    rpc_msghdr          msg;
    struct rpc_iovec    vector;
    te_bool             use_zc;
    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_BOOL_PARAM(use_route);
    TEST_GET_BOOL_PARAM(bind_multiaddr);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    domain = rpc_socket_domain_by_addr(iut_addr);

    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    sendbuf = te_make_buf_by_len(data_len);
    CHECK_NOT_NULL(recvbuf = (char *)malloc(data_len));

    if (use_route)
    {
        af = addr_family_rpc2h(sockts_domain2family(domain));
        route_prefix = te_netaddr_get_size(af) * 8;
    
        if (tapi_cfg_add_route(pco_tst->ta, af, 
                               te_sockaddr_get_netaddr(mcast_addr),
                               route_prefix, NULL, tst_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0, &route_handle) < 0)
        {
            TEST_FAIL("Cannot add route to multicast address");
        }
        CFG_WAIT_CHANGES;
    }
    else
    {
        tarpc_mreqn     mreq;

        memset(&mreq, 0, sizeof(mreq));
        mreq.type = OPT_IPADDR;
        memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
               sizeof(struct in_addr));
       
        rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);
    }

    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst, iut_if, tst_s, mcast_addr);

    if (!use_zc)
        listener = mcast_listener_init(pco_iut, iut_if, mcast_addr,
                                       tst_addr, 1);
    for (i = 0; i < packet_number; i++)
    {
        iut_s = sockts_socket(sock_func,
                              pco_iut, domain,
                              RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

        if (i == 0)
        {            
            rpc_common_mcast_join(pco_iut, iut_s, mcast_addr, tst_addr,
                                  iut_if->if_index, method);
        }
        
        /* On Win32 joining a group causes automatical bind */
        
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (bind_multiaddr)
        {
            rc = rpc_bind(pco_iut, iut_s, mcast_addr);
        }
        else
        {
            struct sockaddr_storage bind_addr;

            memset(&bind_addr, 0, sizeof(bind_addr));
            bind_addr.ss_family = SA(mcast_addr)->sa_family;
            te_sockaddr_set_port(SA(&bind_addr),
                                 te_sockaddr_get_port(mcast_addr));
            rc = rpc_bind(pco_iut, iut_s, SA(&bind_addr));
        }

        if (rc == -1)
        {
            if (i == 0 && RPC_ERRNO(pco_iut) == RPC_EINVAL)
            {
                TEST_VERDICT("Joining a group has bound the socket");
            }
            else
            {
                TEST_FAIL("RPC bind() unexpectedly failed");
            }
        }

        if (i != 0)
        {
            rpc_common_mcast_join(pco_iut, iut_s, mcast_addr, tst_addr,
                                  iut_if->if_index, method);
        }

        if (!use_zc)
            mcast_listen_start(pco_iut, listener);
        rpc_sendto(pco_tst, tst_s, sendbuf, data_len, 0, mcast_addr);
        
        MSLEEP(100);
        if (use_zc)
        {
            memset(&msg, 0, sizeof(msg));
            vector.iov_base = recvbuf;
            vector.iov_len = vector.iov_rlen = data_len;
            msg.msg_iov = &vector;
            msg.msg_iovlen = msg.msg_riovlen = 1;

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
        }
        else
        {
            rc = mcast_listen_stop(pco_iut, listener, NULL);
            if (rc > 0 && !detected)
            {
                RING_VERDICT("Multicast packet was detected by system");
                detected = 1;
            }
            rc = rpc_recv(pco_iut, iut_s, recvbuf, data_len, 0);
        }


        if (rc < data_len)
        {
            TEST_FAIL("Some data were lost");
        }
        
        if (memcmp(sendbuf, recvbuf, data_len) != 0)
        {
            TEST_FAIL("Data verification error");
        }
        
        rpc_close(pco_iut, iut_s);
        iut_s = -1;
    }

    TEST_SUCCESS;

cleanup:
    if (!use_zc)
        mcast_listener_fini(pco_iut, listener);
    free(sendbuf);
    free(recvbuf);
    tapi_cfg_del_route(&route_handle);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    TEST_END;
}
