/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-default_if_for_join IP_ADD_MEMBERSHIP behaviour in case of wildcard local address and zero interface index.
 *
 * @objective Check that if imr_address and imr_ifindex are zeroed,
 *            setsockopt(IP_ADD_MEMBERSHIP) uses routing table to find
 *            appropriate interface.
 *
 * @type Conformance.
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on Tester
 * @param iut_if            Interface on IUT connected to Tester
 * @param tst_if            Interface on Tester
 * @param tst_addr          Address on @p iut_if1
 * @param mcast_addr        Multicast address
 * @param data_len          Size of datagram
 * @param packet_number     Number of datagrams to send for reliability.
 * @param sock_func         Socket creation function
 *
 * @par Scenario:
 *
 * -# Create datagram sockets: @p iut_s on @p pco_iut and
 *    @p tst_s on @p pco_tst.
 * -# Bind @p tst_s to @p mcast_addr.
 * -# Add a route to @p mcast_addr on @p pco_iut.
 * -# Try to join a multicast group @p mcast_addr with zero interface index.
 *    If it fails, make a warning.
 * -# If it succeeded:
 *     -# Do multiple times for more reliability:
 *         -# Send a datagram from @p tst_s to @p mcast_addr.
 *         -# Wait 100 milliseconds.
 *         -# Check that @p iut_s did not receive it.
 *     -# Leave the @p mcast_addr group.
 * -# If @p direct_route is @c TRUE, add a route to @p mcast_addr
 *    with interface @p iut_if on @p pco_iut.
 * -# Otherwise:
 *     -# Add a route to @p tst_addr with interface @p iut_if on @p pco_tst.
 *     -# Add a route to @p mcast_addr via @p tst_addr.
 * -# Join multicast group @p mcast_addr with zero interface index again.
 * -# Do @p packet_number times for more reliability:
 *     -# Send a datagram from @p tst_s to @p mcast_addr.
 *     -# Receive datagram on @p iut_s and verify it. If no errors occured,
 *        test is passed.
 *   
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/default_if_for_join"

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
    const struct sockaddr *mcast_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;

    const struct if_nameindex   *iut_if;
    const struct if_nameindex   *tst_if;

    char                  *sendbuf = NULL;
    char                  *recvbuf = NULL;
    int                    data_len;
    te_bool                direct_route;
    int                    i;
    int                    af;
    int                    route_prefix;
    int                    packet_number;
    cfg_handle             rh1 = CFG_HANDLE_INVALID;
    cfg_handle             rh2 = CFG_HANDLE_INVALID;
    cfg_handle             rh3 = CFG_HANDLE_INVALID;
    tarpc_joining_method   method;

    mcast_listener_t listener;

    te_bool          use_zc = FALSE;
    rpc_msghdr       msg;
    struct rpc_iovec vector;

    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_BOOL_PARAM(direct_route);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    domain = rpc_socket_domain_by_addr(tst_addr);
    af = addr_family_rpc2h(sockts_domain2family(domain));
    route_prefix = te_netaddr_get_size(af) * 8;

    sendbuf = te_make_buf_by_len(data_len);
    CHECK_NOT_NULL(recvbuf = malloc(data_len));

    iut_s = sockts_socket(sock_func, pco_iut,
                          domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    rpc_bind(pco_iut, iut_s, mcast_addr);

    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);


    if (tapi_cfg_add_route(pco_tst->ta, af,
                           te_sockaddr_get_netaddr(mcast_addr),
                           route_prefix, NULL, tst_if->if_name, NULL,
                           0, 0, 0, 0, 0, 0, &rh1) < 0)
    {
        TEST_FAIL("Cannot add route to multicast address on Tester");
    }

    CFG_WAIT_CHANGES;

    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut, pco_tst, iut_if, tst_addr,
                                           mcast_addr);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if ((rc = rpc_common_mcast_join(pco_iut, iut_s, mcast_addr, tst_addr,
                                    0, method)) != 0)
    {
        WARN("System cannot select interface to join multicast group;"
             "error %r", rc);
    }
    else
    {
        for (i = 0; i < packet_number; i++)
        {
            rpc_sendto(pco_tst, tst_s, sendbuf, data_len, 0, mcast_addr);
            MSLEEP(100);
            RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);
        }

        rpc_common_mcast_leave(pco_iut, iut_s, mcast_addr, tst_addr,
                               0, method);
    }

    if (direct_route)
    {
        if (tapi_cfg_add_route(pco_iut->ta, af,
                               te_sockaddr_get_netaddr(mcast_addr),
                               route_prefix, NULL, iut_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0, &rh2) < 0)
        {
            TEST_FAIL("Cannot add route to multicast address");
        }
    }
    else
    {
        if (tapi_cfg_add_route(pco_iut->ta, af,
                               te_sockaddr_get_netaddr(tst_addr),
                               route_prefix, NULL, iut_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0, &rh2) < 0)
        {
            TEST_FAIL("Cannot add route to Tester");
        }

        CFG_WAIT_CHANGES;

        if (tapi_cfg_add_route(pco_iut->ta, af,
                               te_sockaddr_get_netaddr(mcast_addr),
                               route_prefix,
                               te_sockaddr_get_netaddr(tst_addr),
                               NULL, NULL,
                               0, 0, 0, 0, 0, 0, &rh3) < 0)
        {
            TEST_FAIL("Cannot add route to multicast address via Tester");
        }
    }

    CFG_WAIT_CHANGES;

    if ((rc = rpc_common_mcast_join(pco_iut, iut_s, mcast_addr, tst_addr,
                                    0, method)) != 0)
    {
        TEST_FAIL("System cannot choose interface to join multicast group;"
                  "error %r", rc);
    }
    else
    {
        if (!use_zc)
            listener = mcast_listener_init(pco_iut, iut_if, mcast_addr,
                                           tst_addr, 1);
        for (i = 0; i < packet_number; i++)
        {
            te_bool sock_readable;

            if (!use_zc)
                mcast_listen_start(pco_iut, listener);

            rpc_sendto(pco_tst, tst_s, sendbuf, data_len, 0, mcast_addr);

            MSLEEP(100);

            if (!use_zc)
            {
                rc = mcast_listen_stop(pco_iut, listener, NULL);
                if (rc > 0)
                    TEST_VERDICT("Multicast packet was detected by system");
            }

            RPC_GET_READABILITY(sock_readable, pco_iut, iut_s, 1);
            if (!sock_readable)
            {
                TEST_VERDICT("IUT does not receive data. Perhaps default "
                             "interface was joined instead of one from "
                             "route to mcast_addr");
            }

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
                    TEST_VERDICT("Multicast packet was detected by system");
                }
            }
            else
                rc = rpc_recv(pco_iut, iut_s, recvbuf, data_len, 0);

            if (rc != data_len)
            {
                TEST_FAIL("Unexpected datagram size: %d instead of %d",
                          rc, data_len);
            }
            if (memcmp(sendbuf, recvbuf, data_len) != 0)
            {
                TEST_FAIL("Data verification error");
            }
            RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);
        }
    }

    TEST_SUCCESS;

cleanup:
    if (!use_zc)
        mcast_listener_fini(pco_iut, listener);
    free(sendbuf);
    free(recvbuf);
    tapi_cfg_del_route(&rh3);
    tapi_cfg_del_route(&rh2);
    tapi_cfg_del_route(&rh1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
