/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page multicast-mcast_send_via_l5 Sending multicast traffic on L5 interface.
 *
 * @objective Check that multicast packets sent on L5 interface
 *            are invisible for the OS.
 *
 * @type interop
 *
 * @param pco_tst       PCO on Tester
 * @param pco_iut       PCO on IUT
 * @param iut_addr      Local address on IUT
 * @param mcast_addr    Multicast address
 * @param iut_if        Interface on IUT
 * @param tst_if        Tester interace connected to IUT
 * @param use_route     If @c TRUE, add a route to @p mcast_addr on IUT,
 *                      otherwise set @c IP_MULTICAST_IF to @p iut_addr.
 * @param connect_iut   Connect IUT and use @b send() instead of @b sendto().
 * @param loop_disable  Disable @c IP_MULTICAST_LOOP socket option.
 * @param packet_number Number of datagrams to send for reliability.
 * @param mtu           MTU to be set on interfaces
 *
 * @par Test sequence:
 * -# Set MTU to @p mtu on both @p iut_if and @p tst_if. Packets of
 *    0.9 MTU length will be transmitted in the test.
 * -# Create datagram sockets: @p iut_s on @p pco_iut and
 *    @p tst_s on @p pco_tst.
 * -# Adjoin @p tst_s to @p mcast_addr multicasting group.
 * -# Set @c IP_MULTICAST_IF option on @p iut_s or add route depending on
 *    @p use_route value.
 * -# Send @p packet_number datagrams from @p iut_s to @p mcast_addr.
 * -# Receive them on Tester.
 * -# Create CSAP to catch packets from IUT to Tester. Start listening.
 * -# Send @p packet_number datagrams from @p iut_s to @p mcast_addr.
 * -# Receive them on Tester. Verify them.
 * -# Stop the CSAP. Make sure the multicast datagram was not caught by it.
 *  
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_send_via_l5"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"

#define DATA_BULK       (mtu * 0.9)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    rpc_socket_domain          domain = RPC_PF_INET;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *mcast_addr = NULL;
    uint8_t                   *sendbuf = NULL;
    uint8_t                   *recvbuf = NULL;
    int                        num;
    struct tarpc_mreqn         mreq;
    int                        af;
    int                        route_prefix;
    cfg_handle                 route_handle = CFG_HANDLE_INVALID;
    te_bool                    use_route;
    te_bool                    connect_iut;
    te_bool                    loop_disable;
    uint32_t                   optval = 0;
    int                        i;
    int                        packet_number;

    int                 mtu;
    te_saved_mtus       iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus       tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    mcast_listener_t    listener;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, mcast_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(use_route);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_BOOL_PARAM(loop_disable);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_INT_PARAM(mtu);

    CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                    mtu, &iut_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                    mtu, &tst_mtus));

    /* Reset ARP dynamic entries */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr));
    CFG_WAIT_CHANGES;

    sendbuf = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = malloc(DATA_BULK));

    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    rpc_bind(pco_iut, iut_s, iut_addr);

    if (loop_disable)
        rpc_setsockopt_raw(pco_iut, iut_s, RPC_IP_MULTICAST_LOOP, &optval, 1);

    if (rpc_mcast_join(pco_tst, tst_s, mcast_addr, tst_if->if_index,
                       TARPC_MCAST_ADD_DROP) < 0)
    {
        TEST_VERDICT("Socket on Tester cannot join multicast group");
    }

    if (use_route)
    {
        af = addr_family_rpc2h(sockts_domain2family(domain));
        route_prefix = te_netaddr_get_size(af) * 8;

        if (tapi_cfg_add_route(pco_iut->ta, af,
                               te_sockaddr_get_netaddr(mcast_addr),
                               route_prefix, te_sockaddr_get_netaddr(tst_addr),
                               iut_if->if_name,
                               te_sockaddr_get_netaddr(iut_addr),
                               0, 0, 0, 0, 0, 0, &route_handle) < 0)
        {
            TEST_FAIL("Cannot add route to multicast address");
        }
        CFG_WAIT_CHANGES;
    }
    else
    {
        memset(&mreq, 0, sizeof(mreq));
        mreq.type = OPT_IPADDR;
        memcpy(&mreq.address, te_sockaddr_get_netaddr(iut_addr),
               sizeof(mreq.address));
        rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);
    }

    rpc_bind(pco_tst, tst_s, mcast_addr);

    /* Send the first datagram (always by the means of OS) */
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
            rpc_send(pco_iut, iut_s, sendbuf, DATA_BULK, 0);
        }
        else
        {
            rpc_sendto(pco_iut, iut_s, sendbuf, DATA_BULK, 0, mcast_addr);
        }

        rpc_recv(pco_tst, tst_s, recvbuf, DATA_BULK, 0);
        SLEEP(1);
    }

    num = mcast_listen_stop(pco_iut, listener, NULL);

    if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
    {
        TEST_FAIL("Data verification failed");
    }

    if (num > 0) {
        WARN("%d of %d multicast packets detected by system", num,
             packet_number);
        if (num == packet_number)
        {
            TEST_VERDICT("All multicast packets were detected by system");
        }
    }

    if (rpc_mcast_leave(pco_tst, tst_s, mcast_addr, tst_if->if_index,
                        TARPC_MCAST_ADD_DROP) < 0)
    {
        TEST_FAIL("Socket on Tester cannot leave multicast group");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    if (route_handle != CFG_HANDLE_INVALID)
        tapi_cfg_del_route(&route_handle);

    mcast_listener_fini(pco_iut, listener);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    TEST_END;
}
