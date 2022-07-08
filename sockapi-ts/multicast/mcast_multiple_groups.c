/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP.
 *
 * $Id$
 */

/** @page multicast-mcast_multiple_groups Receiving multicast traffic from two different multicast groups simultaneously.
 *
 * @objective Check that socket adjoined to two multicast addresses
 *            simultaneously receives traffic from both groups.
 *
 * @type interop
 *
 * @param pco_tst1      PCO on Tester
 * @param pco_tst2      PCO on Tester
 * @param pco_iut       PCO on IUT
 * @param iut_if1
 * @param iut_if2       Interfaces on IUT
 * @param mcast_addr1
 * @param mcast_addr2   Multicast addresses
 * @param packet_number Number of datagrams to send for reliability.
 * @param use_zc        Use @b onload_zc_recv() instead of @b recv()
 *                      on IUT
 * @param sock_func     Socket creation function
 *
 * @par Test sequence:
 * -# Create datagram sockets: @p iut_s on @p pco_iut, @p tst1_s
 *    on @p pco_tst1, @p tst2_s on @p pco_tst2.
 * -# Set @c IP_MULTICAST_IF option on @p tst1_s and @p tst2_s to set
 *    @p tst1_if and @p tst2_if as interfaces for multicast traffic
 *    sending.
 * -# Make multicast addresses to have the same port
 * -# Adjoin @p iut_s to @p mcast_addr1 and @p mcast_addr2
 *    multicasting groups.
 * -# Send @p packet_number datagrams from @p tst1_s to @p mcast_addr1.
 * -# Check that @p iut_s socket recieved datagrams.
 * -# Send @p packet_number datagrams from @p tst2_s to @p mcast_addr2.
 * -# Check that @p iut_s socket recieved datagrams.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_multiple_groups"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#define DATA_BULK       200

#define DETECT_VERD \
    "Incoming multicast packets were detected receiving data " \
    "from the peer %d"
int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    int             iut_s   = -1;
    int             tst1_s   = -1;
    int             tst2_s   = -1;

    const struct sockaddr     *tst1_addr = NULL;
    const struct sockaddr     *tst2_addr = NULL;
    const struct if_nameindex *iut_if1;
    const struct if_nameindex *iut_if2;
    const struct sockaddr     *mcast_addr1 = NULL;
    const struct sockaddr     *mcast_addr2 = NULL;
    const struct sockaddr     *any_addr = NULL;
    uint8_t                   *sendbuf = NULL;
    uint8_t                   *recvbuf = NULL;
    struct tarpc_mreqn         mreq;
    tarpc_joining_method       method;

    int         i;
    int         j;
    int         packet_number;
    te_bool     use_zc;
    te_bool     detected;

    mcast_listener_t listener;
    int              mcast_packets_received;

    sockts_socket_func  sock_func;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_ADDR(pco_iut, any_addr);
    TEST_GET_ADDR_NO_PORT(mcast_addr1);
    TEST_GET_ADDR_NO_PORT(mcast_addr2);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    sendbuf = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = malloc(DATA_BULK));

    te_sockaddr_set_port(SA(mcast_addr1),
                             *(te_sockaddr_get_port_ptr(any_addr)));
    te_sockaddr_set_port(SA(mcast_addr2),
                             *(te_sockaddr_get_port_ptr(any_addr)));

    tst1_s = rpc_socket(pco_tst1, RPC_PF_INET, RPC_SOCK_DGRAM,
                        RPC_IPPROTO_UDP);
    tst2_s = rpc_socket(pco_tst2, RPC_PF_INET, RPC_SOCK_DGRAM,
                        RPC_IPPROTO_UDP);
    iut_s = sockts_socket(sock_func, pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM,
                          RPC_IPPROTO_UDP);

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst1_addr),
           sizeof(mreq.address));
    rpc_setsockopt(pco_tst1, tst1_s, RPC_IP_MULTICAST_IF, &mreq);

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst2_addr),
           sizeof(mreq.address));
    rpc_setsockopt(pco_tst2, tst2_s, RPC_IP_MULTICAST_IF, &mreq);

    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst1, iut_if1, tst1_s,
                               mcast_addr1);
    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst2, iut_if2, tst2_s,
                               mcast_addr2);

    if (rpc_mcast_join(pco_iut, iut_s, mcast_addr1, iut_if1->if_index,
                       method) < 0)
    {
        TEST_VERDICT("Sockets on IUT cannot join multicast group");
    }
    if (rpc_mcast_join(pco_iut, iut_s, mcast_addr2, iut_if2->if_index,
                       method) < 0)
    {
        TEST_VERDICT("Sockets on IUT cannot join second multicast group");
    }

    rpc_bind(pco_iut, iut_s, any_addr);

    for (j = 0; j <= 1; j++)
    {
        detected = FALSE;

        if (!use_zc)
        {
            listener = mcast_listener_init(pco_iut,
                                           j == 0 ? iut_if1 : iut_if2,
                                           j == 0 ? mcast_addr1 :
                                                            mcast_addr2,
                                           j == 0 ? tst1_addr : tst2_addr,
                                           1);
            mcast_listen_start(pco_iut, listener);
        }

        for (i = 0; i < packet_number; i++)
        {
            rpc_sendto(j == 0 ? pco_tst1 : pco_tst2,
                       j == 0 ? tst1_s : tst2_s, sendbuf,
                       DATA_BULK, 0, j == 0 ? mcast_addr1 : mcast_addr2);

            if (!use_zc)
                rc = rpc_recv(pco_iut, iut_s, recvbuf, DATA_BULK, 0);
            else
            {
                RECV_VIA_ZC(pco_iut, iut_s, recvbuf, DATA_BULK,
                            0, NULL, NULL, !detected, &detected, FALSE,
                            DETECT_VERD, j + 1);
                if (rc < 0)
                {
                    TEST_VERDICT("onload_zc_recv() failed with errno %s "
                                  " receiving data from the peer %d",
                                  errno_rpc2str(RPC_ERRNO(pco_iut)),
                                  j + 1);
                }
            }

            if (rc != DATA_BULK ||
                memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
            {
                TEST_VERDICT("Data verification failed receiving data "
                             "from the peer %d", j + 1);
            }
        }

        if (!use_zc)
        {
            mcast_packets_received = mcast_listen_stop(pco_iut, listener,
                                                       NULL);
            if (mcast_packets_received > 0)
                RING_VERDICT(DETECT_VERD, j + 1);

            mcast_listener_fini(pco_iut, listener);
        }
        TAPI_WAIT_NETWORK;
    }

    if (rpc_mcast_leave(pco_iut, iut_s, mcast_addr1,
                        iut_if1->if_index, method) < 0)
        TEST_VERDICT("Socket on IUT cannot leave multicast group");
    if (rpc_mcast_leave(pco_iut, iut_s, mcast_addr2,
                        iut_if2->if_index, method) < 0)
        TEST_VERDICT("Socket on IUT cannot leave multicast group");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    TEST_END;
}
