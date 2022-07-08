/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP.
 *
 * $Id$
 */

/** @page multicast-mcast_invisible Receiving multicast traffic on L5 interface.
 *
 * @objective Check that multicast packets received on L5 interface
 *            are invisible for the OS.
 *
 * @type interop
 *
 * @param pco_tst       PCO on Tester
 * @param pco_iut       PCO on IUT
 * @param iut_addr      Local address on IUT
 * @param mcast_addr    Multicast address
 * @param tst_if        Tester interace connected to IUT
 * @param dont_join     Do not join multicast group
 *                      (considered for mcast_addr=224.0.0.1 only)
 * @param bind_wildcard If @c TRUE, bind @p iut_s to @c INADDR_ANY address.
 *                      Otherwise bind to @p mcast_addr
 * @param packet_number Number of datagrams to send for reliability.
 * @param sock_func     Socket creation function.
 *
 * @par Test sequence:
 * -# Create datagram sockets: @p iut_s on @p pco_iut and
 *    @p tst_s on @p pco_tst.
 * -# Set @c IP_MULTICAST_IF option on @p tst_s to set @p tst_if as interface
 *    for multicast traffic sending.
 * -# If @p dont_join is FALSE, adjoin @p iut_s to @p mcast_addr
 *    multicasting group.
 * -# Create CSAP to catch packets from Tester to IUT. Start listening.
 * -# Send @p packet_number datagrams from @p tst_s to @p mcast_addr.
 * -# Receive them on IUT. Verify them.
 * -# Stop the CSAP. Make sure the multicast datagram was not caught by it.
 *  
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_invisible"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#define DATA_BULK       200

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *mcast_addr = NULL;
    uint8_t                   *sendbuf = NULL;
    uint8_t                   *recvbuf = NULL;
    struct tarpc_mreqn         mreq;
    te_bool                    dont_join = FALSE;
    te_bool                    bind_wildcard;
    te_bool                    sock_readable;
    int                        i;
    int                        packet_number;
    tarpc_joining_method       method;
    sockts_socket_func         sock_func;

    mcast_listener_t listener;
    int              mcast_packets_received = 0;
    te_bool          detected = FALSE;

    te_bool          use_zc = FALSE;
    rpc_msghdr       msg;
    struct rpc_iovec vector;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(dont_join);
    TEST_GET_BOOL_PARAM(bind_wildcard);
    TEST_GET_INT_PARAM(packet_number);
    if (!dont_join)
        TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    sendbuf = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = malloc(DATA_BULK));

    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    iut_s = sockts_socket(sock_func, pco_iut, RPC_PF_INET,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
           sizeof(mreq.address));
    rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);


    if (SIN(mcast_addr)->sin_addr.s_addr != htonl(INADDR_ALLHOSTS_GROUP))
    {
        CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst, iut_if,
                                   tst_s, mcast_addr);
    }

    if (!dont_join && rpc_common_mcast_join(pco_iut, iut_s, mcast_addr,
                                            tst_addr, iut_if->if_index,
                                            method) < 0)
    {
        TEST_VERDICT("Socket on IUT cannot join multicast group");
    }

    if (bind_wildcard)
    {
        struct sockaddr_storage any_addr;

        memset(&any_addr, 0, sizeof(any_addr));
        memcpy(&any_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
        te_sockaddr_set_wildcard(SA(&any_addr));
        rpc_bind(pco_iut, iut_s, CONST_SA(&any_addr));
    }
    else
    {
        rpc_bind(pco_iut, iut_s, mcast_addr);
    }

    if (!use_zc)
        listener = mcast_listener_init(pco_iut, iut_if, mcast_addr,
                                       tst_addr, 1);

    for (i = 0; i < packet_number; i++)
    {
        if (!use_zc)
            mcast_listen_start(pco_iut, listener);
        rpc_sendto(pco_tst, tst_s, sendbuf, DATA_BULK, 0, mcast_addr);

        if (!use_zc)
        {
            mcast_packets_received = mcast_listen_stop(pco_iut, listener,
                                                       NULL);
        }

        RPC_GET_READABILITY(sock_readable, pco_iut, iut_s, 1);
        if (!sock_readable && dont_join)
        {
            TEST_VERDICT("IUT does not receive multicast traffic without join");
        }

        if (use_zc)
        {
            memset(&msg, 0, sizeof(msg));
            vector.iov_base = recvbuf;
            vector.iov_len = vector.iov_rlen = DATA_BULK;
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
                mcast_packets_received = 1;
            }
        }
        else
            rpc_recv(pco_iut, iut_s, recvbuf, DATA_BULK, 0);

        if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
        {
            TEST_VERDICT("Data verification failed");
        }

        if (mcast_packets_received != 0 && !detected)
        {
            detected = TRUE;
            RING_VERDICT("Multicast packet was detected by system");
        }
    }

    if (!dont_join &&
        rpc_common_mcast_leave(pco_iut, iut_s, mcast_addr, tst_addr,
                               iut_if->if_index, method) < 0)
    {
        TEST_VERDICT("Socket on IUT cannot leave multicast group");
    }
    TEST_SUCCESS;

cleanup:
    if (!use_zc)
        mcast_listener_fini(pco_iut, listener);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
