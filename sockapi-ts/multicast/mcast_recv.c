/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP.
 *
 * $Id$
 */

/** @page multicast-mcast_recv Receiving multicast traffic on two proccess using EF_NAME on L5 interface.
 *
 * @objective Check that two process with set EF_NAME variable both recieve
 *            multicast packets.
 *
 * @type interop
 *
 * @param pco_tst       PCO on Tester
 * @param pco_iut1      PCO on IUT
 * @param pco_iut2      PCO on IUT
 * @param mcast_addr    Multicast address
 * @param dont_join     Do not join multicast group
 *                      (considered for mcast_addr=224.0.0.1 only)
 * @param bind_wildcard If @c TRUE, bind @p iut_s to @c INADDR_ANY address.
 *                      Otherwise bind to @p mcast_addr
 * @param packet_number Number of datagrams to send for reliability.
 * @param sock_func     Socket creation function.
 *
 * @par Test sequence:
 * -# Create datagram sockets: @p iut_s1 on @p pco_iut1, @p iut_s2 on
 *    @p pco_iut2 and @p tst_s on @p pco_tst.
 * -# If @p dont_join is FALSE, adjoin @p iut_s1 and @p iut_s2 to
 *    @p mcast_addr multicasting group.
 * -# Set @c IP_MULTICAST_IF option on @p tst_s to set @p tst_if as
 *    interface for multicast traffic sending.
 * -# Send @p packet_number datagrams from @p tst_s to @p mcast_addr.
 * -# Check that both @p iut_s1 and @p iut_s2 sockets recieved datagrams.
 *  
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_recv"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#define DATA_BULK       200

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut1 = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s1 = -1;
    int             iut_s2 = -1;
    int             tst_s = -1;

    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if;
    const struct sockaddr     *mcast_addr = NULL;
    uint8_t                   *sendbuf = NULL;
    uint8_t                   *recvbuf = NULL;
    struct tarpc_mreqn         mreq;
    tarpc_joining_method       method;
    sockts_socket_func         sock_func;

    te_bool    dont_join = FALSE;
    te_bool    second_join = FALSE;
    te_bool    bind_wildcard;
    te_bool    sock_readable;

    int        i;
    int        packet_number;
    int        opt_on = 1;

    mcast_listener_t listener;
    int              mcast_packets_received = 0;

    te_bool          use_zc = FALSE;
    rpc_msghdr       msg;
    struct rpc_iovec vector;

    TEST_START;

    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut1, mcast_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(dont_join);
    if (!dont_join)
        TEST_GET_BOOL_PARAM(second_join);
    TEST_GET_BOOL_PARAM(bind_wildcard);
    TEST_GET_INT_PARAM(packet_number);
    if (!dont_join)
        TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    sendbuf = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = malloc(DATA_BULK));

    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM,
                       RPC_IPPROTO_UDP);
    iut_s1 = sockts_socket(sock_func, pco_iut1, RPC_PF_INET,
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    iut_s2 = sockts_socket(sock_func, pco_iut2, RPC_PF_INET,
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    if (SIN(mcast_addr)->sin_addr.s_addr != htonl(INADDR_ALLHOSTS_GROUP))
    {
        CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut1, pco_tst, iut_if,
                                               tst_addr, mcast_addr);
    }

    if (!dont_join && rpc_common_mcast_join(pco_iut1, iut_s1, mcast_addr,
                                            tst_addr, iut_if->if_index,
                                            method) < 0)
    {
        TEST_VERDICT("Sockets on IUT cannot join multicast group");
    }
    if (!dont_join && second_join &&
        rpc_common_mcast_join(pco_iut2, iut_s2, mcast_addr, tst_addr,
                              iut_if->if_index, method) < 0)
    {
        TEST_VERDICT("Sockets on IUT cannot join multicast group");
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
           sizeof(mreq.address));
    rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);

    rpc_setsockopt(pco_iut1, iut_s1, RPC_SO_REUSEADDR, &opt_on);
    rpc_setsockopt(pco_iut2, iut_s2, RPC_SO_REUSEADDR, &opt_on);

    struct sockaddr_storage any_addr;
    memset(&any_addr, 0, sizeof(any_addr));
    memcpy(&any_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
    te_sockaddr_set_wildcard(SA(&any_addr));
    if (bind_wildcard)
    {
        rpc_bind(pco_iut1, iut_s1, CONST_SA(&any_addr));
        rpc_bind(pco_iut2, iut_s2, CONST_SA(&any_addr));
    }
    else
    {
        rpc_bind(pco_iut1, iut_s1, mcast_addr);
        rpc_bind(pco_iut2, iut_s2, mcast_addr);
    }

    if (!use_zc)
        listener = mcast_listener_init(pco_iut1, iut_if, mcast_addr,
                                       tst_addr, 1);

    for (i = 0; i < packet_number; i++)
    {
        if (!use_zc)
            mcast_listen_start(pco_iut1, listener);
        rpc_sendto(pco_tst, tst_s, sendbuf, DATA_BULK, 0, mcast_addr);
        TAPI_WAIT_NETWORK;

        if (!use_zc)
        {
            mcast_packets_received = mcast_listen_stop(pco_iut1, listener,
                                                       NULL);
        }

        RPC_GET_READABILITY(sock_readable, pco_iut1, iut_s1, 1);
        if (!sock_readable && dont_join)
        {
            TEST_VERDICT("IUT does not receive multicast traffic without "
                         "join on iut_s1");
        }
        RPC_GET_READABILITY(sock_readable, pco_iut2, iut_s2, 1);
        if (!sock_readable && dont_join)
        {
            TEST_VERDICT("IUT does not receive multicast traffic without "
                         "join on iut_s2");
        }
        if (sock_readable && !dont_join && !second_join)
        {
            TEST_VERDICT("IUT receives multicast traffic without "
                         "join on iut_s2");
        }

        if (use_zc)
        {
            memset(&msg, 0, sizeof(msg));
            vector.iov_base = recvbuf;
            vector.iov_len = vector.iov_rlen = DATA_BULK;
            msg.msg_iov = &vector;
            msg.msg_iovlen = msg.msg_riovlen = 1;
            RPC_AWAIT_IUT_ERROR(pco_iut1);
            rc = rpc_simple_zc_recv_acc(pco_iut1, iut_s1, &msg, 0);
            if (rc == -1)
            {
                CHECK_RPC_ERRNO(pco_iut1, RPC_ENOTEMPTY,
                                "onload_zc_recv() returns %d, but",
                                rc);
                rc = rpc_simple_zc_recv(pco_iut1, iut_s1, &msg, 0);
                TEST_VERDICT("Multicast packet was detected by system");
                mcast_packets_received = 1;
            }
        }
        else
            rc = rpc_recv(pco_iut1, iut_s1, recvbuf, DATA_BULK, 0);
        if (rc != DATA_BULK)
            TEST_VERDICT("Incorrect size of data was receved");
        if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
                TEST_VERDICT("Data verification for iut_s1 failed");

        if (!sock_readable)
            continue;

        if (use_zc)
        {
            memset(&msg, 0, sizeof(msg));
            vector.iov_base = recvbuf;
            vector.iov_len = vector.iov_rlen = DATA_BULK;
            msg.msg_iov = &vector;
            msg.msg_iovlen = msg.msg_riovlen = 1;
            RPC_AWAIT_IUT_ERROR(pco_iut2);
            rc = rpc_simple_zc_recv_acc(pco_iut2, iut_s2, &msg, 0);
            if (rc == -1)
            {
                CHECK_RPC_ERRNO(pco_iut2, RPC_ENOTEMPTY,
                                "onload_zc_recv() returns %d, but",
                                rc);
                rc = rpc_simple_zc_recv(pco_iut2, iut_s2, &msg, 0);
                TEST_VERDICT("Multicast packet was detected by system");
                mcast_packets_received = 1;
            }
        }
        else
            rc = rpc_recv(pco_iut2, iut_s2, recvbuf, DATA_BULK, 0);
        if (rc != DATA_BULK)
            TEST_VERDICT("Incorrect size of data was receved");
        if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
                TEST_VERDICT("Data verification for iut_s2 failed");

        if (mcast_packets_received != 0)
        {
            TEST_VERDICT("Multicast packet was detected by system");
        }
    }

    if (!dont_join &&
        rpc_common_mcast_leave(pco_iut1, iut_s1, mcast_addr, tst_addr,
                               iut_if->if_index, method) < 0)
    {
        TEST_VERDICT("Socket on IUT cannot leave multicast group");
    }
    if (!dont_join && second_join &&
        rpc_common_mcast_leave(pco_iut2, iut_s2, mcast_addr, tst_addr,
                               iut_if->if_index, method) < 0)
    {
        TEST_VERDICT("Socket on IUT cannot leave multicast group");
    }

    TEST_SUCCESS;

cleanup:
    if (!use_zc)
        mcast_listener_fini(pco_iut1, listener);
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
