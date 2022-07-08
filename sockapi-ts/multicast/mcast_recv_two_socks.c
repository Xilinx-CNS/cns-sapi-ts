/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-mcast_recv_two_socks Two sockets from one or different stacks joined to the same multicast address
 *
 * @objective Check receive behaviour of two sockets from one or different stacks
 *            one of which is connected to remote Tester address
 *
 * @type Conformance.
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on Tester1
 * @param pco_tst               PCO on Tester2
 * @param iut_addr              IUT address
 * @param tst1_addr             Tester1 address
 * @param tst2_addr             Tester2 address
 * @param mcast_addr            Multicast address/es
 * @param iut_if1               Interface on IUT
 * @param iut_if2               Interface on IUT
 * @param tst1_if               Interface on Tester1
 * @param tst2_if               Interface on Tester2
 * @param packet_number         Number of datagrams to send for reliability.
 * @param diff_ifs              If it is @c TRUE join group on different
 *                              IUT interfaces
 * @param use_zc                Whether to use @b zc_recv() or @b recv()
 * @param connect_sock          Whether to connect socket or not
 * @param zero_length           Whether to use packets of zero lenght or
 *                              not
 * @param sock_func             Socket creation function
 * @param diff_stacks           If it is @c TRUE use different stacks
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_recv_two_socks"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#define DATA_BULK 512

#define CHECK_READABLE_GET(pco_, s_, detected_, mis_, sndbuf_) \
do {                                                                 \
                                                                     \
    te_bool readable = FALSE;                                        \
    RPC_GET_READABILITY(readable, pco_, s_, 1000);                   \
    if (readable)                                                    \
    {                                                                \
        if (use_zc)                                                  \
        {                                                            \
            RPC_AWAIT_IUT_ERROR(pco_);                               \
            rc = rpc_simple_zc_recv_acc(pco_, s_, &msg, 0);          \
            if (rc == -1)                                            \
            {                                                        \
                CHECK_RPC_ERRNO(pco_, RPC_ENOTEMPTY,                 \
                                "onload_zc_recv() returns %d, but",  \
                                rc);                                 \
                rc = rpc_simple_zc_recv(pco_, s_, &msg, 0);          \
                detected_++;                                         \
            }                                                        \
        }                                                            \
        else                                                         \
        {                                                            \
            rc = rpc_recv(pco_, s_, recvbuf, DATA_BULK, 0);          \
        }                                                            \
        if (zero_length)                                             \
        {                                                            \
            if (rc != 0)                                             \
                TEST_VERDICT("Receive function returned %d instead " \
                             "of 0", rc);                            \
        }                                                            \
        else if (memcmp(sndbuf_, recvbuf, DATA_BULK) != 0)           \
        {                                                            \
            TEST_VERDICT("Data verification for iut_s1 failed");     \
        }                                                            \
    }                                                                \
    else                                                             \
        mis_++;                                                      \
} while (0)

int
main(int argc, char *argv[])
{
    rpc_socket_domain           domain;
    rcf_rpc_server              *pco_iut1 = NULL;
    rcf_rpc_server              *pco_iut2 = NULL;
    rcf_rpc_server              *pco_tst1 = NULL;
    rcf_rpc_server              *pco_tst2 = NULL;
    const struct sockaddr       *iut_addr = NULL;
    struct sockaddr_storage      iut_wildcard_addr;
    const struct sockaddr       *tst1_addr = NULL;
    const struct sockaddr       *tst2_addr = NULL;
    const struct sockaddr       *mcast_addr = NULL;
    socklen_t                    mcast_addrlen;
    int                          iut_s1 = -1;
    int                          iut_s2 = -1;
    int                          tst1_s = -1;
    int                          tst2_s = -1;
    char                        *sendbuf1 = NULL;
    char                        *sendbuf2 = NULL;
    char                        *recvbuf = NULL;
    const struct if_nameindex   *iut_if1 = NULL;
    const struct if_nameindex   *iut_if2 = NULL;
    const struct if_nameindex   *tst1_if = NULL;
    const struct if_nameindex   *tst2_if = NULL;
    int                          packet_number;
    int                          i;
    tarpc_joining_method         method;
    struct tarpc_mreqn           mreq;

    mcast_listener_t    listener1;
    te_bool             listener1_created = FALSE;
    mcast_listener_t    listener2;
    te_bool             listener2_created = FALSE;

    int                 opt_val = 1;

    int                 mis_s1 = 0;
    int                 mis_s2 = 0;
    te_bool             diff_ifs = FALSE;
    te_bool             diff_stacks;

    te_bool             use_zc = FALSE;
    te_bool             connect_sock = FALSE;
    te_bool             zero_length = FALSE;
    sockts_socket_func  sock_func;

    int                 detected1 = 0;
    int                 detected2 = 0;
    rpc_msghdr          msg;
    struct rpc_iovec    vector;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_ADDR(pco_iut1, mcast_addr);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(diff_ifs);
    TEST_GET_BOOL_PARAM(diff_stacks);
    TEST_GET_BOOL_PARAM(use_zc);
    TEST_GET_BOOL_PARAM(connect_sock);
    TEST_GET_BOOL_PARAM(zero_length);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    if (diff_stacks)
        TEST_GET_PCO(pco_iut2);
    else
        pco_iut2 = pco_iut1;

    sendbuf1 = te_make_buf_by_len(DATA_BULK);
    sendbuf2 = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = malloc(DATA_BULK));

    vector.iov_base = recvbuf;
    vector.iov_len = vector.iov_rlen = DATA_BULK;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &vector;
    msg.msg_iovlen = msg.msg_riovlen = 1;

    TEST_STEP("Create @c SOCK_DGRAM sockets @p tst1_s and tst2_s on @p pco_tst1 "
              "and @p pco_tst2 respectively. Bind them to @p tst1_addr and @p "
              "tst2_addr and set @c IP_MULTICAST_IF with index of @p tst1_if "
              "and @p tst2_if for those sockets.");
    domain = rpc_socket_domain_by_addr(iut_addr);
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst1, tst1_s, tst1_addr);
    memset(&mreq, 0, sizeof(mreq));
    memcpy(&mreq.multiaddr, te_sockaddr_get_netaddr(mcast_addr),
           sizeof(struct in_addr));
    mreq.type = OPT_MREQN;
    mreq.ifindex = tst1_if->if_index;
    rpc_setsockopt(pco_tst1, tst1_s, RPC_IP_MULTICAST_IF, &mreq);

    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst2, tst2_s, tst2_addr);
    mreq.ifindex = tst2_if->if_index;
    rpc_setsockopt(pco_tst2, tst2_s, RPC_IP_MULTICAST_IF, &mreq);

    CHECK_MCAST_HASH_COLLISION(pco_iut1, pco_tst1, iut_if1, tst1_s,
                               mcast_addr);
    CHECK_MCAST_HASH_COLLISION(pco_iut2, pco_tst2, iut_if2, tst2_s,
                               mcast_addr);

    TEST_STEP("Create @c SOCK_DGRAM socket on @p pco_iut1, "
              "set @c SO_REUSEADDR on it, bind to @p mcast_address, join it to "
              "@p mcast_address group using @p method and then connect it to "
              "@p tst1_addr. Also join it to @p mcast_address group on the second "
              "IUT interface in case of @p diff_join is @c TRUE.");
    iut_s1 = sockts_socket(sock_func, pco_iut1, domain,
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_setsockopt(pco_iut1, iut_s1, RPC_SO_REUSEADDR, &opt_val);
    rpc_bind(pco_iut1, iut_s1, mcast_addr);
    rpc_mcast_join(pco_iut1, iut_s1, mcast_addr, iut_if1->if_index,
                   method);
    if (diff_ifs)
        rpc_mcast_join(pco_iut1, iut_s1, mcast_addr, iut_if2->if_index,
                       method);
    if (connect_sock)
        rpc_connect(pco_iut1, iut_s1, tst1_addr);

    TEST_STEP("Create @c SOCK_DGRAM socket on @p pco_iut2, set @c SO_REUSEADDR "
              "on it, bind to wildcard address with port of @p mcast_address and "
              "then join it to @p mcast_address group using @p method. "
              "If @p diff_join is @c TRUE join it to @p mcast_address group on the "
              "second IUT interface and then connect it to @p tst2_addr.");
    mcast_addrlen = te_sockaddr_get_size(mcast_addr);
    iut_s2 = sockts_socket(sock_func, pco_iut2, domain,
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_setsockopt(pco_iut2, iut_s2, RPC_SO_REUSEADDR, &opt_val);
    if (diff_ifs)
        rpc_bind(pco_iut2, iut_s2, mcast_addr);
    else
    {
        memcpy(&iut_wildcard_addr, mcast_addr, mcast_addrlen);
        te_sockaddr_set_wildcard(SA(&iut_wildcard_addr));
        rpc_bind(pco_iut2, iut_s2, SA(&iut_wildcard_addr));
    }
    rpc_mcast_join(pco_iut2, iut_s2, mcast_addr, iut_if1->if_index,
                   method);
    if (diff_ifs)
        rpc_mcast_join(pco_iut2, iut_s2, mcast_addr, iut_if2->if_index,
                       method);
    if (diff_ifs && connect_sock)
        rpc_connect(pco_iut2, iut_s2, tst2_addr);

    TEST_STEP("Create CSAPs to check that multicast packets are accelerated.");
    if (!use_zc)
    {
        listener1 = mcast_listener_init(pco_iut1, iut_if1, mcast_addr,
                                        NULL, 1);
        listener1_created = TRUE;
        listener2 = mcast_listener_init(pco_iut2, iut_if2, mcast_addr,
                                        NULL, 1);
        listener2_created = TRUE;

        mcast_listen_start(pco_iut1, listener1);
        mcast_listen_start(pco_iut2, listener2);
    }

    TEST_STEP("Send @p packet_number packets from @p tst1_s and tst2_s to "
              "@p mcast_addr. Check that packets from @p tst1_s are received on "
              "@p iut_s1 and on @p iut_s2 in case of shared stack and when "
              "@p diff_ifs is @c FALSE. Check that packets from @p tst1_s are "
              "received on @p iut_s1 and packets from @p tst2_s are received on "
              "@p iut_s2 when @p diff_ifs is @c TRUE.");
    for (i = 0; i < packet_number; i++)
    {
        rpc_sendto(pco_tst1, tst1_s, sendbuf1,
                   zero_length ? 0 : DATA_BULK, 0, mcast_addr);
        MSLEEP(100);
        rpc_sendto(pco_tst2, tst2_s, sendbuf2,
                   zero_length ? 0 : DATA_BULK, 0, mcast_addr);
        MSLEEP(100);

        CHECK_READABLE_GET(pco_iut1, iut_s1, detected1, mis_s1,
                           sendbuf1);
        if (!connect_sock && diff_ifs)
            CHECK_READABLE_GET(pco_iut1, iut_s1, detected1, mis_s1,
                               sendbuf2);
        RPC_CHECK_READABILITY(pco_iut1, iut_s1, FALSE);

        if (!connect_sock && diff_ifs)
            CHECK_READABLE_GET(pco_iut2, iut_s2, detected2, mis_s2,
                               sendbuf1);
        CHECK_READABLE_GET(pco_iut2, iut_s2, detected2, mis_s2,
                           (diff_ifs ? sendbuf2 : sendbuf1));
        RPC_CHECK_READABILITY(pco_iut2, iut_s2, FALSE);
    }
    if (mis_s1 > 0)
        RING_VERDICT("%sulticast packets were missed on iut_s1",
                     (mis_s1 == packet_number) ? "All m" : "M");
    if (mis_s2 > 0)
        RING_VERDICT("%sulticast packets were missed on iut_s2",
                     (mis_s2 == packet_number) ? "All m" : "M");

    if (use_zc)
    {
        if (detected1)
            RING_VERDICT("%sulticast packets were detected on iut_if1",
                         (detected1 == packet_number) ? "All m" : "M");
        if (detected2)
            RING_VERDICT("%sulticast packets were detected on iut_if2",
                         (detected2 == packet_number) ? "All m" : "M");
    }
    else
    {
        rc = mcast_listen_stop(pco_iut1, listener1, NULL);
        if (rc > 0)
            RING_VERDICT("%sulticast packets were detected on iut_if1",
                         (rc == packet_number) ? "All m" : "M");
        rc = mcast_listen_stop(pco_iut1, listener2, NULL);
        if (rc > 0)
            RING_VERDICT("%sulticast packets were detected on iut_if2",
                         (rc == packet_number) ? "All m" : "M");
    }

    TEST_SUCCESS;

cleanup:

    if (listener1_created)
        mcast_listener_fini(pco_iut1, listener1);
    if (listener2_created)
        mcast_listener_fini(pco_iut1, listener2);

    free(sendbuf1);
    free(sendbuf2);
    free(recvbuf);

    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);
    TEST_END;
}
