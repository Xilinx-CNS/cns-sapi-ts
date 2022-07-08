/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-imr_ifindex_vs_imr_address IP_ADD_MEMBERSHIP behaviour with incorrect ip_mreqn parameter.
 *
 * @objective Check that imr_ifindex has higher priority for IP_ADD_MEMBERSHIP
 *            than imr_address.
 *
 * @type Conformance.
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst1          PCO on Tester1
 * @param pco_tst2          PCO on Tester2
 * @param iut_if1           Interface on IUT connected to Tester1
 * @param tst1_if           Interface on Tester1
 * @param iut_if2           Interface on IUT connected to Tester2
 * @param tst2_if           Interface on Tester2
 * @param iut_addr1         Address on @p iut_if1
 * @param mcast_addr        Multicast address
 * @param data_len          Size of datagram
 * @param packet_number     Number of datagrams to send for reliability.
 * @param sock_func         Socket creation function.
 *
 * @par Scenario:
 *
 * -# Create datagram sockets: @p tst1_s on Tester 1
 *    and @p tst2_s on Tester 2.
 * -# Create a datagram socket @p iut_s on @p pco_iut. 
 * -# Bind it to @p mcast_addr.
 * -# Call @b setsockopt(IP_ADD_MEMBERSHIP) with ip_mreqn structure
 *    as parameter:
 *    imr_multiaddr = @p mcast_addr,
 *    imr_address = @p iut_addr1,
 *    imr_ifindex = index of @p iut_if2.
 *    If it fails, it means that the system prevent incorrect setting,
 *    test is passed.
 * -# Repeat @p packet_number times for reliability:
 *     -# Send a datagram from @p tst1_s to @p mcast_addr.
 *     -# Send a datagram from @p tst2_s to @p mcast_addr.
 *     -# Check that only datagram from @p tst2_s was received.
 *   
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/imr_ifindex_vs_imr_address"

#include "sockapi-test.h"
#include "mcast_lib.h"

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
    struct tarpc_mreqn     mreq;
    
    struct sockaddr_storage     from_addr;
    socklen_t                   from_addrlen = sizeof(from_addr);
    const struct if_nameindex   *iut_if1;
    const struct if_nameindex   *tst1_if;
    const struct if_nameindex   *iut_if2;
    const struct if_nameindex   *tst2_if;
 
    char                  *sendbuf = NULL;
    char                  *recvbuf = NULL;
    int                    data_len;
    int                    i;
    int                    packet_number;

    mcast_listener_t listener1;
    mcast_listener_t listener2;
    int              detected1 = 0;
    int              detected2 = 0;

    te_bool             use_zc;
    sockts_socket_func  sock_func;

    rpc_msghdr          msg;
    struct rpc_iovec    vector;

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
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    domain = rpc_socket_domain_by_addr(iut_addr1);

    sendbuf = te_make_buf_by_len(2 * data_len);
    CHECK_NOT_NULL(recvbuf = malloc(2 * data_len));

    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    mreq.address = SIN(tst1_addr)->sin_addr.s_addr;

    rpc_setsockopt(pco_tst1, tst1_s, RPC_IP_MULTICAST_IF, &mreq);
    mreq.address = SIN(tst2_addr)->sin_addr.s_addr;

    rpc_setsockopt(pco_tst2, tst2_s, RPC_IP_MULTICAST_IF, &mreq);
    /* Wait for multicast filters to be added */
    TAPI_WAIT_NETWORK;

    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst1, iut_if1,
                               tst1_s, mcast_addr);
    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst2, iut_if2,
                               tst2_s, mcast_addr);

    iut_s = sockts_socket(sock_func, pco_iut, domain,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    FILL_TARPC_MREQN(mreq, mcast_addr, iut_addr1, iut_if2->if_index);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (rpc_setsockopt(pco_iut, iut_s, RPC_IP_ADD_MEMBERSHIP, &mreq) != 0)
    {
        VERB("System does not allow interface address and index mismatch");
        TEST_SUCCESS;
    }

    rpc_bind(pco_iut, iut_s, mcast_addr);

    if (!use_zc)
    {
        listener1 = mcast_listener_init(pco_iut, iut_if1, mcast_addr,
                                        tst1_addr, 1);
        listener2 = mcast_listener_init(pco_iut, iut_if2, mcast_addr,
                                        tst2_addr, 1);
    }

    for (i = 0; i < packet_number; i++)
    {
        if (!use_zc)
        {
            mcast_listen_start(pco_iut, listener1);
            mcast_listen_start(pco_iut, listener2);
        }
        /* Datagrams will be distinguished by size */
        rpc_sendto(pco_tst1, tst1_s, sendbuf, data_len, 0, mcast_addr);

        rpc_sendto(pco_tst2, tst2_s, sendbuf, 2 * data_len, 0, mcast_addr);

        MSLEEP(100);
        if (use_zc)
        {
            memset(&msg, 0, sizeof(msg));
            memset(&from_addr, 0, from_addrlen);
            msg.msg_name = &from_addr;
            msg.msg_namelen = msg.msg_rnamelen = from_addrlen;
            vector.iov_base = recvbuf;
            vector.iov_len = vector.iov_rlen = 2 * data_len;
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
                if (rc > 0 && !detected2)
                {
                    detected2 = 1;
                    RING_VERDICT("Multicast packet was detected by "
                                 "system on iut_if2");
                }
            }
        }
        else
        {
            rc = mcast_listen_stop(pco_iut, listener1, NULL);
            if (rc > 0 && !detected1)
            {
                RING_VERDICT("Multicast packet was detected by system on "
                             "iut_if1");
                detected1 = 1;
            }
            rc = mcast_listen_stop(pco_iut, listener2, NULL);
            if (rc > 0 && !detected2)
            {
                RING_VERDICT("Multicast packet was detected by system on "
                             "iut_if2");
                detected2 = 1;
            }

            memset(&from_addr, 0, from_addrlen);
            rc = rpc_recvfrom(pco_iut, iut_s, recvbuf, 2 * data_len, 0,
                              SA(&from_addr), &from_addrlen);
        }
        if (rc == data_len)
        {
            TEST_FAIL("The imr_address was not ignored despite imr_ifindex is from "
                       "other interface");
        }
        else if (rc != 2 * data_len)
        {
            TEST_FAIL("Unexpected datagram size: %d instead of %d or %d ",
                      rc, data_len, 2 * data_len);
        }

        RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);
    }

    TEST_SUCCESS;

cleanup:
    if (!use_zc)
    {
        mcast_listener_fini(pco_iut, listener1);
        mcast_listener_fini(pco_iut, listener2);
    }
    free(sendbuf);
    free(recvbuf);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
