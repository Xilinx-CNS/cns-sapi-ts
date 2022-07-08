/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_send_too_long_dgram Behaviour of send() function on attempt to send too long datagram
 *
 * @objective Check that a datagram larger than 64K (including all headers)
 *            cannot be sent.
 *
 * @type Conformance.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param dgram_size    Size of the datagram
 * @param func          Function to be used for datagram sending:
 *                          @b send() or @b aio_write()
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 *
 */

#define TE_TEST_NAME  "bnbvalue/func_send_too_long_dgram"

#include "sockapi-test.h"

/* Obtain size of IPv6 header */
#ifdef HAVE_NETINET_IPV6_H
#include <netinet/ipv6.h>
#define IP6_HDR_SIZE    sizeof(struct ip6_hdr)
#else
#define IP6_HDR_SIZE    40
#endif

/* Obtain size of IPv4 header */
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#define IP_HDR_SIZE     sizeof(struct iphdr)
#else
#define IP_HDR_SIZE     20
#endif

/* Obtain size of UDP header */
#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#define UDP_HDR_SIZE    sizeof(struct udphdr)
#else
#define UDP_HDR_SIZE    8
#endif

/* Limit for datagram size */
#define MAX_DGRAM_SIZE  0x10000
/* Limit for IPv4 packet size */
#define MAX_IPV4_SIZE   0x10000

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_tst = NULL;        /* Test host */
    rcf_rpc_server         *pco_iut = NULL;        /* Server under testing */
    const struct sockaddr  *tst_addr = NULL;
    const struct sockaddr  *iut_addr = NULL;
    rpc_send_f              func;

    int                     tst_s = -1;
    int                     iut_s = -1;
    uint8_t                *send_buf = NULL;
    uint8_t                *recv_buf = NULL;
    int                     dgram_size;
    int                     max_payload_size;
    const int               socket_buf_size = MAX_DGRAM_SIZE;
    ssize_t                 sent;
    rpc_socket_domain       domain;

    TEST_START;
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SEND_FUNC(func);
    TEST_GET_INT_PARAM(dgram_size);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Create two @c SOCK_DGRAM sockets: @p tst_s on @p pco_tst and "
              "@p iut_s on @p pco_iut. Connect @p iut_s to @p tst_s.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_iut, iut_s, iut_addr);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_connect(pco_iut, iut_s, tst_addr);

    send_buf = te_make_buf_by_len(dgram_size);
    recv_buf = te_make_buf_by_len(dgram_size);

    TEST_STEP("Try to set @c SO_SNDBUF socket option with value "
              "@c MAX_DGRAM_SIZE on both @p iut_s and @p tst_s. "
              "If failed, ignore.");
    RPC_AWAIT_IUT_ERROR(pco_tst);
    if (rpc_setsockopt(pco_tst, tst_s, RPC_SO_SNDBUF, &socket_buf_size) < 0)
    {
        RING("Could not set SO_SNDBUF on Tester");
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &socket_buf_size) < 0)
    {
        RING("Could not set SO_SNDBUF on IUT");
    }

    /* IPv4 imposes its own limit on total packet length, which is equal
     * to 65536 and includes IPv4 header, leaving less bytes for UDP payload;
     * while IPv6 allows to send "jumbogram" which can be much larger. So in
     * case of IPv4 it is IPv4-limit which should be taken into account here,
     * while in case of IPv6 it is UDP-limit */
    if (domain == RPC_PF_INET)
        max_payload_size = MAX_IPV4_SIZE - IP_HDR_SIZE - UDP_HDR_SIZE;
    else
        max_payload_size = MAX_DGRAM_SIZE - UDP_HDR_SIZE;

    TEST_STEP("If datagram is longer than @b max_payload_size, send datagram "
              "and check errno. It must be @c EMSGSIZE");
    if (dgram_size >= max_payload_size)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        sent = func(pco_iut, iut_s, send_buf, dgram_size, 0);
        if (sent != -1)
            TEST_VERDICT("Datagram is too large, however %s() returned "
                         "%d instead of -1 with EMSGSIZE errno",
                         rpc_send_func_name(func), (int)sent);
        CHECK_RPC_ERRNO(pco_iut, RPC_EMSGSIZE,
                        "Datagram is too large, however");
        TEST_SUCCESS;
    }

    TEST_STEP("Send 1 byte from @p iut_s to @p tst_s in order to create "
              "ARP record for easier long datagram transmission.");
    func(pco_iut, iut_s, send_buf, 1, 0);
    if (rpc_recv(pco_tst, tst_s, recv_buf, dgram_size, 0) != 1 ||
        recv_buf[0] != send_buf[0])
    {
        TEST_FAIL("General problem with sending datagrams");
    }

    TEST_STEP("Send @p dgram_size bytes of data from @p iut_s to @p tst_s.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = func(pco_iut, iut_s, send_buf, dgram_size, 0);
    if (sent != dgram_size)
        TEST_FAIL("Send function result is %d instead %d",
                  (int)sent, dgram_size);
    MSLEEP(50);

    TEST_STEP("If data were successfully sent, receive and verify it. "
              "If verification failed, test is also failed, otherwise test "
              "is passed.");
    if (rpc_recv(pco_tst, tst_s, recv_buf, dgram_size, 0) < dgram_size)
    {
        TEST_FAIL("Some data were lost");
    }

    if (memcmp(send_buf, recv_buf, dgram_size) != 0)
    {
        TEST_FAIL("Data verification error");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    free(send_buf);
    free(recv_buf);

    TEST_END;
}
