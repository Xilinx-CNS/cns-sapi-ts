/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page sockopts-type Usage of IPV6_V6ONLY socket option.
 *
 * @objective Check that @c IPV6_V6ONLY socket option works properly..
 *
 * @type conformance
 *
 * @reference @ref RFC2553
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param iut_s         INET6 socket on IUT
 * @param tst_s         INET6 socket on Tester
 * @param iut_addr      IPv4 address on IUT
 * @param iut_addr6     IPv6 address on IUT
 * 
 * @par Test sequence:
 * -# Open datagram socket @p iut_s of family @p PF_INET6 on IUT.
 * -# Open datagram socket @p tst_s of family @p PF_INET6 on Tester.
 * -# Bind @p iut_s to @c IPv6 wildcard address.
 * -# Get @c IPV6_V6ONLY option value on @p pco_iut.
 *    Make a warning if it is non-zero.
 * -# Set @c IPV6_V6ONLY option value to @c TRUE.
 * -# Check that only IPv6 datagrams can be transferred from @p tst_s to
 *    @p iut_s.
 * -# Set @c IPV6_V6ONLY option value to @c FALSE.
 * -# Check that again both IPv6 and IPv4 datagrams can be transferred from
 *    @p tst_s to @p iut_s.
 * -# Close @p iut_s and @p tst_s.
 * 
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ipv6_only"

#include "sockapi-test.h"

#define DATA_BULK       200

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             opt_val;
    uint8_t        *sendbuf = NULL;
    uint8_t        *recvbuf = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *iut_addr6 = NULL;
    struct sockaddr_in6    wild_addr;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR_NO_PORT(iut_addr);

    sendbuf = (uint8_t *)te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = (uint8_t *)malloc(DATA_BULK));
    
    iut_s = rpc_socket(pco_iut, RPC_PF_INET6, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    tst_s = rpc_socket(pco_tst, RPC_PF_INET6, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    rpc_getsockopt(pco_iut, iut_s, RPC_IPV6_V6ONLY, &opt_val);
    if (opt_val != 0)
    {
        WARN("IPV6_V6ONLY option is set to TRUE by default");
    }

    opt_val = FALSE;
    rpc_setsockopt(pco_iut, iut_s, RPC_IPV6_V6ONLY, &opt_val);
 
    memset(&wild_addr, 0, sizeof(wild_addr));
    wild_addr.sin6_family = AF_INET6;
    te_sockaddr_set_wildcard(SA(&wild_addr));
    SIN(iut_addr)->sin_port = wild_addr.sin6_port = SIN6(iut_addr6)->sin6_port;    
    rpc_bind(pco_iut, iut_s, SA(&wild_addr));

    rpc_sendto(pco_tst, tst_s, sendbuf, DATA_BULK, 0, iut_addr6);
    SLEEP(5);
    rpc_recv(pco_iut, iut_s, recvbuf, DATA_BULK, 0);
    if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
    {
        TEST_FAIL("Data verification failed");
    }

    rpc_sendto(pco_tst, tst_s, sendbuf, DATA_BULK, 0, iut_addr);
    SLEEP(5);
    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);

    opt_val = FALSE;
    rpc_setsockopt(pco_iut, iut_s, RPC_IPV6_V6ONLY, &opt_val);
    rpc_sendto(pco_tst, tst_s, sendbuf, DATA_BULK, 0, iut_addr6);
    SLEEP(5);
    rpc_recv(pco_iut, iut_s, recvbuf, DATA_BULK, 0);
    if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
    {
        TEST_FAIL("Data verification failed");
    }

    rpc_sendto(pco_tst, tst_s, sendbuf, DATA_BULK, 0, iut_addr);
    SLEEP(5);
    rpc_recv(pco_iut, iut_s, recvbuf, DATA_BULK, 0);
    if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
    {
        TEST_FAIL("Data verification failed");
    }

    TEST_SUCCESS;
cleanup:
    free(sendbuf);
    free(recvbuf);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

