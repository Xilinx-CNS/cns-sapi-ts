/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-wildcard_server_passive_opening Creation of the several connections requested through different host addresses
 *
 * @objective Check that wildcard server establishes connections on
 *            separate addresses according to remote peer requests.
 *
 * @type Conformance, compatibility
 *
 * @param env   Private set of environments with three tester RPC servers
 *              which are spread around three hosts (each environment
 *              is iterated with IPv4/IPv6 addresses):
 *              -# @p pco_tst1 and @p pco_tst2 located on two different tester
 *              hosts, @p pco_tst3 on IUT;
 *              -# @p pco_tst1 and @p pco_tst2 located on two different tester
 *              hosts, @p pco_tst3 (accelerated) on IUT;
 *              -# the same as the first env, but tst3 uses not loopback but
 *              unicast network address;
 *              -# the same as the second env, but tst3 uses not loopback but
 *              unicast network address;
 *              -# @p pco_tst1 is on one tester host, @p pco_tst2 and
 *              @p pco_tst3 are on another tester host.
 *
 * @par Scenario:
 *
 * -# Create @p iut_s as a stream server socket on @p pco_iut,
 *    @b bind() it to wildcard IP address and call @b listen() on it;
 * -# Create @p tst1_s, @p tst2_s and @p pco_tst3 sockets on @p pco_tst1,
 *    @p pco_tst2 and @p pco_tst3 appropriately;
 * -# Try to connect the @p tst1_s, @p tst2_s and tst3_s sockets to the
 *    @p pco_iut server using @p iut1_addr, @p iut2_addr and
 *    @p iut3_addr appropriately;
 * -# Check that accepted connections is established with correct addresses
 *    by means of call @b getsockname() on the appropriate @p acceptedX_s
 *    socket;
 * -# Prepare three buffers by means of @b te_make_buf();
 * -# Send prepared data through @p tst1_s, @p tst2_s and @p tst3_s;
 * -# Check correctness of the data received on the @p pco_iut;
 * -# @b close() created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/wildcard_server_passive_opening"

#include "sockapi-test.h"

#define DATA_BULK 1000

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut;
    rcf_rpc_server              *pco_tst1;
    rcf_rpc_server              *pco_tst2;
    rcf_rpc_server              *pco_tst3;

    int                          iut_s       = -1;
    int                          accepted1_s = -1;
    int                          accepted2_s = -1;
    int                          accepted3_s = -1;
    int                          tst1_s = -1;
    int                          tst2_s = -1;
    int                          tst3_s = -1;

    const struct sockaddr       *iut1_addr;
    const struct sockaddr       *iut2_addr;
    const struct sockaddr       *iut3_addr;

    const struct sockaddr       *wild_addr;

    struct sockaddr_storage      retaddr;
    socklen_t                    retaddr_len;

    int                          s_len1;
    int                          s_len2;
    int                          s_len3;
    int                          r_len1;
    int                          r_len2;
    int                          r_len3;

    void                        *tx_buf1 = NULL;
    void                        *tx_buf2 = NULL;
    void                        *tx_buf3 = NULL;
    void                        *rx_buf1 = NULL;
    void                        *rx_buf2 = NULL;
    void                        *rx_buf3 = NULL;
    
    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_PCO(pco_tst3);

    TEST_GET_ADDR_NO_PORT(iut1_addr);
    TEST_GET_ADDR_NO_PORT(iut2_addr);
    TEST_GET_ADDR_NO_PORT(iut3_addr);

    TEST_GET_ADDR(pco_iut, wild_addr);
    
    domain = rpc_socket_domain_by_addr(iut1_addr);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, wild_addr);

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    SIN(iut1_addr)->sin_port = SIN(wild_addr)->sin_port;
    SIN(iut2_addr)->sin_port = SIN(wild_addr)->sin_port;
    SIN(iut3_addr)->sin_port = SIN(wild_addr)->sin_port;

    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst3_s = rpc_socket(pco_tst3, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_connect(pco_tst1, tst1_s, iut1_addr);
    accepted1_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    rpc_connect(pco_tst2, tst2_s, iut2_addr);
    accepted2_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    rpc_connect(pco_tst3, tst3_s, iut3_addr);
    accepted3_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    retaddr_len = sizeof(retaddr);
    rpc_getsockname(pco_iut, accepted1_s, SA(&retaddr), &retaddr_len);

    if (te_sockaddrcmp(SA(&retaddr), retaddr_len,
                       iut1_addr, te_sockaddr_get_size(iut1_addr)) != 0)
    {
        TEST_FAIL("Incorrect address");
    }

    retaddr_len = sizeof(retaddr);
    rpc_getsockname(pco_iut, accepted2_s, SA(&retaddr), &retaddr_len);

    if (te_sockaddrcmp(SA(&retaddr), retaddr_len,
                       iut2_addr, te_sockaddr_get_size(iut2_addr)) != 0)
    {
        TEST_FAIL("Incorrect address");
    }

    retaddr_len = sizeof(retaddr);
    rpc_getsockname(pco_iut, accepted3_s, SA(&retaddr), &retaddr_len);

    if (te_sockaddrcmp(SA(&retaddr), retaddr_len,
                       iut3_addr, te_sockaddr_get_size(iut3_addr)) != 0)
    {
        TEST_FAIL("Incorrect address");
    }

    tx_buf1 = te_make_buf_by_len(DATA_BULK);
    tx_buf2 = te_make_buf_by_len(DATA_BULK);
    tx_buf3 = te_make_buf_by_len(DATA_BULK);
    rx_buf1 = te_make_buf_by_len(DATA_BULK);
    rx_buf2 = te_make_buf_by_len(DATA_BULK);
    rx_buf3 = te_make_buf_by_len(DATA_BULK);

    RPC_SEND(s_len1, pco_tst1, tst1_s, tx_buf1, DATA_BULK, 0);

    RPC_SEND(s_len2, pco_tst2, tst2_s, tx_buf2, DATA_BULK, 0);

    RPC_SEND(s_len3, pco_tst3, tst3_s, tx_buf3, DATA_BULK, 0);

    r_len1 = rpc_recv(pco_iut, accepted1_s, rx_buf1, DATA_BULK, 0);
    if (r_len1 != s_len1)
    {
        TEST_FAIL("Received only %d bytes instead of %d", r_len1, s_len1);
    }

    r_len2 = rpc_recv(pco_iut, accepted2_s, rx_buf2, DATA_BULK, 0);
    if (r_len2 != s_len2)
    {
        TEST_FAIL("Received only %d bytes instead of %d", r_len2, s_len2);
    }

    r_len3 = rpc_recv(pco_iut, accepted3_s, rx_buf3, DATA_BULK, 0);
    if (r_len3 != s_len3)
    {
        TEST_FAIL("Received only %d bytes instead of %d", r_len3, s_len3);
    }

    if (memcmp(tx_buf1, rx_buf1, DATA_BULK) != 0)
        TEST_FAIL("Recieved data wasn't correct");

    if (memcmp(tx_buf2, rx_buf2, DATA_BULK) != 0)
        TEST_FAIL("Recieved data wasn't correct");

    if (memcmp(tx_buf3, rx_buf3, DATA_BULK) != 0)
        TEST_FAIL("Recieved data wasn't correct");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, accepted1_s);
    CLEANUP_RPC_CLOSE(pco_iut, accepted2_s);
    CLEANUP_RPC_CLOSE(pco_iut, accepted3_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_tst3, tst3_s);

    free(tx_buf1);
    free(tx_buf2);
    free(tx_buf3);

    free(rx_buf1);
    free(rx_buf2);
    free(rx_buf3);

    TEST_END;
}
