/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-server Classical server functionality involved main socket operations
 *
 * @objective Test on reliability of the standard operations
 *            on BSD compatible sockets as server application.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_server2clients
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of the @c SOCK_STREAM type on the @p IUT side;
 * -# Create @p tst_1 socket of the @c SOCK_STREAM type on the @p TESTER side;
 * -# Create @p tst_2 socket of the @c SOCK_STREAM type on the @p TESTER side;
 * -# @b bind() @p pco_iut socket to the local address/port;
 * -# Call @b listen() on the @p pco_iut socket;
 * -# Call @b accept() on the @p pco_iut to establish
 *    new connection with @p tst_1 socket;
 * -# @b connect() @p tst_1 socket to the @p pco_iut one;
 * -# Call @b getsockname()/getpeername() on @p iut_1 @p accepted socket;
 * -# Validate information returned by @b getsockname()/getpeername()
 *    operation on @p iut_1 @p accepted socket;
 * -# Call @b accept() on the @p pco_iut to establish
 *    new connection with @p tst_2 socket;
 * -# @b connect() @p tst_2 socket to the @p pco_iut one;
 * -# Call @b getsockname()/getpeername() on @p iut_2 @p accepted socket;
 * -# Validate information returned by @b getsockname()/getpeername()
 *    operation on @p iut_2 @p accepted socket;
 * -# Call blocking @b recv() on the @p iut_1 @p accepted socket;   
 * -# @b send() data to the @p tst_1 socket;
 * -# Call blocking @b recv() on the @p iut_2 @p accepted socket;
 * -# @b send() data to the @p tst_2 socket;
 * -# Call @b send() of the obtained data on the @p iut_1 @b accepted
 *    socket with some delay to run @b recv() on the @p tst_1 socket;
 * -# Call @b recv() on the @p tst_1 socket to obtain data from
 *    @p iut_1 @p accepted socket;
 * -# Call @b send() of the obtained data on the @p iut_2 @b accepted
 *    socket with some delay to run @b recv() on the @p tst_2 socket;
 * -# Call @b recv() on the @p tst_2 socket to obtain data from
 *    @p iut_2 @p accepted socket;
 * -# Close created sockets on the both sides;
 * -# Compare transmitted and received data.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/server"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    int             err;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    int             iut_s = -1;
    int             tst1_s = -1;
    int             tst2_s = -1;
    int             accepted1 = -1;
    int             accepted2 = -1;
    void           *tx_buf1 = NULL;
    size_t          tx_buf1_len;
    void           *rx_buf1 = NULL;
    size_t          rx_buf1_len;
    void           *tx_buf2 = NULL;
    size_t          tx_buf2_len;
    void           *rx_buf2 = NULL;
    size_t          rx_buf2_len;

    struct sockaddr_storage addr;
    socklen_t               addrlen;
    struct sockaddr_storage addr_tst;
    socklen_t               addrlen_tst;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *host2_addr;
    const struct sockaddr  *aux_addr;
    struct sockaddr_storage conn_addr;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    if (sockts_is_addr_ip6_linklocal(iut_addr))
        TEST_GET_ADDR(pco_tst2, host2_addr);

    tx_buf1 = sockts_make_buf_stream(&tx_buf1_len);
    rx_buf1 = te_make_buf_min(tx_buf1_len, &rx_buf1_len);
    tx_buf2 = sockts_make_buf_stream(&tx_buf2_len);
    rx_buf2 = te_make_buf_min(tx_buf2_len, &rx_buf2_len);

    if ((iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                            RPC_PROTO_DEF, TRUE, FALSE,
                                            iut_addr)) < 0)
        TEST_FAIL("Cannot create SOCK_STREAM 'iut_s' socket");
    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    sockts_ip6_get_ll_remote_addr(iut_addr, host2_addr, &conn_addr);
    if (sockts_is_addr_ip6_linklocal(iut_addr) &&
        strcmp(pco_tst1->ta, pco_iut->ta) != 0)
        aux_addr = SA(&conn_addr);
    else
        aux_addr = iut_addr;

    pco_tst1->op = RCF_RPC_CALL;
    rpc_connect(pco_tst1, tst1_s, aux_addr);

    addrlen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, accepted1, SA(&addr), &addrlen);
    if (rc != -1)
    {
        err = RPC_ERRNO(pco_iut);
        if (err != RPC_ENOTCONN)
        {
            ERROR("RPC getsockname() unexpected behaviour");
        }
        TEST_STOP;
    }

    addrlen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, accepted1, SA(&addr), &addrlen);
    if (rc != -1)
    {
        err = RPC_ERRNO(pco_iut);
        if (err != RPC_ENOTCONN)
        {
            ERROR("RPC getpeername() unexpected behaviour");
        }
        TEST_STOP;
    }

    addrlen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    accepted1 = rpc_accept(pco_iut, iut_s, SA(&addr), &addrlen);

    pco_tst1->op = RCF_RPC_WAIT;
    rpc_connect(pco_tst1, tst1_s, aux_addr);

    addrlen_tst = sizeof(addr_tst);
    memset(&addr_tst, 0, sizeof(addr_tst));
    rpc_getsockname(pco_tst1, tst1_s, SA(&addr_tst), &addrlen_tst);

    /* In case of link local IP6 address when @p pco_iut and @p pco_tst are
     * on different hosts, @b accept() function returns @p scope_id for
     * interface on host with @p pco_iut, but @p addr_tst contains
     * @p scope_id for interface on host with @p pco_tst. So, @p scope_id
     * should be fixed for further comparison.
     */
    if (sockts_is_addr_ip6_linklocal(iut_addr))
        SIN6(&addr_tst)->sin6_scope_id = SIN6(iut_addr)->sin6_scope_id;
    if (te_sockaddrcmp(SA(&addr), addrlen, SA(&addr_tst), addrlen_tst))
    {
        TEST_FAIL("Accepted address does not match with connected one");
    }

    rc = sockts_compare_sock_peer_name(pco_iut, accepted1,
                                       pco_tst1, tst1_s);
    if (rc != 0)
        TEST_FAIL("accepted1 local address is not validated");

    rc = sockts_compare_sock_peer_name(pco_tst1, tst1_s,
                                       pco_iut, accepted1);
    if (rc != 0)
        TEST_FAIL("accepted1 remote address is not validated");

    if (sockts_is_addr_ip6_linklocal(iut_addr) &&
        strcmp(pco_tst2->ta, pco_iut->ta) != 0)
        aux_addr = SA(&conn_addr);
    else
        aux_addr = iut_addr;
    pco_tst2->op = RCF_RPC_CALL;
    rpc_connect(pco_tst2, tst2_s, aux_addr);

    addrlen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, accepted2, SA(&addr), &addrlen);
    if (rc != -1)
    {
        if (RPC_ERRNO(pco_iut) != RPC_ENOTCONN)
            TEST_FAIL("RPC getsockname() unexpected behaviour");
    }

    addrlen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, accepted2, SA(&addr), &addrlen);
    if (rc != -1)
    {
        if (RPC_ERRNO(pco_iut) != RPC_ENOTCONN)
            TEST_FAIL("RPC getpeername() unexpected behaviour");
    }

    addrlen = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    accepted2 = rpc_accept(pco_iut, iut_s, SA(&addr), &addrlen);

    pco_tst2->op = RCF_RPC_WAIT;
    rpc_connect(pco_tst2, tst2_s, aux_addr);

    addrlen_tst = sizeof(addr_tst);
    memset(&addr_tst, 0, sizeof(addr_tst));
    rpc_getsockname(pco_tst2, tst2_s, SA(&addr_tst), &addrlen_tst);
    if (sockts_is_addr_ip6_linklocal(iut_addr))
        SIN6(&addr_tst)->sin6_scope_id = SIN6(iut_addr)->sin6_scope_id;
    if (te_sockaddrcmp(SA(&addr), addrlen, SA(&addr_tst), addrlen_tst))
    {
        TEST_FAIL("Accepted address does not match with connected one");
    }

    rc = sockts_compare_sock_peer_name(pco_iut, accepted2,
                                       pco_tst2, tst2_s);
    if (rc != 0)
        TEST_FAIL("accepted2 local address is not validated");

    rc = sockts_compare_sock_peer_name(pco_tst2, tst2_s,
                                       pco_iut, accepted2);
    if (rc != 0)
        TEST_FAIL("accepted2 remote address is not validated");

    pco_iut->op = RCF_RPC_CALL;
    rpc_recv_gen(pco_iut, accepted1, rx_buf1, tx_buf1_len, 0, rx_buf1_len);

    rc = rpc_send(pco_tst1, tst1_s, tx_buf1, tx_buf1_len, 0);
    if (rc != (int)tx_buf1_len)
    {
        err = RPC_ERRNO(pco_tst1);
        TEST_FAIL("RPC send() on TESTER tst1_s  failed RPC_errno=%X",
                  TE_RC_GET_ERROR(err));
    }

    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recv_gen(pco_iut, accepted1, rx_buf1, tx_buf1_len, 0,
                      rx_buf1_len);
    if (rc != (int)tx_buf1_len)
    {
        TEST_FAIL("Only part of data received");
    }
    if (memcmp(tx_buf1, rx_buf1, tx_buf1_len) != 0)
    {
        TEST_FAIL("Invalid data received (tx_buf1/rx_buf1)");
    }

    pco_iut->op = RCF_RPC_CALL;
    rc = rpc_recv_gen(pco_iut, accepted2, rx_buf2, tx_buf2_len, 0,
                      rx_buf2_len);

    rc = rpc_send(pco_tst2, tst2_s, tx_buf2, tx_buf2_len, 0);
    if (rc != (int)tx_buf2_len)
    {
        err = RPC_ERRNO(pco_tst2);
        TEST_FAIL("RPC send() on TESTER tst2_s failed RPC_errno=%X",
                  TE_RC_GET_ERROR(err));
    }

    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recv_gen(pco_iut, accepted2, rx_buf2, tx_buf2_len, 0,
                      rx_buf2_len);
    if (rc != (int)tx_buf2_len)
    {
        TEST_FAIL("Only part of data received (tx_buf2)");
    }
    if (memcmp(tx_buf2, rx_buf2, tx_buf2_len) != 0)
    {
        TEST_FAIL("Invalid data received (tx_buf2/rx_buf2)");
    }

    rc = rpc_send(pco_iut, accepted1, rx_buf1, tx_buf1_len, 0);
    if (rc != (int)tx_buf1_len)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC send() on IUT accepted1 socket failed "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    rc = rpc_recv_gen(pco_tst1, tst1_s, rx_buf1, tx_buf1_len, 0,
                      rx_buf1_len);
    if (rc != (int)tx_buf1_len)
    {
        TEST_FAIL("Only part of data received (tst1_s) ");
    }
    if (memcmp(tx_buf1, rx_buf1, tx_buf1_len) != 0)
    {
        TEST_FAIL("Invalid data received (tst1_s)");
    }

    rc = rpc_send(pco_iut, accepted2, rx_buf2, tx_buf2_len, 0);
    if (rc != (int)tx_buf2_len)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC send() on IUT accepted2 socket failed "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    rc = rpc_recv_gen(pco_tst2, tst2_s, rx_buf2, tx_buf2_len, 0,
                      rx_buf2_len);
    if (rc != (int)tx_buf2_len)
    {
        TEST_FAIL("Only part of data received (tst2_s) ");
    }
    if (memcmp(tx_buf2, rx_buf2, tx_buf2_len) != 0)
    {
        TEST_FAIL("Invalid data received (tst2_s)");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, accepted1);
    CLEANUP_RPC_CLOSE(pco_iut, accepted2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    free(tx_buf1);
    free(rx_buf1);
    free(tx_buf2);
    free(rx_buf2);

    TEST_END;
}
