/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-getsockname_getpeername The getsockname()/getpeername() operations on BSD compatible sockets
 *
 * @objective Test on reliability of @b getsockname()/getpeername()
 *            operations on BSD compatible sockets.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_p2p_ip6ip4mapped
 *                  - @ref arg_types_env_p2p_ip6
 *                  - @ref arg_types_env_p2p_ip6linklocal
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 * @param sock_type     Socket type:
 *                      - @c SOCK_STREAM
 *                      - @c SOCK_DGRAM
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of the @p sock_type type on the
 *    @p IUT side;
 * -# Create @p pco_tst socket of the @p sock_type type on the
 *    @p TESTER side;
 * -# @b bind() @p pco_tst socket to the local address/port;
 * -# If @p sock_type is @c SOCK_STREAM:
 *      - Call @b listen() on the @p pco_tst socket;
 *      - @b connect() @p pco_iut socket to the @p pco_tst one;
 *      - Call @b accept() on the @p pco_tst socket to establish
 *        new connection with @p pco_iut socket;
 * -# If @p sock_type is @c SOCK_DGRAM:
 *      - @b connect() @p pco_iut socket to the @p pco_tst one;
 *      - @b connect() @p pco_tst socket to the @p pco_iut one;
 * -# Call @b getsockname()/getpeername() on the @p pco_iut socket
 *    to retrieve local/remote address of the connection end;
 * -# Check data returned by @b getsockname()/getpeername() on the 
 *    @p pco_iut socket;
 * -# Call @b sendto() on the @p pco_iut socket with right two last
 *    parameters with some delay for running of the @b recv() on the
 *    @p pco_tst @p accepted socket;
 * -# Call @b recv() on the @p pco_tst @p accepted socket; 
 * -# Compare transmitted and received data.
 * -# Close created sockets on the both sides;
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/getsockname_getpeername"

#include "sockapi-test.h"


#define TST_SENDRECV_FLAGS    0


int
main(int argc, char *argv[])
{
    int             err = 0;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             accepted = -1;
    void           *tx_buf = NULL;
    size_t          tx_buf_len;
    void           *rx_buf = NULL;
    size_t          rx_buf_len;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    struct sockaddr_storage iut_conn_addr;
    struct sockaddr_storage tst_conn_addr;

    rpc_socket_type         sock_type;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);
    sockts_ip6_get_ll_remote_addr(tst_addr, iut_addr,
                                  SS(&tst_conn_addr));
    sockts_ip6_get_ll_remote_addr(iut_addr, tst_addr,
                                  SS(&iut_conn_addr));
    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

        pco_iut->op = RCF_RPC_CALL;
        rpc_connect(pco_iut, iut_s, SA(&tst_conn_addr));

        accepted = rpc_accept(pco_tst, tst_s, NULL, NULL);

        pco_iut->op = RCF_RPC_WAIT;
        rpc_connect(pco_iut, iut_s, SA(&tst_conn_addr));
    }
    else
    {
        rpc_connect(pco_iut, iut_s, SA(&tst_conn_addr));
        rpc_connect(pco_tst, tst_s, SA(&iut_conn_addr));
        accepted = tst_s;
    }

    /*
     * Check local/peer addresses by means of both 
     * getsockname() and getpeername() socket API calls.
     */
    rc = sockts_compare_sock_peer_name(pco_iut, iut_s,
                                       pco_tst, accepted);
    if (rc != 0)
        TEST_FAIL("iut_s local address is not validated");

    rc = sockts_compare_sock_peer_name(pco_tst, accepted,
                                       pco_iut, iut_s);
    if (rc != 0)
        TEST_FAIL("iut_s remote address is not validated");

    pco_tst->op = RCF_RPC_CALL;
    rpc_recv_gen(pco_tst, accepted, rx_buf, 
                 tx_buf_len, TST_SENDRECV_FLAGS,  rx_buf_len);

    rc = rpc_sendto(pco_iut, iut_s, tx_buf, tx_buf_len, TST_SENDRECV_FLAGS,
                    NULL);
    if (rc != (int)tx_buf_len)
    {
        TEST_FAIL("RPC sendto() on IUT failed RPC_errno=%X",
                  TE_RC_GET_ERROR(err));
    }

    pco_tst->op = RCF_RPC_WAIT;
    rc = rpc_recv_gen(pco_tst, accepted, rx_buf, tx_buf_len, 
                      TST_SENDRECV_FLAGS, rx_buf_len);

    if (rc != (int)tx_buf_len)
        TEST_FAIL("Only part of data received");

    if (memcmp(tx_buf, rx_buf, tx_buf_len))
        TEST_FAIL("Invalid data received");

    TEST_SUCCESS;

cleanup:
    if (sock_type == RPC_SOCK_STREAM)
        CLEANUP_RPC_CLOSE(pco_tst, accepted);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
