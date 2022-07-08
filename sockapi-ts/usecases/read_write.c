/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-read_write The read()/write() operations on the SOCK_STREAM socket
 *
 * @objective This test checks a possibility of the @b read()/write()
 *            operations on BSD compatible sockets by means of creation of the
 *            communication endpoints and generation of the traffic between
 *            them.
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
 *
 * @par Scenario:
 *
 * -# Create @p pco_iut socket of the @c SOCK_STREAM type on the
 *    @p IUT side;
 * -# Create @p pco_tst socket of the @c SOCK_STREAM type on the
 *    @p TESTER side;  
 * -# @b bind() @p pco_iut socket to the local address/port;
 * -# @b bind() @p pco_tst socket to the local address/port;
 * -# Call @p listen() operation on the @p pco_iut socket;
 * -# @b connect() @p pco_tst socket to the @p pco_iut one; 
 * -# Call @b accept() on the @p pco_iut to establish
 *    new connection with @p pco_tst socket;
 * -# Call blocking @b read() on the @p pco_iut @p accepted socket;
 * -# @b write() data to the @p pco_tst socket;
 * -# Wait for @b read() completion on the @p pco_iut @p accepted socket;
 * -# Call @b write() of the obtained data on the @p pco_iut @p accepted 
 *    socket with some delay to run @b read() on the @p pco_tst socket;
 * -# Call @b read() on the @p pco_tst socket to obtain data from 
 *    @p pco_iut @p accepted socket;
 * -# Compare transmitted and received data.
 * -# Close created sockets;
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/read_write"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    int                 iut_s = -1;
    int                 tst_s = -1;
    int                 accepted = -1;
    void               *tx_buf = NULL;
    size_t              tx_buf_len;
    void               *rx_buf = NULL;
    size_t              rx_buf_len;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    struct sockaddr_storage conn_addr;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    sockts_ip6_get_ll_remote_addr(iut_addr, tst_addr, SS(&conn_addr));
    pco_tst->op = RCF_RPC_CALL;
    rpc_connect(pco_tst, tst_s, SA(&conn_addr));
    accepted = rpc_accept(pco_iut, iut_s, NULL, NULL);
    pco_tst->op = RCF_RPC_WAIT;
    rpc_connect(pco_tst, tst_s, SA(&conn_addr));

    pco_iut->op = RCF_RPC_CALL;
    rc = rpc_read_gen(pco_iut, accepted, rx_buf, tx_buf_len, rx_buf_len);
    RPC_WRITE(rc, pco_tst, tst_s, tx_buf, tx_buf_len);

    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_read_gen(pco_iut, accepted, rx_buf, tx_buf_len, rx_buf_len);
    if (rc != (int)tx_buf_len)
        TEST_FAIL("Only part of data received");

    if (memcmp(tx_buf, rx_buf, tx_buf_len))
        TEST_FAIL("Invalid data received");
    
    rc = rpc_write(pco_iut, accepted, rx_buf, tx_buf_len);
    if (rc != (int)tx_buf_len)
    {
        TEST_FAIL("RPC write() on IUT accepted socket does not write "
                  "all data");
    }

    memset(tx_buf, 0, tx_buf_len);
    rc = rpc_read(pco_tst, tst_s, tx_buf, tx_buf_len);
    if (rc != (int)tx_buf_len)
        TEST_FAIL("Only part of data received");

    if (memcmp(tx_buf, rx_buf, tx_buf_len))
        TEST_FAIL("Invalid data received");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, accepted);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
