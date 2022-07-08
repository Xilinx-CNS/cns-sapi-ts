/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-readv_writev Standard readv()/writev() I/O operations on the SOCK_STREAM socket
 *
 * @objective This test checks a possibility of the standard
 *            @b readv()/writev() I/O operations on BSD compatible sockets by
 *            means of creation of the communication endpoints and generation
 *            of the traffic between them.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_p2p_ip6ip4mapped
 *                  - @ref arg_types_env_p2p_ip6
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 *
 * @par Scenario:
 *
 * -# Prepare multiple buffers for @b readv()/writev() operations on
 *    the both @p IUT side and @p TESTER side;
 * -# Create @p pco_iut socket of the @c SOCK_STREAM type on the
 *    @p IUT side;
 * -# Create @p pco_tst socket of the @c SOCK_STREAM type on the
 *    @p TESTER side;
 * -# @b bind() @p pco_iut socket to the local address/port;
 * -# @b bind() @p pco_tst socket to the local address/port;
 * -# Call @b listen() on the @p pco_tst socket;
 * -# Call @b accept() on the @p pco_tst socket to establish
 *    new connection with @p pco_iut socket;
 * -# @b connect() the @p pco_iut socket to the @p pco_tst one with some
 * -# Call blocking @b readv() on the @p pco_iut socket;
 * -# @b writev() data to the @p pco_tst @p accepted socket;
 * -# Wait for @b readv() completion on the @p pco_iut socket;
 * -# Call @b writev() of the obtained data on the @p pco_iut socket
 *    with some delay to run @b readv() on the @p pco_tst @p accepted
 *    socket;
 * -# Call @b readv() on the @p pco_tst @p accepted socket to obtain
 *    data from @p pco_iut socket;
 * -# Compare transmitted and received data;
 * -# Close created sockets on the both sides;
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/readv_writev"

#include "sockapi-test.h"


#define TST_VEC               4


int
main(int argc, char *argv[])
{
    int             i;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             accepted = -1;
    ssize_t         sent, received;

    struct rpc_iovec tx_vector[TST_VEC] = {};
    struct rpc_iovec rx_vector[TST_VEC] = {};
    struct rpc_iovec rrx_vector[TST_VEC] = {};

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    sockts_make_vector(tx_vector, rx_vector, rrx_vector, TST_VEC);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    pco_tst->op = RCF_RPC_CALL;
    rpc_accept(pco_tst, tst_s, NULL, NULL);
    rpc_connect(pco_iut, iut_s, tst_addr);
    pco_tst->op = RCF_RPC_WAIT;
    accepted = rpc_accept(pco_tst, tst_s, NULL, NULL);

    pco_iut->op = RCF_RPC_CALL;
    rpc_readv(pco_iut, iut_s, rx_vector, TST_VEC);
    sent = rpc_writev(pco_tst, accepted, tx_vector, TST_VEC);
    pco_iut->op = RCF_RPC_WAIT;
    received = rpc_readv(pco_iut, iut_s, rx_vector, TST_VEC);

    rc = rpc_iovec_cmp(sent, tx_vector, TST_VEC,
                       received, rx_vector, TST_VEC);
    if (rc != 0)
        TEST_FAIL("Invalid data received on IUT");

    sent = rpc_writev(pco_iut, iut_s, rx_vector, TST_VEC);
    received = rpc_readv(pco_tst, accepted, rrx_vector, TST_VEC);
    rc = rpc_iovec_cmp(sent, rx_vector, TST_VEC,
                       received, rrx_vector, TST_VEC);
    if (rc != 0)
        TEST_FAIL("Invalid data received on TESTER");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, accepted);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    for (i = 0; i < TST_VEC; i++)
    {
        free(tx_vector[i].iov_base);
        free(rx_vector[i].iov_base);
        free(rrx_vector[i].iov_base);
    }

    TEST_END;
}
