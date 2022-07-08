/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-destination_as_bound Operating System choose destination address the same as one which socket was bound to.
 *
 * @objective Check that OS connects socket to the destination address the same as address
 *            as one which the socket was bound to if @b connect() was called 
 *            with wildcard IP address and real port.
 *
 * @type Conformance, compatibility(Linux behavior)
 *
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Auxiliary PCO on IUT
 *
 *  Note, that both @p pco_iut and @p pco_tst are on the same host.
 *
 * @par Scenario
 *
 * -# Create sockets @p iut_s and @p tst_s of the @c SOCK_STREAM type
 *    on @p pco_iut and @p pco_tst respectively;
 * -# @b bind() @p tst_s to the local address on @p pco_tst;
 * -# @b bind() @p iut_s to the local address on @p pco_iut;
 * -# Call @b listen() on the @p tst_s;
 * -# Prepare address of the server the @p iut_s should be connected to the
 *    same as @p tst_s address but with wildcard IP address part;
 * -# Call @b connect() on @p iut_s with prepared address;
 * -# Call @b getpeername() on @p iut_s to check that remote peer address
 *    the same as local address the @p iut_s is bound to;
 * -# Close the sockets created in test.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/destination_as_bound"

#include "sockapi-test.h"
#include "tapi_cfg.h"


int
main(int argc, char *argv[])
{

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;

    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;
    int                     sent, rcv;

    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     acc_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    struct sockaddr_storage dst_addr;

    struct sockaddr_storage peer_addr;
    socklen_t               peer_addrlen;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    memcpy(&dst_addr, tst_addr, te_sockaddr_get_size(tst_addr));
    SIN(&dst_addr)->sin_addr.s_addr = 0;

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_bind(pco_iut, iut_s, iut_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_iut, iut_s, SA(&dst_addr));

    peer_addrlen = sizeof(peer_addr);
    rpc_getpeername(pco_iut, iut_s, SA(&peer_addr), &peer_addrlen);


    if (te_sockaddrcmp(SA(&tst_addr), te_sockaddr_get_size(tst_addr),
                       SA(&peer_addr), peer_addrlen) != 0)
    {
        TEST_FAIL("Peer name is not the same as installed "
                  "on 'pco_tst' TCP server address");
    }

    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    pco_iut->op = RCF_RPC_CALL;
    RPC_SEND(sent, pco_iut, iut_s, tx_buf, buf_len, 0);

    rcv = rpc_recv(pco_tst, tst_s, rx_buf, buf_len, 0);

    pco_iut->op = RCF_RPC_WAIT;
    RPC_SEND(sent, pco_iut, iut_s, tx_buf, buf_len, 0);

    if (rcv != sent)
    {
        TEST_FAIL("The number of bytes sent (%d) through 'iut_s' is not the "
                  "same as received (%d) on 'tst_s'", sent, rcv);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
