/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-send_recv send()/recv() operations on the SOCK_STREAM socket
 *
 * @objective Test on reliability of the @b send()/recv() operations
 *            on BSD compatible sockets.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_p2p_ip6ip4mapped
 *                  - @ref arg_types_env_p2p_ip6
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 * @param sock_type Socket type:
 *                  - udp
 *                  - TCP active
 *                  - TCP passive
 * @param sock_func Function to open socket:
 *                  - socket()
 *                  - onload_socket_unicast_nonaccel()
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
 * -# Call blocking @b recv() on the @p pco_iut @p accepted socket;
 * -# @b send() data to the @p pco_tst socket;
 * -# Wait for @b recv() completion on the @p pco_iut @p accepted socket;
 * -# Call @b send() of the obtained data on the @p pco_iut @b accepted
 *    socket with some delay to run @b recv() on the @p pco_tst socket;
 * -# Call @b recv() on the @p pco_tst socket to obtain data from
 *    @p pco_iut @p accepted socket;
 * -# Compare transmitted and received data.
 * -# Close created sockets;
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/send_recv"

#include "sockapi-test.h"


#define TST_SENDRECV_FLAGS    0


int
main(int argc, char *argv[])
{
    int             err;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    void           *tx_buf = NULL;
    size_t          tx_buf_len;
    void           *rx_buf = NULL;
    size_t          rx_buf_len;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    sockts_socket_type    sock_type;
    sockts_socket_func    sock_func;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    SOCKTS_GET_SOCK_FUNC(sock_func);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, FALSE, FALSE, NULL, &iut_s, &tst_s,
                      NULL, sock_func);

    pco_iut->op = RCF_RPC_CALL;
    rpc_recv_gen(pco_iut, iut_s, rx_buf,
                 tx_buf_len, TST_SENDRECV_FLAGS, rx_buf_len);
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, TST_SENDRECV_FLAGS);

    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recv_gen(pco_iut, iut_s, rx_buf, tx_buf_len,
                      TST_SENDRECV_FLAGS, rx_buf_len);
    if (rc != (int)tx_buf_len)
        TEST_FAIL("Only part of data received");

    if (memcmp(tx_buf, rx_buf, tx_buf_len))
        TEST_FAIL("Invalid data received");

    rc = rpc_send(pco_iut, iut_s, tx_buf, tx_buf_len, TST_SENDRECV_FLAGS);
    if (rc != (int)tx_buf_len)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC send() on IUT accepted socket failed "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    memset(rx_buf, 0, rx_buf_len);
    rc = rpc_recv(pco_tst, tst_s, rx_buf, tx_buf_len, TST_SENDRECV_FLAGS);
    if (rc != (int)tx_buf_len)
        TEST_FAIL("Only part of data received");

    if (memcmp(tx_buf, rx_buf, tx_buf_len))
        TEST_FAIL("Invalid data received");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
