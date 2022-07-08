/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-shutdown_wr shutdown(SHUT_WR) function for TCP connection
 *
 * @objective Test on reliability of the @b shutdown() operation for full-duplex
 *            connection on the BSD compatible sockets.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_p2p_ip6ip4mapped
 *                  - @ref arg_types_env_p2p_ip6
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 *                  - @ref arg_types_env_peer2peer_fake
 *
 * @par Scenario:
 *
 * -# Create connected @c SOCK_STREAM sockets on @p pco_iut and @p pco_tst.
 * -# Send data to the @p pco_tst socket and receive then on the @p pco_iut.
 * -# Call @b shutdown(@c SHUT_WR) on the @p pco_tst socket.
 * -# Check that @b recv() on the @p pco_iut socket returns 0.
 * -# Call @b send() on the @p pco_iut socket. 
 * -# Call @b recv() on the @p pco_tst socket and verify received data.
 * -# Call @b shutdown on the @p pco_iut socket.
 * -# Call @b recv() on the @p pco_tst socket.
 * -# Check that @b recv() returns 0.
 * -# Close opened sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/shutdown_wr"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
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

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);
    rc = rpc_recv(pco_iut, iut_s, rx_buf, tx_buf_len, 0);
    if (rc != (int)tx_buf_len)
        TEST_FAIL("Only part of data received");

    if (memcmp(tx_buf, rx_buf, tx_buf_len))
        TEST_FAIL("Invalid data received");


    rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, rx_buf, tx_buf_len, 0);
    if (rc != 0)
    {
        TEST_FAIL("RPC read() on IUT iut_s socket "
                  "unexpected behaviour (SHUT_WR)");
    }
    
    RPC_SEND(rc, pco_iut, iut_s, tx_buf, tx_buf_len, 0);
    memset(rx_buf, 0, rx_buf_len);
    rc = rpc_recv(pco_tst, tst_s, rx_buf, tx_buf_len, 0);
    if (rc != (int)tx_buf_len)
        TEST_FAIL("Only part of data received");

    if (memcmp(tx_buf, rx_buf, tx_buf_len))
        TEST_FAIL("Invalid data received");

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);

    rc = rpc_recv(pco_tst, tst_s, rx_buf, tx_buf_len, 0);
    if (rc != 0)
        TEST_FAIL("RPC write() on IUT tst_s socket "
                  "unexpected behaviour (SHUT_WR)");


    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
