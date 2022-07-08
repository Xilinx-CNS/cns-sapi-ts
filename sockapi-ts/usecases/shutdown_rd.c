/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-shutdown_rd shutdown(SHUT_RD) function for TCP connection
 *
 * @objective Test on reliability of the @b shutdown() operation for
 *            full-duplex connection on the BSD compatible sockets.
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
 * -# Call @b shutdown on the @p pco_iut @p socket.
 * -# Call blocking @b recv() on the @p pco_iut socket.
 * -# Check that @b recv() returnsimmediately with code 0.
 * -# @b send() data to the @p pco_tst socket.
 * -# Check that @b send() operation is completed successfully.
 * -# Call @b shutdown()(SHUT_RD) on the @p pco_tst socket.
 * -# Call @b send() on the @p pco_iut @p socket.
 * -# Check that @b send() on the @p pco_iut @p socket is 
 *    completed successfully.
 * -# Check that @c FD_CLOSE event is set.
 * -# Close opened sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/shutdown_rd"

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

    tarpc_network_events     ev_err;

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

    memset(&ev_err, 0, sizeof(ev_err));

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, rx_buf, tx_buf_len, 0);
    if (rc != 0)
        TEST_FAIL("recv() on IUT socket failed after shutdown(SHUT_RD)");

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);

    RPC_AWAIT_IUT_ERROR(pco_tst);

    rc = rpc_shutdown(pco_tst, tst_s, RPC_SHUT_RD);
    if (rc != 0)
    {
        TEST_FAIL("RPC shutdown() on tester socket failed after "
                  "shutdown(SHUT_RD) on the IUT");
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, rx_buf, tx_buf_len, 0);
    if (rc < 0)
    {
        TEST_FAIL("RPC send() on IUT socket failed after "
                  "shutdown(SHUT_RD)");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
