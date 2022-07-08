/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-shutdown shutdown() function for TCP connection (passive open)
 *
 * @objective Test on reliability of the @b shutdown() operation for
 *            TCP connection on the BSD compatible sockets.
 *            Server side activates @b shutdown() operation.
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
 * -# Call @b shutdown() on the @p pco_iut socket.
 * -# Call @b recv() on the @p pco_iut socket.
 * -# Check that @b recv() returns immediately with code 0.
 * -# Call @b send() on the @p pco_iut socket.
 * -# Call @b recv() on the @p pco_tst socket and check that correct data
 *    are received.
 * -# Call @b shutdown() on the @p pco_iut socket.
 * -# Register signal handler for handling of @c SIGPIPE signal by means
 *    of @b signal().
 * -# Call @b send() on the @p pco_iut socket.
 * -# Check that @b send() returns immediately with code -1 and @c EPIPE
 *    @b errno.
 * -# Check that @c SIGPIPE is received when trying to send to the
 *    @p pco_iut @p socket.
 * -# Close created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/shutdown"

#include "sockapi-test.h"


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

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;
    rpc_sigset_p            received_set = RPC_NULL;

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

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, rx_buf, tx_buf_len, 0);
    if (rc != 0)
    {
        TEST_FAIL("RPC recv() on IUT iut_s socket "
                  "unexpected behaviour (SHUT_RD)");
    }

    RPC_SEND(rc, pco_iut, iut_s, rx_buf, tx_buf_len, 0);

    rc = rpc_recv(pco_tst, tst_s, rx_buf, rx_buf_len, 0);
    if (rc != (int)tx_buf_len)
        TEST_FAIL("Only part of data received");

    if (memcmp(tx_buf, rx_buf, tx_buf_len))
        TEST_FAIL("Invalid data received");

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);

    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, rx_buf, tx_buf_len, 0);
    err = RPC_ERRNO(pco_iut);
    if (rc != -1)
    {
        TEST_FAIL("RPC send() on IUT iut_s socket unexpected "
                  "behaviour after SHUT_WR, retval=%d, errno=%X",
                  rc, TE_RC_GET_ERROR(err));
    }
    if (err != RPC_EPIPE)
    {
        TEST_FAIL("RPC send() on IUT returns unexpected errno %X "
                  "when try to send to shutdown for writing socket",
                  TE_RC_GET_ERROR(err));
    }

    received_set = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, received_set, RPC_SIGPIPE);
    if (rc == 0)
    {
        TEST_FAIL("SIGPIPE is not received when try to send to "
                  "shut down for writing socket");
    }

    TEST_SUCCESS;

cleanup:
    if (restore_signal_handler)
    {
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act, 
                              SIGNAL_REGISTRAR);
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf);
    free(rx_buf);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
