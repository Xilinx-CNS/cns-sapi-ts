/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-shutdown_stream_read_write Consistently shutdown(RD) and shutdown(WR) on TCP socket
 *
 * @objective Check shutdown of stream socket in connected state
 *            in sequence @c SHUT_RD, then @c SHUT_WR. Check that data can be
 *            sent after shutdown(RD).
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *              - @ref arg_types_env_peer2peer_fake
 *
 * @par Scenario:
 *
 * -# Create @c SOCK_STREAM connection between @p pco_iut and @p pco_tst,
 *    using @p pco_tst as a server and @p iut_addr and
 *    @p tst_addr as local addresses on @p pco_tst and @p pco_iut
 *    respectevely. Two sockets @p iut_s and @p tst_s appear as a result
 *    of created connection.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p sock is @c STATE_CONNECTED. 
 * -# @b shutdown() @p iut_s for reading.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p sock is @c STATE_SHUT_RD. 
 * -# @b send() data from @p iut_s socket.
 * -# Call @b recv() on @p tst_s.
 * -# Check that @p accepted received the same data as was sent from 
 *    @p iut_s. 
 * -# @b shutdown() @p iut_s for writing.
 * -# Perform routine #sockts_get_socket_state on @p pco_iut,  @p iut_s.
 * -# Check that obtained state of @p sock is @c STATE_SHUT_RDWR. 
 * -# Close all sockets.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/shutdown_stream_read_write"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED);

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    if (rc == -1)
        TEST_VERDICT("send() issued on RD-shutdowned socket returns %d "
                     "and errno is set to %s", rc, 
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    rc = rpc_recv(pco_tst, tst_s, rx_buf, buf_len, 0); 

    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("Recv on accepted return length differ then was sent"); 
    }
 
    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_SHUT_RD); 
    
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_SHUT_RDWR); 

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s); 
    CLEANUP_RPC_CLOSE(pco_tst, tst_s); 

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}

