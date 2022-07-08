/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-shutdown_write_read shutdown() on connected socket
 *
 * @objective Check shutdown on socket in connected state in sequence
 *            @c SHUT_WR, then @c SHUT_RD.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param shut_peer Shutdown tester socket:
 *                  - never: don't close tester socket
 *                  - first: shutdown(SHUT_WR) it before IUT socket is closed
 *                  - second: shutdown(SHUT_WR) tester socket after closing
 *                            IUT socket
 *
 * @par Scenario:
 *
 * -# Create @p sock_type connection between @p pco_iut and @p pco_tst,
 *    using @p pco_tst as a server and @p iut_addr and
 *    @p tst_addr as local addresses on @p pco_tst and @p pco_iut
 *    respectevely. Two sockets @p iut_s and @p tst_s appear as a result
 *    of created connection.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p sock is @c STATE_CONNECTED. 
 * -# @b shutdown() @p iut_s for writing.
 * -# Perform routine #sockts_get_socket_state for @p iut_s.
 * -# Check that obtained state of @p sock is @c STATE_SHUT_WR. 
 * -# @b send() data from @p tst_s socket.
 * -# Call @b recv() on @p iut_s.
 * -# Check that @p iut_s received the same data as was sent from 
 *    @p iut_s. 
 * -# @b shutdown() @p iut_s for reading.
 * -# Perform routine #sockts_get_socket_state on @p pco_iut,  @p iut_s.
 * -# Check that obtained state of @p sock is @c STATE_SHUT_RDWR. 
 * -# Close all sockets. 
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/shutdown_write_read"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    rpc_socket_type         sock_type;
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const char *shut_peer;
    enum {
        PEER_NEVER,
        PEER_FIRST,
        PEER_SECOND
    } peer_type;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(shut_peer);

    if (strcmp(shut_peer, "never") == 0)
        peer_type = PEER_NEVER;
    else if (strcmp(shut_peer, "first") == 0)
        peer_type = PEER_FIRST;
    else if (strcmp(shut_peer, "second") == 0)
        peer_type = PEER_SECOND;
    else
        TEST_FAIL("unknown shut_peer parameter \"\"", shut_peer);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(pco_iut, iut_s, pco_tst, tst_s,
                                          STATE_CONNECTED);

    if (peer_type == PEER_FIRST) {
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);
        if (sock_type == RPC_SOCK_STREAM) {
            TAPI_WAIT_NETWORK;
            CHECK_RC(rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0));
            CHECK_SOCKET_STATE_AND_RETURN_VERDICT(pco_iut, iut_s, pco_tst,
                                                  tst_s, STATE_SHUT_RD);
        }
    }

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
    if (peer_type == PEER_FIRST && sock_type == RPC_SOCK_STREAM)
    {
        TAPI_WAIT_NETWORK;
        CHECK_RC(rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0));
        SOCKTS_CHECK_SOCK_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_BOUND,
                                "Wrong socket state after shutdown(WR) #1");
    }
    else
        CHECK_SOCKET_STATE_AND_RETURN_VERDICT(pco_iut, iut_s, pco_tst,
                                              tst_s, STATE_SHUT_WR);

    if (peer_type != PEER_FIRST) {
        RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);

        rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);

        if ((unsigned)rc != buf_len)
        {
            TEST_FAIL("Recv on accepted return length differ then was sent");
        }
    }

    if (peer_type == PEER_SECOND)
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);

    if (peer_type == PEER_NEVER || sock_type == RPC_SOCK_DGRAM) {
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);
        CHECK_SOCKET_STATE_AND_RETURN_VERDICT(pco_iut, iut_s, pco_tst,
                                              tst_s, STATE_SHUT_RDWR);
    }
    else
    {
        CHECK_RC(rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0));
        SOCKTS_CHECK_SOCK_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_BOUND,
                                "Wrong socket state after shutdown(WR) #2");
        if (peer_type == PEER_SECOND)
        {
            SLEEP(60); /* TIME-WAIT => CLOSED states */
            CHECK_RC(rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0));
            SOCKTS_CHECK_SOCK_STATE(pco_iut, iut_s, pco_tst, tst_s,
                STATE_BOUND, "Wrong socket state after TIME-WAIT timeout");
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
