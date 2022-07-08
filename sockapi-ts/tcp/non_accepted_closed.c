/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page tcp-non_accepted_closed Non accepted TCP socket is closed
 *
 * @objective Check behaviour of @b accept() when socket to be returned
 *            by it received RST or FIN from peer already and then
 *            @b close() or @b shutdown (RD) was called on listening
 *            socket 
 *
 * @type Conformance, compatibility
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_addr      Network address on IUT
 * @param tst_addr      Network address on TESTER
 * @param iut_close     Whether we should call @b close() or
 *                      @b shutdown(RD) on listening socket
 * @param tst_close     Whether we should call @b close() or
 *                      @b shutdown(WR) on connected socket
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut, bind it to
 *    @p iut_addr, make it listening.
 * -# Create socket @p tst_s on @p pco_tst. If @p tst_close,
 *    set @c SO_LINGER option on it with value 0 (so that
 *    it will send RST when being closed).
 * -# @b connect() @p tst_s to @p iut_addr.
 * -# Call @b close() or @b shutdown(WR) on @p tst_s
 *    (according to @p tst_close).
 * -# Call @b close() or @b shutdown(RD) on @p iut_s
 *    (according to @p iut_close).
 * -# Call @b accept() on @p iut_s, check returned
 *    value.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/non_accepted_closed"

#include "sockapi-test.h"
#include "tapi_sockets.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     acc_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    tarpc_linger           ling_optval;
    rpc_tcp_state          sock_state;

    te_bool                iut_close = FALSE;
    te_bool                tst_close = FALSE;
    te_bool                is_failed = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(iut_close);
    TEST_GET_BOOL_PARAM(tst_close);

    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, TRUE, iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (tst_close)
    {
        ling_optval.l_onoff = 1;
        ling_optval.l_linger = 0;
        rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER,
                       &ling_optval);
    }

    rpc_connect(pco_tst, tst_s, iut_addr);
    if (tst_close)
        rpc_close(pco_tst, tst_s);
    else
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);

    TAPI_WAIT_NETWORK;

    if (iut_close)
        rpc_close(pco_iut, iut_s);
    else
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    if (acc_s >= 0)
    {
        is_failed = TRUE;
        RING_VERDICT("accept() succeed on socket after calling "
                     "%s on it", iut_close ? "close()" : "shutdown(RD)");

        sock_state = tapi_get_tcp_sock_state(pco_iut, acc_s);
        RING("Socket state is %s", tcp_state_rpc2str(sock_state));

        if (sock_state != RPC_TCP_CLOSE)
            TEST_VERDICT("After receiving RST socket is in %s state",
                         tcp_state_rpc2str(sock_state));
    }
    else
        RING_VERDICT("accept() failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (!iut_close)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    if (!tst_close)
        CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

