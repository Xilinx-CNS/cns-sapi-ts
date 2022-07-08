/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-tcp_defer_accept_rst TCP_DEFER_ACCEPT reset connection on timeout
 *
 * @objective Check that listening socket with non-zero @c TCP_DEFER_ACCEPT 
 *            option reset connection on timeout.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param iut_addr          Address/port on IUT to bind to
 * @param pco_tst           PCO on TESTER
 *
 * @par Test sequence:
 *
 * -# Create TCP socket @p iut_s on @p pco_iut and bind it to
 *    @p iut_addr address/port.
 * -# Set @c TCP_DEFER_ACCEPT option to value in the range from @c 49 
 *    (=3*2^(5-1)+1) to @c 96 (=3*2^5) seconds (it is very
 *    Linux-specific and relies on Linux kernel internals). 
 * -# Get applied value of @c TCP_DEFER_ACCEPT option, since it may be
 *    adjust to TCP RTO algorithm. Check that the value is greater than
 *    zero. (In fact, applied value has to be @c 96.)
 * -# Call @b listen() on @p iut_s socket.
 * -# Get @c TCP_DEFER_ACCEPT option value once more to check that it
 *    is not affected by @b listen() (Linux 2.6.14 and 2.6.15 have bug
 *    here).
 * -# Create TCP socket @p tst_s on @p pco_tst.
 * -# Connect @p tst_s socket to @p iut_addr address/port. It will not
 *    block and return success, since SYN-ACK is sent by listening
 *    socket.
 * -# Sleep for @c 4 * @c TCP_DEFER_ACCEPT option applied value seconds
 *    (Constant @c 4 is extracted from Linux kernel sources).
 * -# Check that first attempt to send data from @p tst_s socket succeed,
 *    but leads to RST from IUT and the second attempt returns @c -1
 *    with @c ECONNRESET errno.
 * -# Close created sockets.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_defer_accept_rst"

#include "sockapi-test.h"

#define TCP_DEFER_ACCEPT_LIMIT  5


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    ret;
    int                    opt_val = rand_range(3 * (1 << 4) + 1,
                                                3 * (1 << 5));
    int                    applied1;
    int                    applied2;

    void                  *tx_buf = NULL;
    size_t                 tx_buf_len;
    ssize_t                sent;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    CHECK_NOT_NULL(tx_buf = sockts_make_buf_stream(&tx_buf_len));
    
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    rpc_bind(pco_iut, iut_s, iut_addr);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_setsockopt(pco_iut, iut_s, RPC_TCP_DEFER_ACCEPT, &opt_val);
    if (ret != 0)
    {
        TEST_VERDICT("setsockopt(SOL_TCP, TCP_DEFER_ACCEPT) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_DEFER_ACCEPT, &applied1);

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_DEFER_ACCEPT, &applied2);

    if (applied1 != applied2)
        TEST_VERDICT("TCP_DEFER_ACCEPT value unexpectedly changed by "
                     "listen()");

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    rpc_connect(pco_tst, tst_s, iut_addr);

    SLEEP(4 * applied1);

    RPC_SEND(sent, pco_tst, tst_s, tx_buf, tx_buf_len, 0);

    MSLEEP(100);

    RPC_AWAIT_IUT_ERROR(pco_tst);
    sent = rpc_send(pco_tst, tst_s, tx_buf, tx_buf_len, 0);
    if (sent != -1)
        TEST_VERDICT("Listening socket with non-zero TCP_DEFER_ACCEPT "
                     "option have to sent RST on timeout, but send() "
                     "from peer returns %d instead of -1", (int)sent);
    CHECK_RPC_ERRNO(pco_tst, RPC_ECONNRESET,
                    "Listening socket with non-zero TCP_DEFER_ACCEPT "
                    "option have to sent RST on timeout, send() from "
                    "peer returns -1");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    
    TEST_END;
}
