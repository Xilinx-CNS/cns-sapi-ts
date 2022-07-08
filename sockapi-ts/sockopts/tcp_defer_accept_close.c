/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-tcp_defer_accept_close TCP_DEFER_ACCEPT and closing connection before accept()
 *
 * @objective Check what happens if @c TCP_DEFER_ACCEPT option is set
 *            on a listening socket and established connection is closed
 *            before successful @b accept() call.
 *
 * @type conformance
 *
 * @param pco_iut           RPC server on IUT
 * @param pco_tst           RPC server on TESTER
 * @param iut_addr          Address/port on @p pco_iut
 * @param tst_addr          Address/port on @p pco_tst
 * @param peer_close        Whether to close connection from the IUT side
 *                          or from the TESTER side
 * @param iomux             I/O multiplexing function to be called
 * @param check_writable    Whether to check if socket is writable
 * @param overfill_buffers  Whether to overfill buffers or not
 *                          before calling iomux function
 * @param is_blocking       Whether send() function should be blocked
 *                          or not
 * @param use_shutdown      Whether we should use shutdown() or close()
 *                          to close listening socket
 * @param swap_pco          Swap IUT and tester PCOs
 *
 * @par Test sequence:
 *
 * -# Create TCP socket @p iut_s on @p pco_iut, bind it to
 *    @p iut_addr, set @c TCP_DEFER_ACCEPT socket option on
 *    it, call @b rpc_listen() on it.
 * -# Create TCP socket @p tst_s on @p pco_tst, connect it to
 *    @p iut_addr.
 * -# If !(@p peer_close), do the following:
 * -# If required, overfill buffers on @p tst_s.
 * -# Call @p iomux function on @p tst_s it with @c RCF_RPC_CALL.
 * -# Close @p iut_s with help of @b close() or @b shutdown(RD)
 *    (according to @p use_shutdown).
 * -# Call @p iomux function on @p tst_s with @c RCF_RPC_WAIT.
 *    Check whether expected events were returned.
 * -# Call @b send() on @p tst_s, check its return value.
 * -# If @p peer_close, do the following:
 * -# Make @p iut_s socket nonblocking.
 * -# Call @b accept() on it and check that it failed with errno
 *    @c EAGAIN.
 * -# Call @b close() or @b shutdown(WR) (select proper function
 *    according to @p use_shutdown) on @p tst_s.
 * -# Call @b accept() on @p iut_s again, check its return value.
 * -# If @b accept() successed, check TCP state of returned socket
 *    (should be @c TCP_CLOSE_WAIT).
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_defer_accept_close"

#include "sockapi-test.h"
#include "iomux.h"
#include "tapi_sockets.h"

#define IOMUX_VERDICT_LEN 250

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             acc_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    opt_val;

    void                  *tx_buf = NULL;
    size_t                 tx_buf_len;

    uint64_t               sent = 0;

    iomux_call_type        iomux = IC_UNKNOWN;
    iomux_evt_fd           event;
    te_bool                is_blocking = FALSE;
    te_bool                use_shutdown = FALSE;
    te_bool                overfill_buffers = FALSE;
    te_bool                check_writable = FALSE;
    te_bool                swap_pco = FALSE;

    te_bool                is_failed = FALSE;
    te_bool                operation_done = FALSE;
    te_bool                peer_close = FALSE;

    uint16_t               exp_events = 0;
    uint16_t               missed_events = 0;
    uint16_t               unexp_events = 0;
    char                   iomux_verdict[IOMUX_VERDICT_LEN];
    int                    n = 0;
    int                    fdflags;
    void                  *tmp;

    rpc_tcp_state          tcp_state;

    /* Timeout was changed from 2 to 5 secs because of OL bug 8621 */
    tarpc_timeval          timeout = {.tv_sec = 5, .tv_usec = 0};

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_BOOL_PARAM(use_shutdown);
    TEST_GET_BOOL_PARAM(peer_close);
    if (!peer_close)
    {
        TEST_GET_IOMUX_FUNC(iomux);
        TEST_GET_BOOL_PARAM(is_blocking);
        TEST_GET_BOOL_PARAM(overfill_buffers);
        TEST_GET_BOOL_PARAM(check_writable);
        TEST_GET_BOOL_PARAM(swap_pco);
    }

    if (swap_pco)
    {
        tmp = (void *)pco_iut;
        pco_iut = pco_tst;
        pco_tst = (rcf_rpc_server *)tmp;
        tmp = (void *)iut_addr;
        iut_addr = tst_addr;
        tst_addr = (const struct sockaddr *)tmp;
    }

    CHECK_NOT_NULL(tx_buf = sockts_make_buf_stream(&tx_buf_len));

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_IPPROTO_TCP, TRUE, FALSE,
                                       iut_addr);
    if (peer_close)
    {
        fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);
        fdflags |= RPC_O_NONBLOCK;
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, fdflags);
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    opt_val = 7;
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_TCP_DEFER_ACCEPT, &opt_val);
    if (rc != 0)
        TEST_VERDICT("setsockopt(SOL_TCP, TCP_DEFER_ACCEPT) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                      RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    rpc_connect(pco_tst, tst_s, iut_addr);

    if (overfill_buffers)
        rpc_overfill_buffers(pco_tst, tst_s, &sent);

    if (!peer_close)
    {
        event.fd = tst_s;
        event.events = EVT_RD | EVT_EXC | (check_writable ? EVT_WR : 0);

        pco_tst->op = RCF_RPC_CALL;
        iomux_call(iomux, pco_tst, &event, 1, &timeout);
        TAPI_WAIT_NETWORK;
        rcf_rpc_server_is_op_done(pco_tst, &operation_done);
        RING("iomux call %s", operation_done ? "done" : "waiting");
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        if (acc_s >= 0)
            TEST_VERDICT("accept() successed before receiving any data "
                         "from a peer");
        else
            CHECK_RPC_ERRNO_NOEXIT(pco_iut,
                                   RPC_EAGAIN,
                                   is_failed,
                                   "accept() failed but returned "
                                   "unexpected errno");
    }

    if (use_shutdown)
        rpc_shutdown(peer_close ? pco_tst : pco_iut,
                     peer_close ? tst_s : iut_s,
                     peer_close ? RPC_SHUT_WR : RPC_SHUT_RD);
    else
        rpc_close(peer_close ? pco_tst : pco_iut,
                  peer_close ? tst_s : iut_s);

    TAPI_WAIT_NETWORK;

    if (!peer_close)
    {
        pco_tst->op = RCF_RPC_WAIT;
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = iomux_call(iomux, pco_tst, &event, 1, NULL);

        if (rc < 0)
        {
            RING_VERDICT("iomux() failed with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_tst)));
            is_failed = TRUE;
        }
        else
        {
            if (operation_done)
            {
                RING_VERDICT("iomux() finished before closing of socket "
                             "and timeout");
                is_failed = TRUE;
            }

            if (iomux == IC_SELECT || iomux == IC_PSELECT)
                exp_events = EVT_RD | (check_writable ? EVT_WR : 0);
            else
                exp_events = (EVT_ERR | EVT_EXC | EVT_RD | EVT_HUP |
                              (check_writable ? EVT_WR : 0));

            if (!overfill_buffers)
                exp_events = 0;

            /** Ignore OUT event checking on tester because of possible fail
             * on linux, see SF bug 48360 for details. */
            if (!swap_pco && check_writable)
            {
                exp_events &= ~EVT_WR;
                event.revents &= ~EVT_WR;
            }

            if (event.revents != exp_events)
            {
                if (event.revents == 0)
                {
                    RING_VERDICT("iomux() timed out");
                    is_failed = TRUE;
                }
                else
                {
                    memset(iomux_verdict, 0, IOMUX_VERDICT_LEN);
                    n = snprintf(iomux_verdict, IOMUX_VERDICT_LEN, "iomux() ");

                    unexp_events = event.revents & ~exp_events;
                    missed_events = exp_events & ~event.revents; 

                    if (unexp_events != 0)
                        n += snprintf(iomux_verdict + n, IOMUX_VERDICT_LEN - n,
                                      "returned unexpected event(s) %s",
                                      iomux_event_rpc2str(unexp_events));

                    if (unexp_events != 0 && missed_events != 0)
                        n += snprintf(iomux_verdict + n, IOMUX_VERDICT_LEN - n,
                                      ", but ");

                    if (missed_events != 0)
                        n += snprintf(iomux_verdict + n, IOMUX_VERDICT_LEN - n,
                                      "missed expected event(s) %s",
                                      iomux_event_rpc2str(missed_events));

                    RING_VERDICT(iomux_verdict);
                }
            }
        }

        RPC_AWAIT_IUT_ERROR(pco_tst);
        if (is_blocking)
            rc = rpc_send(pco_tst, tst_s, tx_buf, tx_buf_len,
                          0);
        else
            rc = rpc_send(pco_tst, tst_s, tx_buf, tx_buf_len,
                          RPC_MSG_DONTWAIT);

        if (rc >= 0)
        {
            if (overfill_buffers)
                TEST_VERDICT("send() successed when peer was closed");
        }
        else
            CHECK_RPC_ERRNO_NOEXIT(pco_tst,
                                   overfill_buffers ? RPC_ECONNRESET :
                                                      RPC_EPIPE,
                                   is_failed,
                                   "send() failed but returned "
                                   "unexpected errno");
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        if (acc_s >= 0)
        {
            RING_VERDICT("accept() successed after connection was "
                         "closed by a peer");
            tcp_state = tapi_get_tcp_sock_state(pco_iut, acc_s);
            RING_VERDICT("The socket returned by accept() is in "
                         "%s state", tcp_state_rpc2str(tcp_state));
            if (tcp_state != RPC_TCP_CLOSE_WAIT)
                is_failed = TRUE;
        }
        else
            CHECK_RPC_ERRNO_NOEXIT(pco_iut,
                                   RPC_EAGAIN,
                                   is_failed,
                                   "accept() failed but returned "
                                   "unexpected errno");
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    if (!peer_close)
    {
        if (use_shutdown)
            CLEANUP_RPC_CLOSE(pco_iut, iut_s);
        CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    }
    else
    {
        if (use_shutdown)
            CLEANUP_RPC_CLOSE(pco_tst, tst_s);
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
        CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    }

    free(tx_buf);
    
    TEST_END;
}
