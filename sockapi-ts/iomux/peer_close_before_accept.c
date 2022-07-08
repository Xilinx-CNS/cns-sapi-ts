/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-peer_close_before_accept Peer close connection before accept on server
 *
 * @objective Check that @b accept() after indication of the connection
 *            by @p iomux function doesn't block, if peer closed the
 *            connection before @b accept() call on server.
 *
 * @type conformance, stress, compatibility
 *
 * @requirement REQ-3, REQ-6, REQ-7, REQ-13
 *
 * @reference @ref STEVENS sections 6.3, 15.6
 *
 * @param pco_iut   PCO on IUT
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param pco_aux   Auxiluary PCO
 * @param tst_addr  Address/port to be used to connect to @p pco_aux
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll())
 * @param linger    If true, set linger option on client before
 *                  close connection to send an RST
 * @param func      Function (@b send() or @b recv())to be call at the end
 *                  of the test
 *
 * @par Scenario:
 * -# Create stream @p iut_s socket on @p pco_iut.
 * -# @b bind() @p iut_s socket to @p iut_addr address/port;
 * -# Call @b listen() on @p iut_s socket;
 * -# Create stream @p tst_s socket on @p pco_aux.
 * -# If @b linger parameter is true, set @c SO_LINGER
 *    (@a onoff=@c 1, @a linger=@c 0) option on @p tst_s socket;
 * -# Wait for connection using @b iomux function on @p iut_s socket
 *    with 15 seconds timeout;
 * -# @b connect() @p tst_s socket to @p iut_addr address/port;
 * -# Check that called @p iomux function returns @c 1 with incoming
 *    connection indication;
 * -# Close @p tst_s socket;
 * -# Try to @b accept() connection. It MUST either return @c -1 with
 *    @c ECONNABORTED in @b errno or accept connection.  However, some
 *    implementations may block, since client has already closed the
 *    connection;
 * -# If connection is established, try to call @p func on accepted socket.
 * -# For @b send() : if @p linger is true, @c -1 with @c ECONNRESET must
 *    be returned from the first attempt. If @p linger is false, the first
 *    attempt should return success, the second should return @c -1 with
 *    @c ECONNRESET.
 * -# For @b recv() : if @p linger is true, @c -1 with @c ECONNRESET must
 *    be returned. If @p linger is false, @c 0 must be returned.
 * -# Close @p iut_s socket.
 *
 * The test should be called with all combinations of @b linger
 * parameter (true, false) and @b iomux functions.  It's also useful
 * to run the test when @b pco_iut and @b aux PCOs are threads of the same
 * process.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/peer_close_before_accept"

#include "sockapi-test.h"
#include "iomux.h"


int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;
    te_bool                 linger;

    const char             *func;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_aux = NULL;

    const struct sockaddr  *iut_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     accept_s = -1;

    iomux_evt_fd            event;
    tarpc_timeval           timeout;
    unsigned char           b = 0;
    ssize_t                 sent;
    ssize_t                 recv;
    
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;
    rpc_sigset_p            received_set = RPC_NULL;
    
    tarpc_linger            opt_val;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_aux);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(linger);
    TEST_GET_STRING_PARAM(func);

    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    tst_s = rpc_socket(pco_aux, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    timeout.tv_sec = 15;
    timeout.tv_usec = 0;

    event.fd = iut_s;
    event.events = EVT_RD;
    pco_iut->op = RCF_RPC_CALL;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (rc != 0)
    {
        TEST_FAIL("Non-blocking call of iomux_call() failed");
    }

    rpc_connect(pco_aux, tst_s, iut_addr);

    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (rc == -1)
    {
        TEST_FAIL("Call of %s function failed", iomux_call_en2str(iomux));
    }
    if (rc != 1)
    {
        TEST_FAIL("%s() function returned %d instead of 1", 
                  iomux_call_en2str(iomux), rc);
    }
    if ((event.revents & EVT_RD) == 0)
    {
        TEST_FAIL("No incomming connection was indicated by %s() function",
                  iomux_call_en2str(iomux));
    }

    if (linger == TRUE)
    {
        opt_val.l_onoff = 1;
        opt_val.l_linger = 0;
        rpc_setsockopt(pco_aux, tst_s, RPC_SO_LINGER, &opt_val);
    }

    rpc_closesocket(pco_aux, tst_s);
    tst_s = -1;
    MSLEEP(100);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    accept_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    if (accept_s == -1)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ECONNABORTED, "accept() function "
                        "called on IUT returned -1, but");
    }
    else
    {
        if (strcmp(func, "send") == 0)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            sent = rpc_send(pco_iut, accept_s, &b, 1, 0);
            if (linger)
            {
                if (sent != -1)
                {
                    TEST_FAIL("Peer (client) closed its socket and sent "
                              "RST, writing to accepted socket on server "
                              "returned %d instead of -1", sent);
                }
                CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET, "Client closed "
                                "its socket and sent RST, send() function "
                                "called on IUT accepted socket returned "
                                "-1, but");
            }
            else
            {
                if (sent != 1)
                {
                    TEST_FAIL("Peer (client) closes its socket without "
                              "linger, and writing to accepted socket "
                              "on server returned %d instead of 1", sent);
                }

                MSLEEP(100);

                RPC_AWAIT_IUT_ERROR(pco_iut);
                sent = rpc_send(pco_iut, accept_s, &b, 1, 0);
                if (sent != -1)
                {
                    TEST_FAIL("Peer (client) closed its socket and sent "
                              "RST, writing to accepted socket on server "
                              "returned %d instead of -1", sent);
                }
                CHECK_RPC_ERRNO(pco_iut, RPC_EPIPE, 
                                "Client closed its socket and sent "
                                "RST, send() function called on IUT "
                                "accepted socket returned -1, but");

                received_set = rpc_sigreceived(pco_iut);
                rc = rpc_sigismember(pco_iut, received_set, RPC_SIGPIPE);
                if (rc == 0)
                {
                    TEST_FAIL("No SIGPIPE signal has been recieved");
                }
            }
        }
        else
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            recv = rpc_recv(pco_iut, accept_s, &b, 1, 0);
            if (linger)
            {
                if (recv != -1)
                {
                    TEST_FAIL("recv() returned %d with linger", recv);
                }
                CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET, "recv() with "
                                "linger returned -1, but");
            }
            else
            {
                if (recv != 0)
                {
                    TEST_FAIL("recv returned %d without linger", recv);
                }
            }
        }
    }

    TEST_SUCCESS;

cleanup:
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act,
                              SIGNAL_REGISTRAR);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_aux, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, accept_s);

    TEST_END;
}
