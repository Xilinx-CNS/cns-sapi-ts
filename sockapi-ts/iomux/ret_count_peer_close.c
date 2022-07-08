/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-ret_count_peer_close Return count when peer close connection
 *
 * @objective Check that I/O Multiplexing functions correctly counts
 *            events in return value when the same socket is waited
 *            for reading and writing and peer closes connection.
 *
 * @type conformance, compatibility
 *
 * @requirement REQ-1, REQ-2, REQ-3, REQ-13
 *
 * @reference @ref STEVENS
 *
 * @param pco_iut   PCO on IUT
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param pco_tst   Auxiliary PCO
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll())
 *
 * @par Scenario:
 * -# Create stream connection between @p pco_iut and @p pco_tst using
 *    @ref lib-stream_client_server algorithm with the following
 *    parameters:
 *      - @a srvr: @p pco_iut;
 *      - @a clnt: @p pco_tst;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut_addr;
 *      - @a srvr_wild: @c FALSE;
 *      - @a clnt_addr: @p tst_addr;
 *      .
 *    Created sockets are further named as @p iut_s and @p tst_s;
 * -# Wait for @e write event on @p iut_s socket using @p iomux function
 *    and, then, send data to it using @b send() function, until
 *    waiting for @e write event times out;
 * -# Wait for @e read and @e write events on @p iut_s socket using
 *    @p iomux function with 5 seconds timeout. The function waits
 *    for timeout, since no data are sent from peer and write buffer
 *    is filled in;
 * -# Do NOT read any data from @p tst_s socket and close it;
 * -# Wait for @p iomux function completion, it must return @c 2;
 * -# Check that @p iut_s socket is ready for reading and writing
 *    (@b poll() must return @c POLLIN, @c POLLERR and @c POLLHUP events);
 * -# Close @p iut_s socket.
 *
 * @note FreeBSD returns POLLIN and POLLOUT events.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/ret_count_peer_close"
#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    tarpc_timeval           timeout;
    iomux_evt_fd            event;

    uint64_t sent;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (rpc_overfill_buffers_gen(pco_iut, iut_s, &sent,
                                 iomux == IC_OO_EPOLL ? IC_EPOLL
                                                      : iomux) != 0)
    {
        TEST_FAIL("Failed to fill in socket Tx buffer");
    }

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    event.fd = iut_s;
    event.events = EVT_RDWR;

    pco_iut->op = RCF_RPC_CALL;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (rc != 0)
    {
        TEST_FAIL("iomux_call() failed");
    }

    TAPI_WAIT_NETWORK;
    RPC_CLOSE(pco_tst, tst_s);

    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (rc < 0)
    {
        TEST_FAIL("iomux_call() failed");
    }

    if (IOMUX_IS_SELECT_LIKE(iomux))
    {
        if ((rc != 2) || (event.revents != EVT_RDWR))
        {
            TEST_VERDICT("Peer has closed its socket, %s() returns %d with "
                         "(%s) event(s) instead of 2 with (EVT_RDRW) events",
                         iomux_call_en2str(iomux), rc,
                         iomux_event_rpc2str(event.revents));
        }
    }
    else
    {
        if ((rc != 1) ||
            (event.revents != (EVT_RDWR | EVT_EXC | EVT_HUP | EVT_ERR)))
        {
            TEST_VERDICT("Peer has closed its socket, %s() returns %d with "
                         "(%s) event(s) instead of 1 with "
                         "(EVT_RDWR | EVT_EXC | EVT_HUP | EVT_ERR) events",
                         iomux_call_en2str(iomux), rc,
                         iomux_event_rpc2str(event.revents));
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
