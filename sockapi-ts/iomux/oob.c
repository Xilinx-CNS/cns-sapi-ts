/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-oob Out-of-band data support
 *
 * @objective Check that I/O multiplexing indicates exception on 
 *            reception of out-of-band data.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 6.3, 6.9, 6.10, 21
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
 *    Created sockets are further named as @p iut_s and @p tst_s.
 * -# On @p pco_iut run @p iomux function to wait for exception (or priority
 *    band data) and ordinary data on @b iut_s socket with 10 seconds timeout.
 * -# Send 1 byte to @p tst_s socket using @b send() function 
 *    with @c MSG_OOB flag.
 * -# @p iomux function must return @c 1 with exception or priority
 *    band data indication on @p iut_s socket.
 * -# Receive 1 byte of @e out-of-band data from @p iut_s socket
 *    using @b recv() function with @c MSG_OOB flag.
 * -# On @p pco_iut run @p iomux function to wait for exception (or priority
 *    band data) and ordinary data on @b iut_s socket with 10 seconds timeout.
 * -# Send 2 bytes to @p tst_s socket using @b send() function 
 *    with @c MSG_OOB flag.
 * -# @p iomux function must return both exception and read indication.
 * -# Close created sockets.
 *
 * @note
 * This test has different behaviour on Linux<=2.6.27, Linux>=2.6.28,
 * Solaris, Windows.  It was reworked for new linux without a chance to check
 * Solaris and/or Windows behaviour.
 * For Linux, see also
 * http://git.kernel.org/?p=linux/kernel/git/stable/linux-2.6.28.y.git;a=commitdiff;h=c7004482e8dcb7c3c72666395cfa98a216a4fb70
 * and thread starting from http://lkml.org/lkml/2008/9/20/165
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/oob"

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
    unsigned int            expected_revents;
    unsigned int            expected_revents1;
    ssize_t                 sent;
    uint8_t                 snd[] = { 1, 2 };
    uint8_t                 rcv[2];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
#if 0
    RPC_SEND(sent, pco_tst, tst_s, snd, 1, 0);
    rpc_recv(pco_iut, iut_s, rcv, 2, 0);
#endif

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    memset(&event, 0, sizeof(iomux_evt_fd));
    event.fd = iut_s;
    event.events = EVT_RD_BAND | EVT_RD | EVT_PRI | EVT_RD_NORM;
    pco_iut->op = RCF_RPC_CALL;

    RPC_SEND(sent, pco_tst, tst_s, snd, 1, RPC_MSG_OOB);
    sleep(1);
    iomux_call(iomux, pco_iut, &event, 1, &timeout);

    /* Only exception event we expect here */
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);

    if (IOMUX_IS_SELECT_LIKE(iomux))
    {
        if (rc != 1 && rc != 2)
        {
            TEST_FAIL("%s() returns unexpected value %d",
                    iomux_call_en2str(iomux), rc);
        }
        expected_revents = EVT_EXC;
        expected_revents1 = EVT_EXC | EVT_RD;
    }
    else
    {
        if (rc != 1)
        {
            TEST_FAIL("%s() returns unexpected value %d",
                    iomux_call_en2str(iomux), rc);
        }
        expected_revents = EVT_PRI;
        expected_revents1 = EVT_PRI | EVT_RD | EVT_RD_NORM;
    }

    if (event.revents == expected_revents1)
    {
        TEST_VERDICT("Single OOB byte is indicated by exception event "
                     "together with normal RD event");
    }
    else if (event.revents != expected_revents)
    {
        TEST_VERDICT("OOB data was sent to a socket, %s() returns (%s) "
                     "event(s) instead of (%s)", iomux_call_en2str(iomux),
                     iomux_event_rpc2str(event.revents),
                     iomux_event_rpc2str(expected_revents));
    }

    rpc_recv(pco_iut, iut_s, rcv, 2, RPC_MSG_OOB);

    /* 
     * Next try -- 2 bytes, second is OOB.
     * It is important to send() before iomux, because it is VALID
     * behaviour to return RD event on the first iomux call, and OOB event
     * on the second only.
     */

    RPC_SEND(sent, pco_tst, tst_s, snd, 2, RPC_MSG_OOB);
    TAPI_WAIT_NETWORK;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    memset(&event, 0, sizeof(iomux_evt_fd));
    event.fd = iut_s;
    event.events = EVT_RD_BAND | EVT_RD | EVT_PRI | EVT_RD_NORM;
    pco_iut->op = RCF_RPC_CALL;
    iomux_call(iomux, pco_iut, &event, 1, &timeout);

    /* Both exception and read events we expect here */
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);


    if (IOMUX_IS_SELECT_LIKE(iomux))
    {
       /* the number of active sets */
       if (rc != 2)
           RING_VERDICT("%s() returns unexpected value %d",
                     iomux_call_en2str(iomux), rc);
        expected_revents = EVT_EXC | EVT_RD;
    }
    else
    {
       /* the number of nfds structures - only 1 in our case */
       if (rc != 1)
           TEST_FAIL("%s() returns unexpected value %d",
                     iomux_call_en2str(iomux), rc);
        expected_revents = EVT_RD | EVT_PRI | EVT_RD_NORM;
    }

    if (event.revents != expected_revents)
    {
        TEST_VERDICT("OOB and non-OOB data was sent to a socket, "
                     "%s() returns (%s) event(s) instead of (%s)",
                     iomux_call_en2str(iomux),
                     iomux_event_rpc2str(event.revents),
                     iomux_event_rpc2str(expected_revents));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
