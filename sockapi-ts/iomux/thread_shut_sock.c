/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-thread_shut_sock Socket is shutdowned from another thread
 *
 * @objective Check I/O multiplexing functions behaviour when socket is
 *            shutdowned from another thread.
 *
 * @type conformance, compatibility
 *
 * @requirement REQ-1, REQ-2, REQ-3, REQ-13
 *
 * @param pco_iut1  IUT thread #1
 * @param pco_iut2  IUT thread #2
 * @param pco_tst   Auxiliary PCO
 * @param iut_addr  Address/port to be used to connect to @p pco_iut1
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll()) should be called
 *                  in thread #1
 * @param howto     SHUT_RD, SHUT_WR, SHUT_RDWR - action which should be
 *                  performed by @b shutdown() called in thread #2
 * @param event     One of EVT_RD, EVT_WR, EVT_RDWR
 * @param ready     Is the socket already shut down before iomux call?
 *
 * @par Scenario:
 * -# Create stream connection by means of @c GEN_CONNECTION() and return
 *    @p iut_s (@p pco_iut1 thread) and @p pco_tst;
 * -# Prepare conditions to block @b iomux() function on appropriate events;
 * -# Call @p iomux function on @p pco_iut1 and with 3 seconds timeout
 *    for waiting an appropriate @p event;
 * -# @b shutdown() @p iut_s for @p howto on @p pco_iut2;
 * -# Check that @b iomux function returns @p expected value and 
 *    correctly process returned 'revents';
 * -# If @b iomux missed some expected readable/writable event(s),
 *    try to call it one more time and check results again.
 * -# Close @b iut_s and @b tst_s sockets.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/thread_shut_sock"
#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;
    rpc_shut_how            howto;
    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    const char             *check_event;
    iomux_evt_fd            event;
    iomux_evt               ck_event = 0;

    uint64_t                total_filled = 0;

    tarpc_timeval           timeout;
    te_bool                 overfill = FALSE;
    te_bool                 ready;
    iomux_evt               expected = FALSE;
    int                     rcvd_rw_evts;
    int                     exp_rw_evts;
    int                     missed_rw_evts;
    int                     unexp_rw_evts;
    int                     exp_rc;
    te_bool                 recall_iomux = FALSE;
    int                     loop_cnt = 0;
    te_bool                 is_failed = FALSE;
    char                   *str = "";

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_SHUT_HOW(howto);
    TEST_GET_STRING_PARAM(check_event);
    TEST_GET_BOOL_PARAM(ready);

    memset(&event, 0, sizeof(event));

    /* Scenario */
    GEN_CONNECTION(pco_tst, pco_iut1, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    if (ready)
        timeout.tv_sec = 0;
    else
        timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    event.fd = iut_s;

    if (strcmp(check_event, "EVT_RD") == 0)
    {
       ck_event = event.events = EVT_RD;
    }
    else if (strcmp(check_event, "EVT_WR") == 0)
    {
        ck_event = event.events = EVT_WR;
        overfill = TRUE;
    }
    else if (strcmp(check_event, "EVT_RDWR") == 0)
    {
        ck_event = event.events = EVT_RDWR;
        overfill = TRUE;
    }
    else
    {
        TEST_FAIL("Unexpected event - %s", check_event);
    }

    if ((howto == RPC_SHUT_RDWR || howto == RPC_SHUT_RD) &&
        (ck_event & EVT_RD))
        expected = EVT_RD;
    if ((howto == RPC_SHUT_RDWR || howto == RPC_SHUT_WR) &&
        (ck_event & EVT_WR))
        expected |= EVT_WR;

    if (overfill)
    {
        rpc_overfill_buffers_gen(pco_iut1, iut_s, &total_filled,
                                 iomux == IC_OO_EPOLL ? IC_EPOLL : iomux);
        RING("To overfill the both send and received buffers "
             "%d bytes are written", (unsigned int)total_filled);
    }

    if (!ready)
    {
        pco_iut1->op = RCF_RPC_CALL;
        iomux_call(iomux, pco_iut1, &event, 1, &timeout);
        TAPI_WAIT_NETWORK;
    }

    rpc_shutdown(pco_iut2, iut_s, howto);
    TAPI_WAIT_NETWORK;

    if (!ready)
    {
        if (expected) {
            te_bool iomux_done;
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut1, &iomux_done));
            if (!iomux_done)
                RING_VERDICT("Iomux function does not return in time");
        }
        pco_iut1->op = RCF_RPC_WAIT;
    }

    do {
        rc = iomux_call(iomux, pco_iut1, &event, 1, &timeout);

        if (rc == -1)
            TEST_FAIL("iomux_call() failed");
        RING("%s() returned %d, revents %x",
             iomux_call_en2str(iomux), rc, event.revents);

        if (expected)
        {
            /* For safety, check rc value */
            exp_rc = IOMUX_IS_POLL_LIKE(iomux) ? 1 :
                !!(expected & EVT_RD) + !!(expected & EVT_WR);
            if (rc != (int)exp_rc)
            {
                RING_VERDICT("%s%s() returned unexpected number of "
                             "events: %d instead of %d", str,
                             iomux_call_en2str(iomux), rc, exp_rc);
                is_failed = TRUE;
            }

            /* On SHUT_WR, POLLHUP should be set */
            if (howto == RPC_SHUT_RDWR && IOMUX_IS_POLL_LIKE(iomux))
            {
                if ((event.revents & EVT_HUP) == 0)
                {
                    RING_VERDICT("%sPOLLHUP is not returned when "
                                 "shutdown(SHUT_RDWR) is called", str);
                }
            }
            else
            {
                if ((event.revents & EVT_HUP) != 0)
                {
                    RING_VERDICT("%sPOLLHUP is unexpectedly set", str);
                    is_failed = TRUE;
                }
            }

            /* Check read/write events */
            if ((event.revents & (EVT_RD | EVT_WR)) != expected)
            {
                rcvd_rw_evts = (event.revents & (EVT_RD | EVT_WR));
                exp_rw_evts = (expected & (EVT_RD | EVT_WR));
                missed_rw_evts = exp_rw_evts & ~(rcvd_rw_evts & exp_rw_evts);
                unexp_rw_evts = rcvd_rw_evts & ~(rcvd_rw_evts & exp_rw_evts);

                if (unexp_rw_evts > 0)
                {
                    is_failed = TRUE;
                    RING_VERDICT("%s%s unexpected event(s)",
                                 str,
                                 iomux_event_rpc2str(unexp_rw_evts));
                }

                if (missed_rw_evts > 0)
                {
                    if (howto == RPC_SHUT_RDWR && loop_cnt == 0 &&
                        rcvd_rw_evts > 0)
                    {
                        recall_iomux = TRUE;
                        str = "[the second iomux call] ";
                        RING_VERDICT("The first iomux call after "
                                     "shutdown(RDWR) returned only %s "
                                     "event",
                                     iomux_event_rpc2str(rcvd_rw_evts));
                    }
                    else
                    {
                        is_failed = TRUE;
                        RING_VERDICT("%s%s missed event(s)",
                                     str,
                                     iomux_event_rpc2str(missed_rw_evts));
                    }
                }
            }
        }
        else
        {
            if (rc != 0)
            {
                TEST_VERDICT("%s%s() have returned some events",
                             str, iomux_call_en2str(iomux));
            }
            if (event.revents != 0)
            {
                TEST_VERDICT("%sUnexpected that %s() does not clear "
                             "the events if returns on timeout", str,
                             iomux_call_en2str(iomux));
            }
        }

        loop_cnt++;
    } while (recall_iomux && loop_cnt < 2);

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
