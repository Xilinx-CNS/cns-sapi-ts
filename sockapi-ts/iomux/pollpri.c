/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page sendrecv-pollpri Behavior of iomux functions when out-of-band data is received
 *
 * @objective Check that @b poll()/ @b ppoll/ @b epoll_wait() /
 *            @b epoll_pwait()/ @b epoll_pwait2() functions returns
 *            @c POLLPRI (@c EPOLLPRI)
 *            event when there is available OOB data on the socket.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TST
 *
 * -# Create connection of the @c SOCK_STREAM type between @p pco_iut and
 *    @p pco_tst by means of @c GEN_CONNECTION;
 * -# Call @p iomux function and check it returns 0;
 * -# @b send() one byte data through @p tst_s with @c MSG_OOB flag;
 * -# Call @p iomux function and check it returns @c POLLPRI (@c EPOLLPRI)
 *    event;
 * -# If @p read_after_oob is @c TRUE read @e out-of-band data from
 *    the socket;
 * -# send normal data prom the peer;
 * -# Call @p iomux one again and check that it returns @c POLLIN when
 *    @p read_after_oob is @c TRUE or @c POLLIN | @c POLLPRI when
 *    @p read_after_oob is @c TRUE ;
 * -# Check that @b recv() returns -1 and @e errno set to the @c EINVAL;
 * -# Close @p iut_s and @p tst_s sockets;
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/pollpri"

#include "sockapi-test.h"
#include "iomux.h"

#define TST_BUF_SIZE            100

static void
set_tv_ptr_from_timeout(struct tarpc_timespec *tv_ptr, int timeout)
{
    if (timeout < 0)
        tv_ptr = NULL;
    else
        TE_NS2TS(TE_MS2NS(timeout), tv_ptr);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;

    const struct sockaddr       *iut_addr;
    const struct sockaddr       *tst_addr;

    char                         tx_buf[TST_BUF_SIZE];
    char                         rx_buf[TST_BUF_SIZE];
    int                          iut_s = -1;
    int                          tst_s = -1;

    int                          sent;

    struct rpc_pollfd       fds;
    struct tarpc_timespec   ts;
    int epfd = -1;
    struct rpc_epoll_event  events[2];
    uint32_t                event;
    int                     maxevents = 2;

    const char             *add_flags;
    uint32_t                add_event = 0;
    int                     timeout;
    te_bool                 read_after_oob;

    iomux_call_type         iomux;
    uint32_t                exp_event;
    uint32_t                got_event;

    te_bool                 second_call = TRUE;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_STRING_PARAM(add_flags);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(read_after_oob);

    /* Scenario */
    memset(&fds, 0, sizeof(fds));

    if (strcmp(add_flags, "epollet") == 0)
        add_event = RPC_EPOLLET;
    else if (strcmp(add_flags, "epolloneshot") == 0)
        add_event = RPC_EPOLLONESHOT;

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr,  &iut_s, &tst_s);

    switch (iomux)
    {
        case TAPI_IOMUX_POLL:
        case TAPI_IOMUX_PPOLL:
            fds.fd = iut_s;
            fds.events = RPC_POLLIN | RPC_POLLPRI;
            TE_NS2TS(TE_MS2NS(timeout), &ts);
            break;

        case TAPI_IOMUX_EPOLL_PWAIT2:
            set_tv_ptr_from_timeout(&ts, timeout);
            /*@fallthrough@*/

        case TAPI_IOMUX_EPOLL:
        case TAPI_IOMUX_EPOLL_PWAIT:
            epfd = rpc_epoll_create(pco_iut, 1);

            event = RPC_EPOLLIN | RPC_EPOLLPRI | add_event;
            rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                                 event);
            memset(events, 0, sizeof(events));
            break;

        default:
            TEST_FAIL("Incorrect value of 'iomux' parameter");
    }
    switch (iomux)
    {
        case TAPI_IOMUX_POLL:
            rc = rpc_poll(pco_iut, &fds, 1, timeout);
            break;

        case TAPI_IOMUX_PPOLL:
            rc = rpc_ppoll(pco_iut, &fds, 1, &ts, RPC_NULL);
            break;

        case TAPI_IOMUX_EPOLL:
            rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);
            break;

        case TAPI_IOMUX_EPOLL_PWAIT:
            rc = rpc_epoll_pwait(pco_iut, epfd, events, maxevents, timeout,
                                 RPC_NULL);
            break;

        case TAPI_IOMUX_EPOLL_PWAIT2:
            rc = rpc_epoll_pwait2(pco_iut, epfd, events, maxevents, &ts,
                                  RPC_NULL);
            break;

       default:
            TEST_FAIL("Incorrect value of 'iomux' parameter");
    }
    if (rc != 0)
        TEST_FAIL("iomux function returned incorrect value in case of no "
                  "data on socket");

    RPC_SEND(sent, pco_tst, tst_s, tx_buf, 1, RPC_MSG_OOB);
    MSLEEP(100);

    switch (iomux)
    {
        case TAPI_IOMUX_POLL:
        case TAPI_IOMUX_PPOLL:
            ts.tv_sec = 1;
            ts.tv_nsec = 0;
            exp_event = RPC_POLLPRI;
            break;

        case TAPI_IOMUX_EPOLL_PWAIT2:
            set_tv_ptr_from_timeout(&ts, timeout);
            /*@fallthrough@*/

        case TAPI_IOMUX_EPOLL:
        case TAPI_IOMUX_EPOLL_PWAIT:
            memset(events, 0, sizeof(events));
            exp_event = RPC_EPOLLPRI;
            break;

        default:
            TEST_FAIL("Incorrect value of 'iomux' parameter");
    }
    switch (iomux)
    {
        case TAPI_IOMUX_POLL:
            rc = rpc_poll(pco_iut, &fds, 1, 1000);
            got_event = fds.revents;
            break;

        case TAPI_IOMUX_PPOLL:
            rc = rpc_ppoll(pco_iut, &fds, 1, &ts, RPC_NULL);
            got_event = fds.revents;
            break;

        case TAPI_IOMUX_EPOLL:
            rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);
            got_event = events[0].events;
            break;

        case TAPI_IOMUX_EPOLL_PWAIT:
            rc = rpc_epoll_pwait(pco_iut, epfd, events, maxevents, timeout,
                                 RPC_NULL);
            got_event = events[0].events;
            break;

        case TAPI_IOMUX_EPOLL_PWAIT2:
            rc = rpc_epoll_pwait2(pco_iut, epfd, events, maxevents, &ts,
                                  RPC_NULL);
            got_event = events[0].events;
            break;

        default:
            TEST_FAIL("Incorrect value of 'iomux' parameter");
    }

    if (rc != 1)
        TEST_VERDICT("iomux function returned incorrect value in case of "
                     "oob data on socket");
    else if (exp_event != got_event)
        TEST_VERDICT("iomux function returned incorrect events in case of "
                     "oob data on socket");

    if (strcmp(add_flags, "none") != 0)
    {
        memset(events, 0, sizeof(events));
        switch (iomux)
        {
            case TAPI_IOMUX_EPOLL:
                rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);
                if (rc == 1 && events[0].events == RPC_EPOLLPRI)
                {
                    second_call = FALSE;
                    RING_VERDICT("iomux function returned the same events in "
                                 "case of oob data on socket on the second "
                                 "call");
                    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents,
                                        timeout);
                }
                break;

            case TAPI_IOMUX_EPOLL_PWAIT:
                rc = rpc_epoll_pwait(pco_iut, epfd, events, maxevents, timeout,
                                     RPC_NULL);
                if (rc == 1 && events[0].events == RPC_EPOLLPRI)
                {
                    second_call = FALSE;
                    RING_VERDICT("iomux function returned the same events in "
                                 "case of oob data on socket on the second "
                                 "call");
                    rc = rpc_epoll_pwait(pco_iut, epfd, events, maxevents,
                                         timeout, RPC_NULL);
                }
                break;

            case TAPI_IOMUX_EPOLL_PWAIT2:
                set_tv_ptr_from_timeout(&ts, timeout);
                rc = rpc_epoll_pwait2(pco_iut, epfd, events, maxevents, &ts,
                                      RPC_NULL);
                if (rc == 1 && events[0].events == RPC_EPOLLPRI)
                {
                    second_call = FALSE;
                    RING_VERDICT("iomux function returned the same events in "
                                 "case of oob data on socket on the second "
                                 "call");
                    set_tv_ptr_from_timeout(&ts, timeout);
                    rc = rpc_epoll_pwait2(pco_iut, epfd, events, maxevents,
                                          &ts, RPC_NULL);
                }
                break;

            default:
                TEST_FAIL("Incorrect value of 'iomux' parameter "
                          "when flags are added");
        }
    }
    second_call = TRUE;

    if (read_after_oob)
        rpc_recv(pco_iut, iut_s, rx_buf, TST_BUF_SIZE, RPC_MSG_OOB);
    TAPI_WAIT_NETWORK;

    RPC_SEND(sent, pco_tst, tst_s, tx_buf, 1, 0);
    TAPI_WAIT_NETWORK;

    switch (iomux)
    {
        case TAPI_IOMUX_POLL:
        case TAPI_IOMUX_PPOLL:
            fds.fd = iut_s;
            fds.events = RPC_POLLIN | RPC_POLLPRI;
            ts.tv_sec = 1;
            ts.tv_nsec = 0;
            exp_event = read_after_oob ? RPC_POLLIN :
                                         RPC_POLLPRI | RPC_POLLIN;
            break;

        case TAPI_IOMUX_EPOLL_PWAIT2:
            set_tv_ptr_from_timeout(&ts, timeout);
            /*@fallthrough@*/

        case TAPI_IOMUX_EPOLL:
        case TAPI_IOMUX_EPOLL_PWAIT:
            if (strcmp(add_flags, "epolloneshot") == 0)
            {
                event = RPC_EPOLLIN | RPC_EPOLLPRI | add_event;
                rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_MOD, iut_s,
                                     event);
            }
            memset(events, 0, sizeof(events));
            exp_event = read_after_oob ? RPC_EPOLLIN :
                                         RPC_EPOLLPRI | RPC_EPOLLIN;
            break;

        default:
            TEST_FAIL("Incorrect value of 'iomux' parameter");
    }
    switch (iomux)
    {
        case TAPI_IOMUX_POLL:
            rc = rpc_poll(pco_iut, &fds, 1, 1000);
            got_event = fds.revents;
            break;

        case TAPI_IOMUX_PPOLL:
            rc = rpc_ppoll(pco_iut, &fds, 1, &ts, RPC_NULL);
            got_event = fds.revents;
            break;

        case TAPI_IOMUX_EPOLL:
            rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);
            got_event = events[0].events;
            break;

        case TAPI_IOMUX_EPOLL_PWAIT:
            rc = rpc_epoll_pwait(pco_iut, epfd, events, maxevents, timeout,
                                 RPC_NULL);
            got_event = events[0].events;
            break;

        case TAPI_IOMUX_EPOLL_PWAIT2:
            rc = rpc_epoll_pwait2(pco_iut, epfd, events, maxevents, &ts,
                                  RPC_NULL);
            got_event = events[0].events;
            break;

        default:
            TEST_FAIL("Incorrect value of 'iomux' parameter");
    }

    if (rc != 1)
        TEST_VERDICT("iomux function returned incorrect value in case of "
                     "normal%s data on socket",
                     read_after_oob ? "" : " and oob");
    else if (exp_event != got_event)
        TEST_VERDICT("iomux function returned incorrect events in case of "
                     "normal%s data on socket",
                     read_after_oob ? "" : " and oob");

    if (strcmp(add_flags, "none") != 0)
    {
        memset(events, 0, sizeof(events));
        switch (iomux)
        {
            case TAPI_IOMUX_EPOLL:
                rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);
                if (rc == 1 && events[0].events == exp_event)
                {
                    second_call = FALSE;
                    RING_VERDICT("iomux function returned the same events in "
                                 "case of normal data on socket on the second "
                                 "call");
                    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents,
                                        timeout);
                }
                break;

            case TAPI_IOMUX_EPOLL_PWAIT:
                rc = rpc_epoll_pwait(pco_iut, epfd, events, maxevents, timeout,
                                     RPC_NULL);
                if (rc == 1 && events[0].events == exp_event)
                {
                    second_call = FALSE;
                    RING_VERDICT("iomux function returned the same events in "
                                 "case of normal data on socket on the second "
                                 "call");
                    rc = rpc_epoll_pwait(pco_iut, epfd, events, maxevents,
                                         timeout, RPC_NULL);
                }
                break;

            case TAPI_IOMUX_EPOLL_PWAIT2:
                set_tv_ptr_from_timeout(&ts, timeout);
                rc = rpc_epoll_pwait2(pco_iut, epfd, events, maxevents, &ts,
                                      RPC_NULL);
                if (rc == 1 && events[0].events == exp_event)
                {
                    second_call = FALSE;
                    RING_VERDICT("iomux function returned the same events in "
                                 "case of normal data on socket on the second "
                                 "call");
                    set_tv_ptr_from_timeout(&ts, timeout);
                    rc = rpc_epoll_pwait2(pco_iut, epfd, events, maxevents,
                                          &ts, RPC_NULL);
                }
                break;

            default:
                TEST_FAIL("Incorrect value of 'iomux' parameter "
                          "when flags are added");
        }
        if (rc != 0)
            TEST_VERDICT("iomux function returned incorrect value in case of "
                         "normal%s data on socket on the %s call",
                         read_after_oob ? "" : " and oob",
                         second_call ? "second" : "third");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

