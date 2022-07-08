/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-epoll_dead_circle Call two epoll_wait() functions with fd of each other in their epfd's.
 *
 * @objective Check that potentially infinite loop which can take place
 *            after an event occurs on some fd in epfd of one of epoll_wait()
 *            functions having epfd of each other in their epfds doesn't
 *            cause any error.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_addr          Network address on IUT
 * @param set_sock_evt      Whether to set @c RPC_EPOLLIN event
 *                          on socket or to set @c 0.
 *
 * @par Test sequence:
 *
 * -# Create socket @p iut_s on @p pco_iut, @b bind() it to @p iut_addr
 *    address and make it listening. Create socket @p tst_s on @p pco_tst.
 * -# Create @p epfd1, @p epfd2. Add @p iut_s and @p epfd2 to @p epfd1
 *    and @p epfd1 to @p epfd2 with help of @b epoll_ctl (@c
 *    EPOLL_CTL_ADD). @p iut_s must or must not have @c EPOLLIN event
 *    according to @p set_sock_evt parameter, others must have @c EPOLLIN
 *    event specified.
 * -# Connect @p tst_s to @p iut_addr.
 * -# Check readability of @p epfd1 and @epfd2 with help of @b poll() call.
 * -# Call @b epoll_wait() for @p epfd1 and @p epfd2.
 * -# Call @b poll() again and check readability of @p epfd1 and @p epfd2
 *    again.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "epoll/epoll_dead_circle"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    iomux_call_type iomux;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    int iut_s = -1;
    int tst_s = -1;
    int epfd1 = -1;
    int epfd2 = -1;

    struct rpc_epoll_event events1[2];
    struct rpc_epoll_event events2[1];
    iomux_evt_fd           events[2];
    tarpc_timeval          tv;

    int i = 0;

    te_bool set_sock_evt = FALSE;

    /* Preambule */

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(set_sock_evt);

    /* Scenario */

    epfd1 = rpc_epoll_create(pco_iut, 2);
    epfd2 = rpc_epoll_create(pco_iut, 1);

    memset(events1, 0, sizeof(events1));
    memset(events2, 0, sizeof(events2));
    memset(events, 0, sizeof(events));

    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, TRUE, iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_epoll_ctl_simple(pco_iut, epfd1, RPC_EPOLL_CTL_ADD, iut_s,
                         set_sock_evt ? RPC_EPOLLIN : 0);
    rpc_epoll_ctl_simple(pco_iut, epfd1, RPC_EPOLL_CTL_ADD, epfd2,
                         RPC_EPOLLIN);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_epoll_ctl_simple(pco_iut, epfd2, RPC_EPOLL_CTL_ADD, epfd1,
                         RPC_EPOLLIN);
    if (rc == -1)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ELOOP,
                        "epoll_ctl() returned -1 but");
        TEST_SUCCESS;
    }

    events[0].fd = epfd1;
    events[0].events = EVT_RD;
    events[1].fd = epfd2;
    events[1].events = EVT_RD;
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    rpc_connect(pco_tst, tst_s, iut_addr);

    TAPI_WAIT_NETWORK;

    iomux_call(IC_DEFAULT, pco_iut, events, 2, &tv);
    if ((events[0].revents & EVT_RD) && !set_sock_evt)
        RING("An event for socket was not set, but "
             "corresponding epfd1 is noted readable ");

    if (events[1].revents & EVT_RD)
        RING("epfd2 is noted readable ");

    rc = iomux_epoll_call(iomux, pco_iut, epfd2, events2, 1, 0);
    if (rc != 1)
        RING("epoll_wait() call with epfd2 returned %d instead of 1",
             rc);
    else
    {
        if (events2[0].data.fd != epfd1)
            RING("epoll_wait() call with epfd2 returned %d fd "
                 "instead of %d(epfd1)",
                 events2[0].data.fd, epfd1);
        else if (events2[0].events & RPC_EPOLLIN)
            RING("epoll_wait() call with epfd2 noted that epfd1 is "
                 "readable");
    }

    rc = iomux_epoll_call(iomux, pco_iut, epfd1, events1, 2, 0);
    if (rc > 2)
        RING("epoll_wait() call returned strange result");

    for (i = 0; i < rc; i++)
    {
        if (events1[i].data.fd == epfd2 &&
            (events1[i].events & RPC_EPOLLIN))
        {
            RING("epoll_wait() call with epfd1 noted that epfd2"
                 " is readable after epoll_wait() call with epfd2");
            break;
        }
    }

    if (i == rc)
        RING("epoll_wait() call with epfd1 didn't note that epfd2 "
             "is readable");

    iomux_call(IC_DEFAULT, pco_iut, events, 2, &tv);
    if (events[0].revents & EVT_RD)
        RING("epfd1 is noted readable "
             "after epoll_wait() call with it");

    if (events[1].revents & EVT_RD)
        RING("epfd2 is noted readable "
             "after epoll_wait() call with it");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd1);
    CLEANUP_RPC_CLOSE(pco_iut, epfd2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
