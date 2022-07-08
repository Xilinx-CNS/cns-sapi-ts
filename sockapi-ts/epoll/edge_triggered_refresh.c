/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-edge_triggered_refresh The behaviour of epoll_ctl() function in edge-triggered mode
 *
 * @objective Check that epoll_ctl() refreshes events for the socket in
 *            edge-triggered mode.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param sock_type     Type of sockets using in the test
 * @param sock_state    "just_created" (socket under testing is
 *                      created but not connected) or "connected"
 * @param evts          One of @c in, @c out or @c inout
 * @param data_size     The amount of data to be sent
 * @param timeout1      Timeout for @b epoll_wait() function when it's
 *                      expected that some events will be returned
 * @param timeout2      Timeout for @b epoll_wait() function when it's
 *                      not expected that some events will be
 *                      returned
 * @param non_blocking  If @c TRUE, @p timeout1 will be considered as 0
 *
 * @par Test sequence:
 *
 * -# If we test sockets and @p sock_state is "just_created", create
 *    @p iut_fd socket on @p pco_iut. Otherwise create a pair of
 *    connected fds (i.e. pairs of pipe ends or connected sockets) -
 *    (@p iut_fd, @p tst_fd).
 * -# Create @p epfd with @p iut_fd file descriptor and with the events
 *    according to @p evts parameter with @c EPOLLET flag using
 *    @b epoll_create() and @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# If @p evts is @c in event and @p sock_state is not "just_created",
 *    send @p data_size bytes of data from @p tst_fd fd to @p iut_fd to
 *    produce events on @p iut_fd fd in case of @c EPOLLIN events.
 * -# Call @b epoll_wait() on @p epfd with @p timeout1 timeout.
 * -# Check that @b epoll_wait() returns @c 1 with the events according to
 *    @p evts parameter for @p iut_fd.
 * -# Call @b epoll_wait() on @p epfd once again with @p timeout2 timeout
 *    to check that edge-triggered mode works correctly i.e. there are no
 *    events on @p iut_fd fd.
 * -# Check that @b epoll_wait() returns @c 0.
 * -# Call @b epoll_ctl(@c EPOLL_CTL_MOD) on @p iut_fd fd with the same
 *    events.
 * -# Call @b epoll_wait() on @p epfd with @p timeout timeout1 to check
 *    that @b epoll_ctl() refreshes events on @p iut_fd fd i.e.
 *    @b epoll_wait() detect events for this fd though there is no action
 *    except @p epoll_ctl() call with @p iut_fd fd.
 * -# Check that @b epoll_wait() returns @c 1 with the events according to
 *    @p evts parameter for @p iut_fd.
 * -# Call @b epoll_wait() on @p epfd once again with @p timeout2 timeout
 *    to check that edge-triggered mode still works correctly i.e. there
 *    are no events on @p iut_fd fd.
 * -# Check that @b epoll_wait() returns @c 0.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/edge_triggered_refresh"

#include "sockapi-test.h"
#include "iomux.h"
#include "epoll_common.h"

#define MAX_BUFF_SIZE 1024
int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_fd = -1;
    int                     tst_fd = -1;

    rpc_socket_type         sock_type;

    const char             *evts;

    int                     data_size;
    unsigned char           buffer[MAX_BUFF_SIZE];

    int                     epfd = -1;
    struct rpc_epoll_event  events[2];
    uint32_t                event;
    int                     maxevents = 2;

    uint32_t                exp_ev;
    int                     timeout1;
    int                     timeout2;
    te_bool                 non_blocking;
    te_bool                 is_pipe;
    te_bool                 early_ctl;

    const char             *sock_state = "";

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout1);
    TEST_GET_INT_PARAM(timeout2);
    TEST_GET_BOOL_PARAM(non_blocking);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(is_pipe);
    TEST_GET_BOOL_PARAM(early_ctl);
    if (!is_pipe)
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_iut, iut_addr);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_SOCK_TYPE(sock_type);
        TEST_GET_STRING_PARAM(sock_state);
    }

    if (non_blocking)
        timeout1 = 0;
    PARSE_EVTS(evts, event, exp_ev);
    event |= RPC_EPOLLET;

    if (strcmp(sock_state, "just_created") == 0)
    {
        epfd = rpc_epoll_create(pco_iut, 1);
        iut_fd = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_fd,
                             event);
    }
    else
    {
        GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, is_pipe, sock_type,
                               iut_addr, tst_addr, iut_fd, tst_fd,
                               (is_pipe ? ((exp_ev & RPC_EPOLLOUT) ?
                                                TRUE : FALSE) : TRUE),
                               TRUE, epfd, early_ctl, event);
        GET_FD2_PCO(pco_iut, pco_tst, pco_tst, is_pipe, iut_fd, tst_fd);
    }

    if (strcmp(sock_state, "just_created") == 0)
    {
        exp_ev = 0;
        if (strcmp(evts, "in") != 0)
            exp_ev = RPC_EPOLLOUT;
        exp_ev |= RPC_EPOLLHUP;
    }

    if (exp_ev == RPC_EPOLLIN && strcmp(sock_state, "just_created") != 0)
    {
        RPC_WRITE(rc, pco_tst, tst_fd, buffer, data_size);
        TAPI_WAIT_NETWORK;
    }

    rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                          maxevents, timeout1);

    if (rc != 1)
    {
        TEST_FAIL("%s() returned %d instead of 1",
                  iomux_call_en2str(iomux), rc);
    }
    else if (events[0].data.fd != iut_fd)
    {
        TEST_FAIL("%s() returned incorrect fd %d instead of %d",
                  iomux_call_en2str(iomux), events[0].data.fd, iut_fd);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("%s() returned incorrect events",
                  iomux_call_en2str(iomux));

    rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                          maxevents, timeout2);

    if (rc != 0)
    {
        if (rc == 1 && events[0].data.fd == iut_fd &&
            events[0].events == exp_ev)
        {
            RING_VERDICT("%s returned the same events for the second call",
                         iomux_call_en2str(iomux));
            rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents,
                                  timeout2);
            if (rc != 0)
                TEST_VERDICT("iomux_epoll_call() returned incorrect "
                             "events for the third call");

        }
        else
            TEST_VERDICT("iomux_epoll_call() returned incorrect events "
                         "for the second call");
    }

    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_MOD, iut_fd, event);

    /* Wait for incoming packet in case of non-blocking epoll_wait() */
    if (non_blocking)
        TAPI_WAIT_NETWORK;
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                          maxevents, timeout1);

    if (rc != 1)
    {
        TEST_FAIL("%s() returned %d instead of 1",
                  iomux_call_en2str(iomux), rc);
    }
    else if (events[0].data.fd != iut_fd)
    {
        TEST_FAIL("%s() returned incorrect fd %d instead of %d",
                  iomux_call_en2str(iomux), events[0].data.fd, iut_fd);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("%s() returned incorrect events",
                  iomux_call_en2str(iomux));

    rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                          maxevents, timeout2);
    if (rc != 0)
    {
        if (rc == 1 && events[0].data.fd == iut_fd &&
            events[0].events == exp_ev)
        {
            RING_VERDICT("%s returned the same events for the second call "
                         "after refreshing", iomux_call_en2str(iomux));
            rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents,
                                  timeout2);
            if (rc != 0)
                TEST_VERDICT("iomux_epoll_call() returned incorrect "
                             "events for the third call after refreshing");

        }
        else
            TEST_VERDICT("iomux_epoll_call() returned incorrect events "
                         "for the second call");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);

    if (is_pipe && pco_tst != NULL)
        rcf_rpc_server_destroy(pco_tst);

    TEST_END;
}
