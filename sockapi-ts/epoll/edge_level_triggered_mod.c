/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-edge_level_triggered_mod On-the-fly edge-triggered mode modification
 *
 * @objective Check that modification of triggered mode correctly effects
 *            @b epoll_wait() function.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param is_pipe       Whether we test a pipe or a pair of connected
 *                      sockets
 * @param sock_type     Type of sockets using in the test
 * @param evts          One of @c in, @c out or @c inout
 * @param data_size     The amount of data to be sent
 * @param timeout       Timeout for @b epoll_wait() function
 * @param et_to_lt      Check edge to level-triggered mode modification if
 *                      it is @c TRUE or level to edge-triggered mode
 *                      modification if it is @c FALSE
 * @param non_blocking  Test blocking or non-blocking call of
 *                      @b epoll_wait()
 *
 * @par Test sequence:
 *
 * -# Create a pair of connected fds (i.e. pairs of pipe ends or
 *    connected sockets) - (@p iut_fd, @p tst_fd).
 * -# Create @p epfd using @b epoll_create() function.
 * -# Add the fd to @p epfd according to @p et_to_lt parameter:
 *    - If @p et_to_lt is @c TRUE add @p iut_fd in edge-triggered
 *      mode with the events according to @p evts parameter
 *    - If @p et_to_lt is @c FALSE add @p iut_fd in level-triggered
 *      mode with the events according to @p evts parameter
 * -# Produce events for the @p iut_fd. In case of
 *    @c out and @c inout events do nothing because there is already write
 *    events. In case of @c in event send @p data_size bytes of data from
 *    @p tst_fd to @p iut_fd.
 * -# Call @b epoll_wait() on @p epfd with @p timeout according to
 *    @p non_blocking parameter.
 * -# Check that @b epoll_wait() returns @c 1 with the events according to
 *    @p evts parameter for @p iut_fd.
 * -# Call @b epoll_wait() on @p epfd with zero timeout.
 * -# Check that @b epoll_wait() returns @c 0 in case of @c TRUE
 *    @p el_to_lt and @c 1 with the events according to @p evts parameter
 *    in case of @c FALSE @p el_to_lt.
 * -# Switch modes for the fd using @b epoll_ctl(@c EPOLL_CTL_MOD) to
 *    the opposite mode (edge-triggered to level-triggered and vice versa).
 * -# Call @b epoll_wait() on @p epfd with zero timeout.
 * -# Check that @b epoll_wait() returns @c 1 with the events according to
 *    @p evts parameter for @p iut_fd.
 * -# Call @b epoll_wait() on @p epfd with zero timeout once again.
 * -# Check that @b epoll_wait() returns @c 0 in case of @c FALSE
 *    @p el_to_lt and @c 1 with the events according to @p evts parameter
 *    in case of @c TRUE @p el_to_lt.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/edge_level_triggered_mod"

#include "sockapi-test.h"
#include "epoll_common.h"

#define MAX_BUFF_SIZE 1024
int
main(int argc, char *argv[])
{
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
    int                     timeout;
    te_bool                 et_to_lt;
    te_bool                 non_blocking;
    te_bool                 is_pipe = FALSE;
    te_bool                 is_failed = FALSE;
    te_bool                 early_ctl;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(et_to_lt);
    TEST_GET_BOOL_PARAM(non_blocking);
    TEST_GET_BOOL_PARAM(is_pipe);
    TEST_GET_BOOL_PARAM(early_ctl);
    if (!is_pipe)
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_iut, iut_addr);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_SOCK_TYPE(sock_type);
    }

    if (non_blocking)
        timeout = 0;

    PARSE_EVTS(evts, event, exp_ev);
    if (et_to_lt)
        event |= RPC_EPOLLET;

    GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, is_pipe, sock_type,
                           iut_addr, tst_addr, iut_fd, tst_fd,
                           (is_pipe ? ((exp_ev & RPC_EPOLLOUT) ?
                                        TRUE : FALSE) : TRUE),
                           TRUE, epfd, early_ctl, event);

    GET_FD2_PCO(pco_iut, pco_tst, pco_tst, is_pipe, iut_fd, tst_fd);

    if (exp_ev == RPC_EPOLLIN)
    {
        RPC_WRITE(rc, pco_tst, tst_fd, buffer, data_size);
        TAPI_WAIT_NETWORK;
    }

    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);

    if (rc != 1)
    {
        RING_VERDICT("The first epoll_wait() call returned %d "
                     "instead of 1", rc);
        is_failed = TRUE;
    }
    else if (events[0].data.fd != iut_fd)
    {
        TEST_FAIL("epoll_wait retured incorrect fd %d instead of %d",
                  events[0].data.fd, iut_fd);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("epoll_wait returned incorrect events");

    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);

    if (et_to_lt)
    {
        if (rc != 0)
        {
            RING_VERDICT("The second epoll_wait() call returned %d "
                         "instead of 0", rc);
            is_failed = TRUE;
        }
    }
    else if (rc != 1)
    {
        RING_VERDICT("The second epoll_wait() call returned %d "
                     "instead of 1", rc);
        is_failed = TRUE;
    }
    else if (events[0].data.fd != iut_fd)
    {
        TEST_FAIL("epoll_wait retured incorrect fd %d instead of %d",
                  events[0].data.fd, iut_fd);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("epoll_wait returned incorrect events");

    if (et_to_lt)
        event &= ~RPC_EPOLLET;
    else
        event |= RPC_EPOLLET;
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_MOD, iut_fd, event);

    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);

    if (rc != 1)
    {
        RING_VERDICT("The third epoll_wait() call returned %d "
                     "instead of 1", rc);
        is_failed = TRUE;
    }
    else if (events[0].data.fd != iut_fd)
    {
        TEST_FAIL("epoll_wait retured incorrect fd %d instead of %d",
                  events[0].data.fd, iut_fd);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("epoll_wait returned incorrect events");

    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);

    if (!et_to_lt)
    {
        if (rc != 0)
        {
            RING_VERDICT("The fourth epoll_wait() call returned %d "
                         "instead of 0", rc);
            is_failed = TRUE;
        }
    }
    else if (rc != 1)
    {
        RING_VERDICT("The fourth epoll_wait() call returned %d "
                     "instead of 1", rc);
        is_failed = TRUE;
    }
    else if (events[0].data.fd != iut_fd)
    {
        TEST_FAIL("epoll_wait retured incorrect fd %d instead of %d",
                  events[0].data.fd, iut_fd);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("epoll_wait returned incorrect events");

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);

    if (is_pipe && pco_tst != NULL)
        rcf_rpc_server_destroy(pco_tst);

    TEST_END;
}
