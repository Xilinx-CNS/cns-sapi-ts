/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id: epoll_evnt_queue.c 63313 2010-03-11 08:21:35Z yuran $
 */

/** @page epoll-wait_epollet_wait Modifying epfd with descriptor with EPOLLET flag between epoll_wait calls
 *
 * @objective Check that modifying of descriptor with EPOLLET flag between
 *            two epoll_wait calls correctly handled by epoll_wait function.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param is_pipe       Whether we test a pipe or a pair of connected
 *                      sockets
 * @param sock_type     Type of sockets used in the test
 * @param evts          One of @c in, @c out or @c inout
 * @param timeout       Timeout for @b epoll_wait() function
 * @param data_size     The amount of data to be sent
 * @param non_blocking  Test blocking or non-blocking call of
 *                      @b epoll_wait()
 *
 * @par Test sequence:
 *
 * -# Create a pair of connected fds (i.e. pairs of pipe ends or
 *    connected sockets) - (@p iut_fd, @p tst_fd).
 * -# Create @p epfd with @p iut_fd fd and with the events according to
 *    @p evts parameter using @b epoll_create() and
 *    @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# If @p evts is @c in send @p data_size bytes of data from @p tst_fd
 *    to @p iut_fd. In other cases there is already write event.
 * -# Call @b epoll_wait(@p epfd) with @p timeout according to
 *    @p non_blocking parameter.
 * -# Check that @b epoll_wait() returns @c 1 with the events according to
 *    @p evts paramter for @p iut_fd fd.
 * -# Modify events for @p iut_fd to the events according to @p evts
 *    parameter with @c EPOLLET flag using @b epoll_ctl(@c EPOLL_CTL_MOD)
 *    function.
 * -# Call @b epoll_wait(@p epfd) with zero timeout.
 * -# Check that @b epoll_wait() returns @c 1 with the events acording to
 *    @p evts parameter for @p iut_fd fd.
 * -# Call @b epoll_wait(@p epfd) with zero timeout.
 * -# Check that @b epoll_wait() returns @c 0.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/wait_epollet_wait"

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

    rpc_socket_type         sock_type = RPC_SOCK_UNKNOWN;

    const char             *evts;

    int                     data_size;
    unsigned char           buffer[MAX_BUFF_SIZE];

    int                     epfd = -1;
    struct rpc_epoll_event  events[2];
    uint32_t                event;
    int                     maxevents = 2;

    int                     timeout;
    uint32_t                exp_ev;
    te_bool                 non_blocking;
    te_bool                 is_pipe;
    te_bool                 early_ctl;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout);
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
    event |= RPC_EPOLLET;

    GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, is_pipe, sock_type,
                           iut_addr, tst_addr, iut_fd, tst_fd,
                           (is_pipe ? ((exp_ev & RPC_EPOLLOUT) ?
                                        TRUE : FALSE) : TRUE),
                           TRUE, epfd, early_ctl, event);

    GET_FD2_PCO(pco_iut, pco_tst, pco_tst, is_pipe, iut_fd, tst_fd);

    if (strcmp(evts, "in") == 0)
        RPC_WRITE(rc, pco_tst, tst_fd, buffer, data_size);

    /* Wait for incoming packet in case of non-blocking epoll_wait() */
    if (non_blocking)
        TAPI_WAIT_NETWORK;
    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);

    if (rc != 1)
    {
        TEST_FAIL("epoll_wait returned %d instead of 1", rc);
    }
    else if (events[0].data.fd != iut_fd)
    {
        TEST_FAIL("epoll_wait retured incorrect socket %d instead of %d",
                  events[0].data.fd, iut_fd);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("epoll_wait returned incorrect events");

    event |= RPC_EPOLLET;
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_MOD, iut_fd, event);

    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);

    if (rc != 1)
    {
        TEST_FAIL("epoll_wait returned %d instead of 1", rc);
    }
    else if (events[0].data.fd != iut_fd)
    {
        TEST_FAIL("epoll_wait retured incorrect socket %d instead of %d",
                  events[0].data.fd, iut_fd);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("epoll_wait returned incorrect events");

    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);

    if (rc != 0)
    {
        TEST_FAIL("epoll_wait returned %d instead of 0", rc);
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
