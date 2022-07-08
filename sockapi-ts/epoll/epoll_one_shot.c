/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-epoll_one_shot Epoll functions with EPOLLONESHOT (or EPOLLET in same situation) flag
 *
 * @objective Check that epoll functions work correctly handles
 *            @c EPOLLONESHOT (or @c EPOLLET in the same situation) flag.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param sock_type     Type of sockets using in the test
 * @param evts          One of @c in, @c out or @c inout
 * @param timeout       Timeout for @b epoll_wait() function
 * @param data_size     The amount of data to be sent
 * @param refresh       This parameter describes how to refresh the fd
 *                      with @c EPOLLONESHOT (or @c EPOLLET) flag in
 *                      epoll descriptor. It can be @c none, @c same,
 *                      @c different
 * @param non_blocking  Test blocking or non-blocking call of
 *                      @b epoll_wait()
 * @param et_one_shot   Use @c EPOLLET or @c EPOLLONESHOT
 *
 * @par Test sequence:
 *
 * -# Create a pair of connected fds (i.e. pairs of pipe ends or
 *    connected sockets) - (@p iut_fd, @p tst_fd).
 * -# Create @p epfd with @p iut_fd fd and according to @p evts parameter
 *    with @c EPOLLONESHOT or @c EPOLLET flag using @b epoll_create() and
 *    @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# If @p evts is @c out and we do not test @c SOCK_DGRAM socket,
 *    overfill buffers on @p iut_fd fd.
 * -# Call @b epoll_wait() function with @p timeout according to
 *    @p non_blocking parameter.
 * -# Generate events on @p iut_fd fd according to @p evts:
 *    - if @p evts is @c out and we do not test @c SOCK_DGRAM socket read
 *      previously sent data from @c tst_fd fd.
 *    - if @p evts is @c in send @p data_size bytes of data from @p tst_fd
 *      fd to @p iut_fd fd.
 * -# Check that @p epoll_wait() returns @c 1 with appropriate events.
 * -# Modify events for @p iut_fd fd according to @p refresh parameter:
 *    - if @p refresh is @c none do nothing.
 *    - if @p refresh is @c same call @b epoll_ctl(@c EPOLL_CTL_ADD) with
 *      the same events as in previous @b epoll_ctl() call.
 *    - if @p refresh is @c different call @b epoll_ctl(@c EPOLL_CTL_ADD)
 *      with @c EPOLLOUT | (@c EPOLLONESHOT or @c EPOLLET) events in case
 *      of @c in @p evts and with @c EPOLLIN | (@c EPOLLONESHOT or
 *      @c EPOLLET) events in all other cases.
 * -# If @p refresh is not @c none check that the second call of
 *    epoll_ctl() refreshed @p epfd for that reason call @b epoll_wait()
 *    with zero timeout.
 * -# If @p refresh is not @c none check that @b epoll_wait() returns @c 1
 *    with the events according to two previous steps.
 * -# Call @b epoll_wait() with zero timeout.
 * -# Check that @b epoll_wait() returns @c 0.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epoll_one_shot"

#include "sockapi-test.h"
#include "iomux.h"
#include "epoll_common.h"

#define MAX_BUFF_SIZE 65536
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

    rpc_socket_type         sock_type = RPC_SOCK_UNKNOWN;

    const char             *evts;
    const char             *refresh;

    int                     data_size;
    unsigned char           buffer[MAX_BUFF_SIZE];

    int                     epfd = -1;
    struct rpc_epoll_event  events[2];
    uint32_t                event;
    int                     maxevents = 2;
    int                     timeout;

    uint64_t                total_bytes;
    uint32_t                exp_ev;
    te_bool                 non_blocking;
    te_bool                 early_ctl;

    const char             *et_one_shot;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_STRING_PARAM(refresh);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(non_blocking);
    TEST_GET_STRING_PARAM(et_one_shot);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(early_ctl);

    if (non_blocking)
        timeout = 0;

    PARSE_EVTS(evts, event, exp_ev);

    if (strcmp(et_one_shot, "et") == 0)
        event |= RPC_EPOLLET;
    else if (strcmp(et_one_shot, "one_shot") == 0)
        event |= RPC_EPOLLONESHOT;
    else
        TEST_FAIL("Incorrect value of 'et_one_shot' parameter.");

    /* Hack for ZF shim testing: we can't add one socket to 2 epoll sets,
     * so epoll_ctl() must be called after overfill_buffers().
     * I.e. GET_CONNECTED_ADD_EPFD() does not do the right thing for us in
     * case of early_ctl=FALSE. */
    if (early_ctl)
    {
        GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, FALSE, sock_type,
                               iut_addr, tst_addr, iut_fd, tst_fd, TRUE,
                               TRUE, epfd, early_ctl, event);
    }
    else
    {
        GET_CONNECTED_FDS(pco_iut, pco_tst, FALSE, sock_type,
                          iut_addr, tst_addr, iut_fd, tst_fd, TRUE, TRUE);
    }

    GET_FD2_PCO(pco_iut, pco_tst, pco_tst, FALSE, iut_fd, tst_fd);

    TAPI_WAIT_NETWORK;

    if (strcmp(evts, "out") == 0 || strcmp(evts, "inout") == 0)
    {
        if (sock_type == RPC_SOCK_STREAM)
            rpc_overfill_buffers_gen(pco_iut, iut_fd, &total_bytes,
                                     iomux == IC_OO_EPOLL ? IC_EPOLL
                                                          : iomux);
        else
        {
#define UDP_SEND_PACKETS 10000
            int         vector[UDP_SEND_PACKETS];
            uint64_t    size;
            int         i;

            for (i = 0; i < UDP_SEND_PACKETS; i++)
                vector[i] = 1;
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_many_send(pco_iut, iut_fd, RPC_MSG_DONTWAIT,
                               vector, UDP_SEND_PACKETS, &size);
            if (rc != 0)
            {
                CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                                "Expected to overfill send buffer of the "
                                "UDP socket and get -1(errno=EAGAIN), but");
            }
            else
                WARN("Failed to overfill UDP send queue.");
            /* Additional wait - let all the packets go via link */
            TAPI_WAIT_NETWORK;
        }
        TAPI_WAIT_NETWORK;
    }

    /* Hack for ZF shim testing: we can't add one socket to 2 epoll sets,
     * so epoll_ctl() must be called after overfill_buffers(). */
    if (!early_ctl)
    {
        epfd = rpc_epoll_create(pco_iut, 1);
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_fd, event);
    }

    if (!non_blocking)
    {
        pco_iut->op = RCF_RPC_CALL;
        rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                              maxevents, timeout);
        TAPI_WAIT_NETWORK;
    }

    TAPI_WAIT_NETWORK;
    if (strcmp(evts, "in") == 0) {
        RPC_WRITE(rc, pco_tst, tst_fd, buffer, data_size);
        TAPI_WAIT_NETWORK;
    }
    else if ((strcmp(evts, "out") == 0 || strcmp(evts, "inout") == 0) &&
             sock_type == RPC_SOCK_STREAM)
    {
        do {
            rc = rpc_read(pco_tst, tst_fd, buffer, MAX_BUFF_SIZE);
            total_bytes -= rc;
        } while (total_bytes != 0);
        TAPI_WAIT_NETWORK;
    }

    if (!non_blocking)
        pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, timeout);

    if (rc != 1)
        TEST_FAIL("%s() returned %d instead of 1",
                  iomux_call_en2str(iomux), rc);
    else if (events[0].data.fd != iut_fd)
        TEST_FAIL("%s() retured incorrect fd %d instead of "
                  "%d iut_fd", iomux_call_en2str(iomux),
                  events[0].data.fd, iut_fd);
    else if (events[0].events != exp_ev)
        TEST_FAIL("%s() returned incorrect events",
                  iomux_call_en2str(iomux));
    TAPI_WAIT_NETWORK;

    if (strcmp(refresh, "same") == 0)
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_MOD, iut_fd,
                             event);
    else if (strcmp(refresh, "different") == 0)
    {
        if (strcmp(evts, "in") == 0)
            event = exp_ev = RPC_EPOLLOUT;
        else
            event = exp_ev = RPC_EPOLLIN;
        if (strcmp(et_one_shot, "et") == 0)
            event |= RPC_EPOLLET;
        else
            event |= RPC_EPOLLONESHOT;

        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_MOD, iut_fd,
                             event);
        TAPI_WAIT_NETWORK;
        if (strcmp(evts, "in") != 0)
            RPC_WRITE(rc, pco_tst, tst_fd, buffer, data_size);
    }
    else if (strcmp(refresh, "none") != 0)
        TEST_FAIL("Incorrect value of 'refresh' parameter.");
    TAPI_WAIT_NETWORK;

    if (strcmp(refresh, "none") != 0)
    {
        rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);

        if (rc != 1)
        {
            TEST_FAIL("%s() returned %d instead of 1",
                      iomux_call_en2str(iomux), rc);
        }
        else if (events[0].data.fd != iut_fd)
        {
            TEST_FAIL("%s() retured incorrect fd %d instead of "
                      "%d iut_fd", iomux_call_en2str(iomux),
                      events[0].data.fd, iut_fd);
        }
        else if (events[0].events != exp_ev)
            TEST_FAIL("%s() returned incorrect events",
                      iomux_call_en2str(iomux));
        TAPI_WAIT_NETWORK;
    }

    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);

    if (rc != 0)
    {
        if (rc == 1)
        {
            rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);
            if (rc == 1)
            {
                rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                                  maxevents, 0);
                if (rc == 1)
                    TEST_VERDICT("Event is reported multiple times");
                else if (rc == 0)
                    TEST_VERDICT("Event is reported thrice");
            }
            else if (rc == 0)
                TEST_VERDICT("Event is reported twice");
        }
        TEST_FAIL("Unexpected epoll result");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);

    TEST_END;
}
