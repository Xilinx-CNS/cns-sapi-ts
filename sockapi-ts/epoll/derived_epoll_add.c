/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-derived_epoll_add Adding socket to epfd from one process while epoll_wait(epfd) is running on another process
 *
 * @objective Check that system and epoll functions correctly handle
 *            the situation when one process adds the socket to epoll
 *            descriptor while @b epoll_wait() with this epoll descriptor
 *            is running on another process.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           Tester PCO
 * @param sock_type         Type of sockets using in the test
 * @param func              The function to get another epoll descriptor
 *                          instance (RPC server, epoll file descriptor).
 *                          The value can be @c thread_create, @c fork,
 *                          @c dup, @c execve and @c fork_exec. Last one
 *                          is for the sequence of @b fork() and execve()
 *                          functions.
 * @param data_size         The amount of data to be sent
 * @param timeout           Timeout for @b epoll_wait() function
 * @param evts              One of @c in, @c out or @c inout
 * @param wait_child        If it is @c TRUE call @b epoll_wait() on
 *                          @p child_epfd.
 * @param non_blocking      Test blocking or non-blocking call of
 *                          @b epoll_wait()
 * @param have_events       Whether some events should be raised on socket
 *                          or not.
 * @param event_before_add  Should an event be raised on socket before
 *                          @b epoll_ctl() call or not.
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type connection between @p pco_iut and @p pco_tst. Two
 *    connected sockets @p iut_s and @p tst_s would appear.
 * -# Create @p epfd using @b epoll_create() function.
 * -# Create a process (thread) or duplicated epoll descriptor as defined
 *    by @p func parameter. Let @p pco_child is the child process of
 *    @p pco_iut and @p child_epfd is duplicated @p epfd.
 *    (In case of @b dup() or @b execve @p pco_child = @p pco_iut,
 *    in case of @b fork(), @b execve() or @b thread_create()
 *    @p child_epfd = @p epfd).
 * -# In case of blocking @b epoll_wait() call @b epoll_wait() with
 *    @p timeout according to @p wait_child:
 *    - If @p wait_child is @c TRUE: call @b epoll_wait() on @p pco_child
 *      using @p child_epfd.
 *    - If @p wait_child is @c FALSE: call @b epoll_wait() on @p pco_iut
 *      using @p epfd.
 * -# If @p iut_s socket should be readable before @ epoll_ctl() call,
 *    send some data from @p tst_s. If it should not be writable and
 *    @p sock_type is @c SOCK_STREAM, overfill socket's buffers.
 * -# Call @b epoll_ctl(@c EPOLL_CTL_ADD) to add @p iut_s socket with the
 *    events according to @p evts paramter. This call should be done on
 *    @p pco_iut when @p wait_child is @c TRUE and it should be done on
 *    @p pco_child when @p wait_child is @c FALSE.
 * -# If @p iut_s socket should become readable after @ epoll_ctl() call,
 *    send some data from @p tst_s. If it should become writable,
 *    read all the data received by @p tst_s.
 * -# In case of non-blocking @b epoll_wait() call @b epoll_wait() with
 *    @p timeout according to @p wait_child:
 *    - If @p wait_child is @c TRUE: call @b epoll_wait() on @p pco_child
 *      using @p child_epfd.
 *    - If @p wait_child is @c FALSE: call @b epoll_wait() on @p pco_iut
 *      using @p epfd.
 * -# Check that @b epoll_wait() returns expected events.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/derived_epoll_add"

#include "sockapi-test.h"
#include "epoll_common.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_child = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *rpcs;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     aux_s = -1;
    int                     tst_s = -1;

    rpc_socket_type         sock_type;

    unsigned char          *buffer = NULL;

    int                     epfd = -1;
    int                     child_epfd = -1;
    int                     test_epfd;
    struct rpc_epoll_event  events[2];
    uint32_t                event;
    int                     maxevents = 2;
    int                     timeout;
    int                     data_size;

    int                     inst_num = 0;
    const char             *func;
    te_bool                 wait_child;
    const char             *evts;
    uint32_t                exp_ev;
    te_bool                 non_blocking;
    te_bool                 have_events;
    te_bool                 event_before_add;
    te_bool                 epoll_done;
    iomux_call_type         iomux;
    te_bool                 other_stack;
    te_bool                 remove_before_wait;
    te_bool                 use_wildcard;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(wait_child);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_BOOL_PARAM(non_blocking);
    TEST_GET_BOOL_PARAM(have_events);
    TEST_GET_BOOL_PARAM(event_before_add);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(other_stack);
    TEST_GET_BOOL_PARAM(remove_before_wait);
    TEST_GET_BOOL_PARAM(use_wildcard);

    buffer = TE_ALLOC(data_size);
    if (buffer == NULL)
        TEST_FAIL("Out of memory");
    te_fill_buf(buffer, data_size);

    if (non_blocking)
        timeout = 0;

    if (other_stack)
    {
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, "test");
        aux_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, "");
    }

    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, use_wildcard);

    epfd = rpc_epoll_create(pco_iut, 1);

    PARSE_FUNC(func, pco_iut, pco_child, epfd, child_epfd, inst_num);

    PARSE_EVTS(evts, event, exp_ev);

    CONFIGURE_EVENTS_BEFORE(have_events, event_before_add, evts,
                            sock_type, wait_child, pco_iut,
                            pco_child, iut_s, pco_tst, tst_s,
                            buffer, data_size, non_blocking);

    if (other_stack)
    {
        TAPI_WAIT_NETWORK;
        CALL_EPOLL_CTL(!wait_child, pco_child, pco_iut, child_epfd,
                       epfd, RPC_EPOLL_CTL_ADD, aux_s, RPC_EPOLLIN);
        if (remove_before_wait)
            CALL_EPOLL_CTL(!wait_child, pco_child, pco_iut, child_epfd,
                           epfd, RPC_EPOLL_CTL_DEL, aux_s, RPC_EPOLLIN);
        TAPI_WAIT_NETWORK;
    }

    if (!non_blocking)
        CALL_EPOLL_WAIT(wait_child, pco_child, pco_iut, child_epfd,
                        epfd, events, maxevents, timeout, iomux);

    if (other_stack && !remove_before_wait)
    {
        TAPI_WAIT_NETWORK;
        CALL_EPOLL_CTL(!wait_child, pco_child, pco_iut, child_epfd,
                       epfd, RPC_EPOLL_CTL_DEL, aux_s, RPC_EPOLLIN);
    }

    TAPI_WAIT_NETWORK;
    CALL_EPOLL_CTL(!wait_child, pco_child, pco_iut, child_epfd,
                   epfd, RPC_EPOLL_CTL_ADD, iut_s, event);

    TAPI_WAIT_NETWORK;
    CONFIGURE_EVENTS_AFTER(have_events, event_before_add, evts,
                           pco_tst, tst_s, buffer, data_size,
                           non_blocking);

    if (have_events && !event_before_add && (strcmp(evts, "in") != 0))
        rpc_drain_fd_simple(pco_tst, tst_s, NULL);

    if (wait_child)
    {
        rpcs = pco_child;
        test_epfd = child_epfd;
    }
    else
    {
        rpcs = pco_iut;
        test_epfd = epfd;
    }
    TAPI_WAIT_NETWORK;

    if (!non_blocking && have_events)
    {
        CHECK_RC(rcf_rpc_server_is_op_done(rpcs, &epoll_done));
        if (!epoll_done)
            RING_VERDICT("epoll does not return in time");
    }
    WAIT_EPOLL_WAIT(rpcs, test_epfd, events, maxevents, timeout, iomux,
                    non_blocking);

    if (rc != (have_events ? 1 : 0))
    {
        TEST_VERDICT("%s_wait returned %d instead of %d",
                     iomux_call_en2str(iomux), rc,
                     have_events ? 1 : 0);
    }

    if (have_events)
    {
        if (events[0].data.fd != iut_s)
        {
            TEST_FAIL("epoll_wait retured incorrect socket %d instead of "
                      "%d iut_s", events[0].data.fd, iut_s);
        }
        else if (events[0].events != exp_ev)
            TEST_FAIL("epoll_wait returned incorrect events");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, aux_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (inst_num == 2)
        CLEANUP_RPC_CLOSE(pco_child, child_epfd);

    if (pco_child != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_child));

    free(buffer);

    TEST_END;
}
