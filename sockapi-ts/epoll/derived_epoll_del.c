/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-derived_epoll_del Deleting socket from epfd from one process while epoll_wait(epfd) is running on another process
 *
 * @objective Check that system and epoll functions correctly handle
 *            the situation when one process deletes the socket from epoll
 *            descriptor while @b epoll_wait() with this epoll descriptor
 *            is running on another process.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           Tester PCO
 * @param sock_type         Type of sockets using in the test
 * @param func              The function to get another epoll descriptor
 *                          instance. The value can be @c fork, @c dup,
 *                          @c execve and @c fork_exec. Last one is for
 *                          the sequence of @b fork() and execve()
 *                          functions.
 * @param data_size         The amount of data to be sent
 * @param timeout           Timeout for @b epoll_wait() function
 * @param evts              One of @c in, @c out or @c inout
 * @param wait_child        If it is @c TRUE call @b epoll_wait() on
 *                          @p child_epfd.
 * @param non_blocking      Test blocking or non-blocking call of
 *                          @b epoll_wait()
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type connection between @p pco_iut and @p pco_tst. Two
 *    connected sockets @p iut_s and @p tst_s would appear.
 * -# Create @p epfd with @p iut_s socket and with the events according to
 *    @p evts paramter using @b epoll_create() and
 *    @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# In case of @c SOCK_STREAM socket and @c out or @c inout events call
 *    @b rpc_overfill_buffers() on @p iut_s socket.
 * -# Create a process or duplicated epoll descriptor as defined by
 *    @p func parameter. Let @p pco_child is the child process of
 *    @p pco_iut and @p child_epfd is duplicated @p epfd.
 *    (In case of @b dup() @p pco_child = @p pco_iut, in case of @b fork()
 *    @p child_epfd = @p epfd).
 * -# In case of blocking @b epoll_wait() call @b epoll_wait() with
 *    @p timeout according to @p wait_child:
 *    - If @p wait_child is @c TRUE: call @b epoll_wait() on @p pco_child
 *      using @p child_epfd.
 *    - If @p wait_child is @c FALSE: call @b epoll_wait() on @p pco_iut
 *      using @p epfd.
 * -# Call @b epoll_ctl(@c EPOLL_CTL_DEL) to delete @p iut_s socket from
 *    epoll descriptor. This call should be done on @p pco_iut when
 *    @p wait_child is @c TRUE and it should be done on @p pco_child when
 *    @p wait_child is @c FALSE.
 * -# If @p evts is @c in send @p data_size bytes of data from @p tst_s
 *    socket to @p iut_s.
 * -# If @p events is @c out or @c inout and in case of @c SOCK_STREAM
 *    sockets read all data form @p tst_s socket.
 * -# In case of non-blocking @b epoll_wait() call @b epoll_wait() with
 *    @p timeout according to @p wait_child:
 *    - If @p wait_child is @c TRUE: call @b epoll_wait() on @p pco_child
 *      using @p child_epfd.
 *    - If @p wait_child is @c FALSE: call @b epoll_wait() on @p pco_iut
 *      using @p epfd.
 * -# Check that @b epoll_wait() returns @c 0.
 * -# @b close() all sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/derived_epoll_del"

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
    int                     tst_s = -1;

    rpc_socket_type         sock_type;

    unsigned char          *buffer;

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

    uint64_t                total_bytes;

    te_bool                 non_blocking;
    te_bool                 use_wildcard;
    iomux_call_type         iomux;

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
    TEST_GET_BOOL_PARAM(use_wildcard);
    TEST_GET_IOMUX_FUNC(iomux);

    buffer = TE_ALLOC(data_size);
    if (buffer == NULL)
        TEST_FAIL("Out of memory");
    te_fill_buf(buffer, data_size);

    if (non_blocking)
        timeout = 0;

    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, use_wildcard);

    PARSE_EVTS(evts, event, event);

    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s, event);

    PARSE_FUNC(func, pco_iut, pco_child, epfd, child_epfd, inst_num);

    if ((event & RPC_EPOLLOUT) != 0 && sock_type == RPC_SOCK_STREAM)
        rpc_overfill_buffers_gen(pco_iut, iut_s, &total_bytes, FUNC_EPOLL);

    if (!non_blocking)
        CALL_EPOLL_WAIT(wait_child, pco_child, pco_iut, child_epfd,
                        epfd, events, maxevents, timeout, iomux);

    CALL_EPOLL_CTL(!wait_child, pco_child, pco_iut, child_epfd,
                   epfd, RPC_EPOLL_CTL_DEL, iut_s, event);

    MSLEEP(200);
    if (strcmp(evts, "in") == 0)
        RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
    else
    {
        do {
            rc = rpc_read(pco_tst, tst_s, buffer, data_size);
            total_bytes -= rc;
        } while (total_bytes != 0);
    }

    /* Wait for incoming packet in case of non-blocking epoll_wait() */
    if (non_blocking)
        TAPI_WAIT_NETWORK;
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

    RPC_AWAIT_IUT_ERROR(rpcs);
    WAIT_EPOLL_WAIT(rpcs, test_epfd, events, maxevents, timeout, iomux,
                    non_blocking);
    if (rc > 0)
    {
        TEST_VERDICT("%s_wait returned %d instead of 0",
                     iomux_call_en2str(iomux), rc);
    }
    else if (rc < 0)
    {
        TEST_VERDICT("WAIT_EPOLL_WAIT() unexpectedly failed with %r",
                     RPC_ERRNO(rpcs));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (inst_num == 2)
        CLEANUP_RPC_CLOSE(pco_child, child_epfd);

    if (pco_child != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_child));

    free(buffer);
    TEST_END;
}
