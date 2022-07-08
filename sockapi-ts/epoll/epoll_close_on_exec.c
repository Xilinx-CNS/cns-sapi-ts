/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-epoll_close_on_exec FD_CLOEXEC fcntl flag with epoll file descriptor
 *
 * @objective Check that epoll file descriptor with @c FD_CLOEXEC fcntl
 *            flag will be in the closed state after @b exec() call.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param sock_type     Type of sockets using in the test
 * @param evts          One of @c in, @c out or @c inout
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type @p iut_s socket.
 * -# Create @p epfd with @p iut_s socket and with events accoring to
 *    @p evts paramter using @b epoll_create() and
 *    @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# Set @c FD_CLOEXEC bit on @p epfd by means of @b fcntl(F_SETFD)
 *    and check that new value is set successfully.
 * -# Change image of process @p pco_iut by @b execve() call.
 * -# Call @b epoll_wait() with @p epfd.
 * -# Check that @b epoll_wait() returns @c -1.
 * -# @b close() @p iut_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epoll_close_on_exec"

#include "sockapi-test.h"
#include "epoll_common.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;

    const struct sockaddr  *iut_addr = NULL;

    int                     iut_s = -1;

    rpc_socket_type         sock_type;

    const char             *evts;

    int                     epfd = -1;
    struct rpc_epoll_event  events[2];
    uint32_t                event;
    int                     maxevents = 2;

    const char             *create_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_STRING_PARAM(create_func);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    PARSE_EVTS(evts, event, event);

    if (strcmp(create_func, "epoll_create1") == 0)
        epfd = rpc_epoll_create1(pco_iut, RPC_EPOLL_CLOEXEC);
    else
        epfd = rpc_epoll_create(pco_iut, 1);

    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s, event);

    if (strcmp(create_func, "epoll_create1") != 0)
    {
        rpc_fcntl(pco_iut, epfd, RPC_F_SETFD, 1);

        rc = rpc_fcntl(pco_iut, epfd, RPC_F_GETFD, 1);
        if (rc != 1)
            TEST_FAIL("Can not enable FD_CLOEXEC on epfd");
    }

    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, -1);
    epfd = -1;

    if (rc != -1)
    {
        TEST_FAIL("epoll_wait() returned %d instead -1.", rc);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
