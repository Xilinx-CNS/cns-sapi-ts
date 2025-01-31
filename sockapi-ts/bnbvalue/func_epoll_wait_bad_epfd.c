/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_epoll_wait_bad_epfd Using epoll_wait() function with bad epfd
 *
 * @objective Check that @b epoll_wait() function correctly reports an
 *            error when it is called with bad epfd value.
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 * @param epfd      Value for epoll file descriptor (it can be @c invalid
 *                  or @c socket)
 * @param create    Call or don't call @b epoll_create() function
 * @param sock_type Type of sockets using in the test
 *
 * @par Scenario:
 * -# If @p epfd is @c socket or @p create is @c TRUE create @c sock_type
 *    socket @p iut_s on @p pco_iut.
 * -# If @p create is @c TRUE call @b epoll_create() and
 *    epoll_ctl(@c EPOLL_CTL_ADD) to create @p epoll_fd with @p iut_s socket
 *    and @c EPOLLIN | @c EPOLLOUT events.
 * -# Call @b epoll_wait() function according to @p epfd:
 *        - if @p epfd is @c invalid use @c -1 as epoll descriptor;
 *        - if @p epfd is @c socket use @p iut_s as epoll descriptor;
 * -# Check that @b epoll_wait() function returns @c -1 and sets
 *    errno to @c EINVAL in case of 'socket' value of @p epfd or
 *    @c EBADF in all other cases.
 * -# If @p create is @c TRUE close @p epoll_fd.
 * -# Close @p iut_s.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_wait_bad_epfd"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;
    rpc_socket_type         sock_type;

    int                     iut_s = -1;
    const char             *epfd;
    int                     epoll_fd = -1;
    int                     tmp_epfd;
    struct rpc_epoll_event  events[2];
    int                     maxevents = 2;
    int                     timeout;
    te_bool                 create;

    iomux_call_type iomux;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_STRING_PARAM(epfd);
    TEST_GET_BOOL_PARAM(create);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IOMUX_FUNC(iomux);

    if (strcmp(epfd, "socket") == 0 || create)
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);

    if (create)
    {
        epoll_fd = rpc_epoll_create(pco_iut, 1);
        rpc_epoll_ctl_simple(pco_iut, epoll_fd, RPC_EPOLL_CTL_ADD, iut_s,
                             RPC_EPOLLIN);
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    tmp_epfd = (strcmp(epfd, "socket") == 0) ? iut_s : -1;
    switch (iomux)
    {
        case TAPI_IOMUX_EPOLL:
            rc = rpc_epoll_wait(pco_iut, tmp_epfd, events, maxevents, timeout);
            break;

        case TAPI_IOMUX_EPOLL_PWAIT:
            rc = rpc_epoll_pwait(pco_iut, tmp_epfd, events, maxevents,
                                 timeout, RPC_NULL);
            break;

        default:
            TEST_FAIL("Incorrect value of 'iomux' parameter");
    }

    if (rc != -1)
    {
        TEST_FAIL("epoll_wait() returned %d instead -1.", rc);
    }
    if (strcmp(epfd, "socket") == 0)
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "epoll_wait() returns %d", rc);
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EBADF, "epoll_wait() returns %d", rc);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epoll_fd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
