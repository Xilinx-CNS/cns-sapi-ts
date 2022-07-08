/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_epoll_ctl_add Using epoll_ctl(EPOLL_CTL_ADD) twice with the same file descriptor
 *
 * @objective Check that @b epoll_ctl() function correctly reports
 *            the error when it is called twice with @c EPOLL_CTL_ADD
 *            operation and the same file descriptor.
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 * @param sock_type Type of sockets using in the test
 *
 * @par Scenario:
 * -# Create @p sock_type socket @p iut_s on @p pco_iut.
 * -# Call @b epoll_create() function to create @p epfd
 * -# Call @p epoll_ctl(@c EPOLL_CTL_ADD) with @p iut_s socket and
 *    @c EPOLLIN event.
 * -# Call @p epoll_ctl(@c EPOLL_CTL_ADD) with @p iut_s socket and
 *    @c EPOLLOUT event.
 * -# Check that @b epoll_ctl() returns @c -1 and sets errno to @c EEXIST.
 * -# Close @p epfd and @p iut_s.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_ctl_add"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;

    int                     iut_s = -1;
    int                     epfd = -1;

    rpc_socket_type         sock_type;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         RPC_EPOLLIN);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                              RPC_EPOLLOUT);

    if (rc != -1)
    {
        TEST_FAIL("epoll_ctl() returned %d instead -1.", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EEXIST, "epoll_ctl() returns %d", rc);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
