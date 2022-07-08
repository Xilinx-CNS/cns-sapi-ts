/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_epoll_ctl_bad_fd Using epoll_ctl() function with bad fd
 *
 * @objective Check that @b epoll_ctl() function correctly reports an error when
 *            it is called with bad fd value.
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 * @param sock_type Type of sockets using in the test
 *
 * @par Scenario:
 * -# Create @c sock_type socket @p iut_s on @p pco_iut.
 * -# Call @b epoll_create() to create @p epfd.
 * -# Call @b epoll_ctl(@p epfd) using @c -1 as target file descriptor;
 * -# Check that @b epoll_ctl() returns @c -1 and sets errno to @c EBADF.
 * -# Close @p epfd and @p iut_s.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_ctl_bad_fd"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;
    rpc_socket_type         sock_type;

    int                     iut_s = -1;
    int                     epfd = -1;
    struct rpc_epoll_event  event;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    event.data.fd = iut_s;
    event.events = RPC_EPOLLIN;
    epfd = rpc_epoll_create(pco_iut, 1);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_epoll_ctl(pco_iut, epfd, RPC_EPOLL_CTL_ADD, -1,
                       &event);
    if (rc != -1)
    {
        TEST_FAIL("epoll_ctl() returned %d instead -1.", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EBADF, "epoll_ctl() returns %d", rc);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
