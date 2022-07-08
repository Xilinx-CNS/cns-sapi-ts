/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_epoll_ctl_null_events Using epoll_ctl() with NULL events
 *
 * @objective Check that @b epoll_ctl() function correctly delete
 *            descriptor from epoll fd when it is called with NULL events.
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 * @param sock_type Type of sockets using in the test
 *
 * @par Scenario:
 * -# Create @p sock_type socket @p iut_s on @p pco_iut.
 * -# Call @b epoll_create() function to create @p epfd and add @p iut_s
 *    socket to it.
 * -# Call @b epoll_ctl() function with @p iut_s socket,
 *    @c NULL events and @c EPOLL_CTL_DEL.
 * -# Check that @b epoll_ctl() function returns @c 0.
 * -# Close @p epfd and @p iut_s.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_ctl_null_events"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;

    int                     iut_s = -1;
    int                     epfd = -1;
    rpc_socket_type         sock_type;

    te_bool                 wait_between = FALSE;

    struct rpc_epoll_event  event;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(wait_between);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    epfd = rpc_epoll_create(pco_iut, 1);

    rc = rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                              RPC_EPOLLOUT);

    if (wait_between)
    {
        if (rpc_epoll_wait(pco_iut, epfd, &event, 1, 0) != 1)
            TEST_VERDICT("epoll_wait() returns incorrect value before "
                         "epoll_ctl(EPOLL_CTL_DEL)");
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_epoll_ctl(pco_iut, epfd, RPC_EPOLL_CTL_DEL, iut_s, NULL);

    if (rc == -1)
        TEST_VERDICT("epoll_ctl() called with EPOLL_CTL_DEL operation and "
                     "with NULL evetns failed and returned %r error",
                     RPC_ERRNO(pco_iut));

    if (rpc_epoll_wait(pco_iut, epfd, &event, 1, 0) != 0)
        TEST_VERDICT("epoll_wait() returns incorrect value after "
                     "epoll_ctl(EPOLL_CTL_DEL)");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
