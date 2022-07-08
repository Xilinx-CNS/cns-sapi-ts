/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_epoll_ctl_bad_epfd Using epoll_ctl() function with bad epfd
 *
 * @objective Check that @b epoll_ctl() function correctly reports an
 *            error when it is called with bad epfd value.
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 * @param sock_type Type of sockets using in the test
 * @param epfd      Value for epoll file descriptor (it can be @c invalid
 *                  or @c socket)
 * @param fd        Value for file descriptor (it can be @c invalid
 *                  or @c valid)
 * @param create    Call or don't call @b epoll_create() function
 *
 * @par Scenario:
 * -# If @p fd is @c valid or @p epfd is @c socket create @p sock_type
 *    socket @p iut_s on @p pco_iut.
 * -# If @p create is @c TRUE call @b epoll_create() to create @p epoll_fd.
 * -# Call @b epoll_ctl() according to @p epfd and @p fd:
 *        - if @p epfd is @c invalid use @c -1 as epoll descriptor;
 *        - if @p epfd is @c socket use @p iut_s as epoll descriptor;
 *        - if @p fd is @c invalid use @c -1 as target file descriptor;
 *        - if @p fd is @c valid use @p iut_s as target file descriptor;
 * -# Check that @b epoll_ctl() returns @c -1 and sets errno to @c EINVAL
 *    in case of @c socket value of @p epfd or @c EBADF in all other cases.
 * -# If @p create is @c TRUE close @p epoll_fd.
 * -# Close @p iut_s.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_ctl_bad_epfd"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;

    const char             *fd;
    int                     iut_s = -1;
    int                     tmp_s;
    const char             *epfd;
    int                     epoll_fd = -1;
    int                     tmp_epfd;
    struct rpc_epoll_event  event;
    te_bool                 create;

    rpc_socket_type         sock_type;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(epfd);
    TEST_GET_STRING_PARAM(fd);
    TEST_GET_BOOL_PARAM(create);

    if (strcmp(fd, "valid") == 0 || strcmp(epfd, "socket") == 0)
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);

    event.data.fd = iut_s;
    event.events = RPC_EPOLLIN;
    if (create)
        epoll_fd = rpc_epoll_create(pco_iut, 1);

    tmp_s = (strcmp(fd, "valid") == 0) ? iut_s : -1;
    tmp_epfd = (strcmp(epfd, "socket") == 0) ? iut_s : -1;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_epoll_ctl(pco_iut, tmp_epfd, RPC_EPOLL_CTL_ADD, tmp_s,
                       &event);
    if (rc != -1)
    {
        TEST_FAIL("epoll_wait() returned %d instead -1.", rc);
    }
    if (strcmp(epfd, "socket") == 0 && strcmp(fd, "valid") == 0)
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "epoll_ctl() returns %d", rc);
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EBADF, "epoll_ctl() returns %d", rc);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epoll_fd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
