/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_epoll_ctl_mod_del Modifying or deleting descriptor that is not in epfd
 *
 * @objective Check that @b epoll_ctl() function correctly reports the error
 *            when it is called with @c EPOLL_CTL_MOD or @c EPOLL_CTL_DEL
 *            operation and with target file descriptor that is not in
 *            epoll descriptor.
 *
 * @type conformance, robustness
 *
 * @param pco_iut    PCO on IUT
 * @param sock_type  Type of sockets using in the test
 * @param oper       Operation to test. It can be @c mod or @c del.
 * @param descr_type Type of the descriptor to test. It can be @c socket,
 *                   @c file or @c epoll_fd
 * @param error      Expected error that @b epoll_ctl() function should
 *                   return
 *
 * @par Scenario:
 * -# Create @c sock_type socket @p iut_s on @p pco_iut.
 * -# If @p descr_type is @c socket create @c sock_type socket @p aux_s
 *    on @p pco_iut.
 * -# If @p descr_type is @c file create @p file_d on @p pco_iut.
 * -# Call @b epoll_create() function to create @p epfd.
 * -# Call @p epoll_ctl(@c EPOLL_CTL_ADD) with @p iut_s socket and
 *    @c EPOLLIN event.
 * -# Call @p epoll_ctl(@c EPOLL_CTL_MOD) or @p epoll_ctl(@c EPOLL_CTL_DEL)
 *    according to @p oper with @p aux_s, @p file_d or @p epfd as
 *    target socket according to @p descr_type and with @c EPOLLOUT event.
 * -# Check that @b epoll_ctl() returns @c -1 and sets errno to @c error.
 * -# Close all opened sockets and descriptors.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_ctl_mod_del"

#include "sockapi-test.h"

#define FILENAME    "/tmp/te_func_epoll_ctl_mod_del"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;
    rpc_socket_type         sock_type;

    int                     iut_s = -1;
    int                     aux_s = -1;
    int                     file_d = -1;
    int                     tgt_d;
    int                     epfd = -1;
    struct rpc_epoll_event  event;
    const char             *oper;
    const char             *descr_type;
    int                     op;
    char                    fname[128] = { 0, };
    rpc_errno               error;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(oper);
    TEST_GET_STRING_PARAM(descr_type);
    TEST_GET_ERRNO_PARAM(error);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    event.data.fd = iut_s;
    event.events = RPC_EPOLLIN;

    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s, &event);

    if (strcmp(descr_type, "socket") == 0)
    {
        aux_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);
        tgt_d = aux_s;
    }
    else if (strcmp(descr_type, "file") == 0)
    {
        TE_SPRINTF(fname, "%s_%d", FILENAME, rand_range(0, 100000));
        file_d = rpc_open(pco_iut, fname, RPC_O_RDWR | RPC_O_CREAT, 0);
        tgt_d = file_d;
    }
    else if (strcmp(descr_type, "epoll_fd") == 0)
    {
        tgt_d = epfd;
    }
    else
        TEST_VERDICT("Invalid value of 'descr_type' parameter");

    op = (strcmp(oper, "mod") == 0) ? RPC_EPOLL_CTL_MOD : RPC_EPOLL_CTL_DEL;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_epoll_ctl(pco_iut, epfd, op, tgt_d, &event);

    if (rc != -1)
    {
        TEST_VERDICT("epoll_ctl() returned %d instead -1.", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, error, "epoll_ctl() returns %d", rc);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, aux_s);
    CLEANUP_RPC_CLOSE(pco_iut, file_d);

    TEST_END;
}
