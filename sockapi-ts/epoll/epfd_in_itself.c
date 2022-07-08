/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-epfd_in_itself Epoll file descriptor in itself.
 *
 * @objective Check that @b epoll_ctl() function called with @p epfd as
 *            epoll file descriptor argument and with @p epfd as target
 *            file descriptor argument fails with appropriate error.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param sock_type     Type of sockets using in the test
 * @param evts          One of @c in, @c out or @c inout
 * @param how           This parameter describes the way of getting the
 *                      error:
 *                      - @c itself - add epoll descriptor into itself
 *                      - @c dup_master - add epoll descriptor in the
 *                        duplicated epoll descriptor
 *                      - @c dup_target - add duplicated epoll descriptor
 *                        in epoll descriptor
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type socket @p iut_s.
 * -# Create @p epfd with @p iut_s socket and with the events according to
 *    @p evts parameter using @b epoll_create() and
 *    @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# if @p how is not @c itself duplicate @p epfd descriptor by dup()
 *    function. The duplicated epoll descriptor is named @p epfd_dup.
 * -# Call @b epoll_ctl(@c EPOLL_CTL_ADD) function according to @p how
 *    parameter:
 *      - if @p how is @c itself use @p epfd as epoll descriptor and target
 *        descriptor
 *      - if @p how is @c dup_master use @p epfd_dup as epoll descriptor
 *        and @p epfd as target descriptor
 *      - if @p how is @c dup_target use @p epfd as epoll descriptor and
 *        @p epfd_dup as targer descriptor
 * -# Check that @b epoll_ctl() returns @c -1 and sets errno to @c EINVAL.
 * -# @b close() all sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epfd_in_itself"

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
    const char             *how;

    int                     epfd1 = -1;
    int                     epfd2 = -1;
    int                     tmp_epfd = -1;
    uint32_t                event;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_STRING_PARAM(how);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    PARSE_EVTS(evts, event, event);

    tmp_epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, tmp_epfd, RPC_EPOLL_CTL_ADD, iut_s, event);

    if (strcmp(how, "itself") != 0)
    {
        if ((epfd1 = rpc_dup(pco_iut, tmp_epfd)) == -1)
        {
            TEST_FAIL("dup() function failed.");
        }
        if (strcmp(how, "dup_master") == 0)
        {
            epfd2 = tmp_epfd;
        }
        else if (strcmp(how, "dup_target") == 0)
        {
            epfd2 = epfd1;
            epfd1 = tmp_epfd;
        }
        else
            TEST_FAIL("Invalid value of 'how' parameter.");
    }
    else
    {
        epfd1 = tmp_epfd;
        epfd2 = tmp_epfd;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rpc_epoll_ctl_simple(pco_iut, epfd1, RPC_EPOLL_CTL_ADD, epfd2, event);

    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "epoll_ctl() returns -1");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd1);
    if (epfd1 != epfd2)
        CLEANUP_RPC_CLOSE(pco_iut, epfd2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
