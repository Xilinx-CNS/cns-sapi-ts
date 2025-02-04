/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/**
* @page bnbvalue-func_epoll_wait_bad_maxevents Using epoll_wait()/epoll_pwait()/epoll_pwait2() with non-positive maxevents
 *
 * @objective Check that @b epoll_wait()/ @b epoll_pwait()/ @b epoll_pwait2()
 *            function correctly reports the
 *            error when it is called with non-positive maxevents.
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 * @param sock_type Type of sockets using in the test
 * @param events    The value of @p events argument for
 *                  @b epoll_wait()/ @b epoll_pwait()/ @b epoll_pwait2()
 *                  function. It can be @c valid or @c invalid
 * @param maxevents Number of max events. It should be non-positive
 * @param timeout   Timeout for @b epoll_wait()/ @b epoll_pwait()/
 *                  @b epoll_pwait2() function
 *
 * @par Scenario:
 * -# Create @c sock_type socket @p iut_s on @p pco_iut.
 * -# Call @b epoll_create() function to create @p epfd.
 * -# Call @p epoll_ctl(@c EPOLL_CTL_ADD) with @p iut_s and
 *    @c POLLIN event.
 * -# Call @b epoll_wait()/ @b epoll_pwait()/ @b epoll_pwait2()
 *    with @p events, @p maxevents and @p timeout.
 * -# Check that @b epoll_wait()/ @b epoll_pwait()/ @b epoll_pwait2()
 *    returns @c -1 and sets errno to @c EINVAL.
 * -# Close @p epfd and @p iut_s.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_wait_bad_maxevents"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;
    rpc_socket_type         sock_type;

    int                     iut_s = -1;
    int                     epfd = -1;
    struct rpc_epoll_event  evs_arr[2];
    int                     rmaxev = 2;
    int                     maxevents;
    int                     timeout;
    const char             *events;

    iomux_call_type iomux;
    struct tarpc_timespec tv;
    struct tarpc_timespec *tv_ptr = &tv;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_INT_PARAM(maxevents);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_STRING_PARAM(events);
    TEST_GET_IOMUX_FUNC(iomux);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         RPC_EPOLLIN);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rmaxev = (strcmp(events, "invalid") == 0) ? 0 : rmaxev;
    switch (iomux)
    {
        case TAPI_IOMUX_EPOLL:
            rc = rpc_epoll_wait_gen(pco_iut, epfd,
                                    (strcmp(events, "invalid") == 0) ?
                                    NULL : evs_arr, rmaxev, maxevents, timeout);
            break;

        case TAPI_IOMUX_EPOLL_PWAIT:
            rc = rpc_epoll_pwait_gen(pco_iut, epfd,
                                     (strcmp(events, "invalid") == 0) ?
                                     NULL : evs_arr, rmaxev, maxevents,
                                     timeout, RPC_NULL);
            break;

        case TAPI_IOMUX_EPOLL_PWAIT2:
            if (timeout < 0)
                tv_ptr = NULL;
            else
                TE_NS2TS(TE_MS2NS(timeout), tv_ptr);
            rc = rpc_epoll_pwait2_gen(pco_iut, epfd,
                                      (strcmp(events, "invalid") == 0) ?
                                       NULL : evs_arr, rmaxev, maxevents,
                                       tv_ptr, RPC_NULL);
            break;

        default:
            TEST_FAIL("Incorrect value of 'iomux' parameter");
    }

    if (rc != -1)
    {
        TEST_FAIL("%s() returned %d instead -1.", iomux, rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "%s() returns %d",
                    iomux_call_en2str(iomux), rc);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
