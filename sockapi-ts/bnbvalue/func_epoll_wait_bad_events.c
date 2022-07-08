/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_epoll_wait_bad_events Using epoll_wait() with invalid events
 *
 * @objective Check that @b epoll_wait() function doesn't crash the system
 *            when it is called with @c NULL events and positive maxevents.
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   Tester PCO
 * @param maxevents Number of max events. It should be positive
 * @param timeout   Timeout for @b epoll_wait() function
 * @param data_size The amount of data to be sent
 * @param send      Send or do not send data
 * @param retval    The value that @b epoll_wait() function should return
 * @param error     @b epoll_wait() function should set errno to this value
 *
 * @par Scenario:
 * -# Create @c sock_type sockets @p iut_s on @p pco_iut and @p tst_s on
 *    @p pco_tst.
 * -# Call @b epoll_create() function to create @p epfd.
 * -# Call @p epoll_ctl(@c EPOLL_CTL_ADD) with @p iut_s and
 *    @c EPOLLIN event.
 * -# If @p send is @c TRUE send @p data_size bytes of data from
 *    @p tst_s socket to @p iut_s.
 * -# Call @b epoll_wait() with @c NULL events, @p maxevents and @p timeout.
 * -# Check that @b epoll_wait() returns @p retval and in case of non-zero
 *    @p retval sets errno to @c EFAULT.
 * -# Close @p epfd, @p iut_s and @p tst_s.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_wait_bad_events"

#include "sockapi-test.h"

#define MAX_BUFF_SIZE 1024
int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    rpc_socket_type         sock_type;

    int                     iut_s = -1;
    int                     tst_s = -1;

    int                     data_size;
    unsigned char           buffer[MAX_BUFF_SIZE];

    int                     epfd = -1;
    int                     maxevents;
    int                     timeout;
    te_bool                 send;
    int                     retval;
    rpc_errno               error;
    const char             *iomux;

    uint64_t                total_bytes;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(maxevents);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(send);
    TEST_GET_INT_PARAM(retval);
    TEST_GET_ERRNO_PARAM(error);
    TEST_GET_STRING_PARAM(iomux);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         RPC_EPOLLIN);

    if (send)
        RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(iomux, "epoll") == 0)
        rc = rpc_epoll_wait_gen(pco_iut, epfd, NULL, 0, maxevents, timeout);
    else if (strcmp(iomux, "epoll_pwait") == 0)
        rc = rpc_epoll_pwait_gen(pco_iut, epfd, NULL, 0, maxevents, timeout,
                                 RPC_NULL);
    else
        TEST_FAIL("Incorrect value of 'iomux' parameter");

    if (rc != retval)
    {
        TEST_FAIL("%s() returned %d instead %d.", iomux, rc, retval);
    }
    if (rc != 0)
        CHECK_RPC_ERRNO(pco_iut, error, "%s() returns %d", iomux, rc);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
