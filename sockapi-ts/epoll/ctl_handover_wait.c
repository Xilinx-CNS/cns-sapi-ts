/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-ctl_handover_wait Epoll file descriptor with handover socket
 * to epoll set early, before bind
 *
 * @objective Check that @b epoll_wait() report correct events after
 *            handover on the socket from epoll file descriptor.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param sock_type     Type of sockets using in the test
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/ctl_handover_wait"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;
    rcf_rpc_server  *pco_tst = NULL;

    struct rpc_epoll_event events[2];
    iomux_call_type        iomux;

    const struct sockaddr *iut_addr, *tst_addr;

    int tst_s = -1;
    int iut_s = -1;
    int epfd = -1;

    int              fds[2] = { -1, -1 };

    int             timeout;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(timeout);

    /* Scenario */

    TEST_STEP("Create epoll file descriptor on @p pco_iut");
    epfd = rpc_epoll_create(pco_iut, 1);
    TEST_STEP("Create pipe on @p pco_iut");
    rpc_pipe(pco_iut, fds);
    TEST_STEP("Add read end of pipe to epoll file descriptor");
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, fds[0],
                         RPC_EPOLLIN | RPC_EPOLLOUT);
    TEST_STEP("Open @p iut_s socket on @p pco_iut");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    TEST_STEP("Open @p tst_s socket on @p pco_tst, bind it to @p tst_addr address "
              "and call @b listen");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, 1);

    TEST_STEP("Add @p iut_s socket to epoll file descriptor");
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         RPC_EPOLLIN | RPC_EPOLLOUT);
    TEST_STEP("Connect @p iut_s socket to @p tst_addr, handover should happend on "
              "the socket");
    rpc_connect(pco_iut, iut_s, tst_addr);

    TAPI_WAIT_NETWORK;
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, 2, timeout);

    if (rc != 1)
        TEST_VERDICT("%s() returned %d instead of 1",
                     iomux_call_en2str(iomux), rc);
    else if (events[0].data.fd != iut_s)
        TEST_VERDICT("%s() retured incorrect fd %d instead of "
                     "%d iut_s", iomux_call_en2str(iomux),
                     events[0].data.fd, iut_s);
    else if (events[0].events != RPC_EPOLLOUT)
            TEST_VERDICT("%s() returned incorrect events",
                         iomux_call_en2str(iomux));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fds[1]);

    TEST_END;
}
