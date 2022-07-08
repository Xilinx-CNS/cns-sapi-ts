/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-epoll_ctl_early Check epoll behaviour when socket is added
 * to epoll set early, before bind
 *
 * @objective Check that socket may be added to epoll set before
 *            bind/connect.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param sock_type     Type of sockets using in the test
 *
 * @par Scenario:
 * -# call socket() and epoll_create();
 * -# call epoll_ctl() with just-created socket;
 * -# bind/connect the socket (to IUT or tester network);
 * -# check that epoll_wait correctly reports events.
 *
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epoll_ctl_early"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;
    rcf_rpc_server  *pco_child = NULL;
    rcf_rpc_server  *pco_aux = NULL;
    rcf_rpc_server  *pco_tst = NULL;

    struct rpc_epoll_event event;
    rpc_socket_type        sock_type;
    iomux_call_type        iomux;

    const struct sockaddr *iut_addr, *tst_addr;

    int tst_s = -1;
    int acc_s = -1;
    int iut_s = -1;
    int epfd = -1;

    te_bool epoll_done;

    te_bool multithread = FALSE;

    te_bool destroy_stack = FALSE;

    te_bool blocking = FALSE;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(multithread);
    TEST_GET_BOOL_PARAM(destroy_stack);
    TEST_GET_BOOL_PARAM(blocking);

    /* Scenario */

    if (multithread)
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_aux",
                                              &pco_aux));

    /* Create epfd and socket; add sockte to the set */
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         RPC_EPOLLIN);

    if (destroy_stack)
    {
        rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child);
        rpc_close(pco_child, iut_s);
    }

    /* bind/connect socket */
    if (sock_type == RPC_SOCK_STREAM)
        tst_s = rpc_stream_server(pco_tst, RPC_PROTO_DEF, FALSE, tst_addr);
    else
    {
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_s, tst_addr);
        rpc_connect(pco_tst, tst_s, iut_addr);
    }
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_connect(pco_iut, iut_s, tst_addr);
    if (sock_type == RPC_SOCK_STREAM)
    {
        acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
        RPC_CLOSE(pco_tst, tst_s);
        tst_s = acc_s;
        acc_s = -1;
    }

    if (blocking)
    {
        /* Check events */
        pco_iut->op = RCF_RPC_CALL;
        iomux_epoll_call(iomux, pco_iut, epfd, &event, 1, -1);
        TAPI_WAIT_NETWORK;
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &epoll_done));
        if (epoll_done)
            TEST_VERDICT("Epoll fires without events");
    }
    else
    {
        /* Check events via non-blocking call */
        rc = iomux_epoll_call(iomux, pco_iut, epfd, &event, 1, 0);
        if (rc != 0)
            TEST_VERDICT("Unexpected non-blocking epoll result");
    }

    {
#define BUF_SIZE 1024
        char tx_buf[BUF_SIZE];
        memset(tx_buf, 0, sizeof(tx_buf));
        RPC_WRITE(rc, pco_tst, tst_s, tx_buf, BUF_SIZE);
#undef BUF_SIZE
    }
    TAPI_WAIT_NETWORK;
    if (blocking)
    {
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &epoll_done));
        if (!epoll_done)
            TEST_VERDICT("Epoll is not fired by event");

        pco_iut->op = RCF_RPC_WAIT;
        rc = iomux_epoll_call(iomux, pco_iut, epfd, &event, 1, -1);
        if (rc != 1 || event.data.fd != iut_s || event.events != RPC_EPOLLIN)
            TEST_VERDICT("Unexpected epoll result");
    }

    /* Check events via non-blocking call */
    rc = iomux_epoll_call(iomux, pco_iut, epfd, &event, 1, 0);
    if (rc != 1 || event.data.fd != iut_s || event.events != RPC_EPOLLIN)
        TEST_VERDICT("Unexpected non-blocking epoll result");

    /* Check blocking call */
    pco_iut->op = RCF_RPC_CALL;
    iomux_epoll_call(iomux, pco_iut, epfd, &event, 1, -1);
    TAPI_WAIT_NETWORK;
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &epoll_done));
    if (!epoll_done)
        TEST_VERDICT("Epoll is not fired by already-present event");
    rc = iomux_epoll_call(iomux, pco_iut, epfd, &event, 1, -1);
    if (rc != 1 || event.data.fd != iut_s || event.events != RPC_EPOLLIN)
    {
        TEST_VERDICT("Unexpected blocking epoll result "
                     "with already-present event");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    if (pco_child != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_child));

    if (pco_aux != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));

    TEST_END;
}

