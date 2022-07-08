/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-few_in_events  A few IN events when data is read incompletely
 *
 * @objective  Check that @b epoll_wait() calls report IN events after
 *             incomplete data read.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT.
 * @param pco_tst       Tester PCO.
 * @param sock_type     Socket type UDP or TCP.
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/few_in_events"

#include "sockapi-test.h"

#define EVENTS_NUM 1

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    rpc_socket_type         sock_type = RPC_SOCK_UNKNOWN;

    struct rpc_epoll_event  events[EVENTS_NUM];
    int     iut_s = -1;
    int     tst_s = -1;
    char   *sndbuf = NULL;
    char   *rcvbuf = NULL;
    size_t  len;
    int     epfd = -1;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    sndbuf = sockts_make_buf_stream(&len);
    rcvbuf = te_make_buf_by_len(len);

    TEST_STEP("Establish TCP connection.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Send some data from tester.");
    rpc_write(pco_tst, tst_s, sndbuf, len);
    rpc_write(pco_tst, tst_s, sndbuf, len);

    TEST_STEP("Create epoll fd and add IUT socket to expect IN events.");
    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s, RPC_EPOLLIN);

    TEST_STEP("Check @a epoll_wait() returns IN event.");
    rc = rpc_epoll_wait(pco_iut, epfd, events, EVENTS_NUM, 1000);
    if (rc != 1 || events->events != RPC_EPOLLIN)
        TEST_VERDICT("Incorrect events were returned by the first "
                     "epoll_wait() call");
    TEST_STEP("Read a part of the data.");
    rc = rpc_recv(pco_iut, iut_s, rcvbuf, len, 0);
    SOCKTS_CHECK_RECV(pco_iut, sndbuf, rcvbuf, len, rc);

    TEST_STEP("Check another one @a epoll_wait() returns IN event.");
    rc = rpc_epoll_wait(pco_iut, epfd, events, EVENTS_NUM, 1000);
    if (rc != 1 || events->events != RPC_EPOLLIN)
        TEST_VERDICT("Incorrect events were returned by the second "
                     "epoll_wait() call");
    TEST_STEP("Read remains data.");
    rc = rpc_recv(pco_iut, iut_s, rcvbuf, len, 0);
    SOCKTS_CHECK_RECV(pco_iut, sndbuf, rcvbuf, len, rc);

    TEST_STEP("Check @a epoll_wait() returns no events.");
    rc = rpc_epoll_wait(pco_iut, epfd, events, EVENTS_NUM, 1000);
    if (rc > 0)
        rpc_recv(pco_iut, iut_s, rcvbuf, len, RPC_MSG_DONTWAIT);

    TEST_SUCCESS;
cleanup:
    rpc_close(pco_tst, tst_s);
    rpc_close(pco_iut, iut_s);
    rpc_close(pco_iut, epfd);

    TEST_END;
}
