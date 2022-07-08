/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-edge_triggered_out TCP and UDP OUT event report in edge-triggered mode
 *
 * @objective Check TCP and UDP OUT event is reported correctly in
 *            edge-triggered mode.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT.
 * @param pco_tst       Tester PCO.
 * @param sock_type     Socket type UDP or TCP.
 *
 * @par Test scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/edge_triggered_out"

#include "sockapi-test.h"

/* Expected events number. */
#define EVENTS_NUM 1

/* The timeout to ensure TCP machinery is done. */
#define SECOND_EPOLL_WAIT_TIMEOUT 500

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

    TEST_STEP("Create sockets on IUT and tester, bind and connect them.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Create epoll fd and add IUT socket to expect OUT event in "
              "edge-triggered mode.");
    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         RPC_EPOLLOUT | RPC_EPOLLET);

    TEST_STEP("Check @a epoll_wait() returns OUT event.");
    rc = rpc_epoll_wait(pco_iut, epfd, events, EVENTS_NUM, 0);
    if (rc != 1 || events->events != RPC_EPOLLOUT)
        TEST_VERDICT("Incorrect events were returned by the first "
                     "epoll_wait() call: %s",
                     poll_event_rpc2str(events->events));

    TEST_STEP("Call @a epoll_wait() once againt and check that it  "
              "returns 0.");
    rc = rpc_epoll_wait(pco_iut, epfd, events, EVENTS_NUM,
                        SECOND_EPOLL_WAIT_TIMEOUT);
    if (rc != 0)
        ERROR_VERDICT("Event is reported twice");

    TEST_STEP("Send a data packet.");
    rpc_write(pco_iut, iut_s, sndbuf, len);

    TEST_STEP("Call @a epoll_wait(), it should return OUT event: "
              "-# for TCP socket; "
              "-# for UDP socket if no data was sent.");
    rc = rpc_epoll_wait(pco_iut, epfd, events, EVENTS_NUM,
                        SECOND_EPOLL_WAIT_TIMEOUT);
    if (sock_type == RPC_SOCK_STREAM)
    {
        if (rc != 0)
            TEST_VERDICT("Unexpected events were returned by the second "
                         "epoll_wait() call: %s",
                         poll_event_rpc2str(events->events));
    }
    else
    {
        if (rc != 1 || events->events != RPC_EPOLLOUT)
            TEST_VERDICT("Incorrect events were returned by the second "
                         "epoll_wait() call: %s",
                         poll_event_rpc2str(events->events));
    }

    rc = rpc_recv(pco_tst, tst_s, rcvbuf, len, 0);
    SOCKTS_CHECK_RECV(pco_tst, sndbuf, rcvbuf, len, rc);

    TEST_SUCCESS;
cleanup:
    rpc_close(pco_tst, tst_s);
    rpc_close(pco_iut, iut_s);
    rpc_close(pco_iut, epfd);

    TEST_END;
}
