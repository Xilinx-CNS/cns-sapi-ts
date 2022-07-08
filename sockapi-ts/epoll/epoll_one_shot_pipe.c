/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-epoll_one_shot_pipe  Using epoll functions with pipe and EPOLLONESHOT or EPOLLET flag
 *
 * @objective  Check that epoll functions with flag EPOLLONESHOT or EPOLLET
 *             report correct events (rd, wr, rdwr) sequence for pipe sockets.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param evts          One of @c in, @c out or @c inout
 * @param timeout       Timeout for @b epoll_wait() function
 * @param data_size     The amount of data to be sent or read
 * @param refresh       This parameter describes how to refresh the fd
 *                      with @c EPOLLONESHOT (or @c EPOLLET) flag in
 *                      epoll descriptor. It can be @c none, @c same,
 *                      @c different
 * @param non_blocking  Call epoll function before an event happening
 * @param et_one_shot   Use @c EPOLLET or @c EPOLLONESHOT
 *
 * @note This test was splitted from the test epoll_one_shot.
 * 
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epoll_one_shot_pipe"

#include "sockapi-test.h"
#include "iomux.h"
#include "epoll_common.h"

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_fd = -1;
    int                     tst_fd = -1;

    rpc_socket_type         sock_type = RPC_SOCK_UNKNOWN;

    const char             *evts;
    const char             *refresh;

    int                     data_size;
    unsigned char          *buffer = NULL;

    int                     epfd = -1;
    struct rpc_epoll_event  events[2];
    uint32_t                event;
    int                     maxevents = 2;
    int                     timeout;

    uint64_t                total_bytes;
    uint32_t                exp_ev;
    te_bool                 non_blocking;
    te_bool                 is_wrt = FALSE;
    int                     finish_cnt = 0;

    const char             *et_one_shot;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_STRING_PARAM(refresh);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(non_blocking);
    TEST_GET_STRING_PARAM(et_one_shot);
    TEST_GET_IOMUX_FUNC(iomux);

    buffer = te_make_buf_by_len(data_size);

    if (non_blocking)
        timeout = 0;

    PARSE_EVTS(evts, event, exp_ev);

    if (strcmp(et_one_shot, "et") == 0)
        event |= RPC_EPOLLET;
    else if (strcmp(et_one_shot, "one_shot") == 0)
        event |= RPC_EPOLLONESHOT;
    else
        TEST_FAIL("Incorrect value of 'et_one_shot' parameter.");

    GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, TRUE, sock_type,
                           iut_addr, tst_addr, iut_fd, tst_fd,
                           (exp_ev & RPC_EPOLLOUT) ? TRUE : FALSE,
                           TRUE, epfd, FALSE, event);

    GET_FD2_PCO(pco_iut, pco_tst, pco_tst, TRUE, iut_fd, tst_fd);

    if (strcmp(evts, "out") == 0 || strcmp(evts, "inout") == 0)
        rpc_overfill_fd(pco_iut, iut_fd, &total_bytes);

    if (!non_blocking)
    {
        pco_iut->op = RCF_RPC_CALL;
        rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                              maxevents, timeout);
        TAPI_WAIT_NETWORK;
    }

    if (strcmp(evts, "in") == 0)
        RPC_WRITE(rc, pco_tst, tst_fd, buffer, data_size);
    else if (strcmp(evts, "out") == 0 || strcmp(evts, "inout") == 0)
    {
        do {
            total_bytes -= rpc_read(pco_tst, tst_fd, buffer, data_size);
            if (!is_wrt)
            {
                if (!non_blocking)
                    rcf_rpc_server_is_op_done(pco_iut, &is_wrt);
                else
                    RPC_GET_WRITABILITY(is_wrt, pco_iut, iut_fd, 1);
            }
            else
                finish_cnt++;
        } while (finish_cnt < 3 && total_bytes > 0);
    }
    TAPI_WAIT_NETWORK;

    if (!non_blocking)
        pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, timeout);

    if (rc != 1)
        TEST_FAIL("%s() returned %d instead of 1",
                  iomux_call_en2str(iomux), rc);
    else if (events[0].data.fd != iut_fd)
        TEST_FAIL("%s() retured incorrect fd %d instead of "
                  "%d iut_fd", iomux_call_en2str(iomux),
                  events[0].data.fd, iut_fd);
    else if (events[0].events != exp_ev)
        TEST_FAIL("%s() returned incorrect events",
                  iomux_call_en2str(iomux));
    TAPI_WAIT_NETWORK;

    if (strcmp(refresh, "same") == 0)
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_MOD, iut_fd, event);
    else if (strcmp(refresh, "different") == 0)
    {
        if (strcmp(evts, "in") == 0)
            event = exp_ev = RPC_EPOLLOUT;
        else
            event = exp_ev = RPC_EPOLLIN;

        if (strcmp(et_one_shot, "et") == 0)
            event |= RPC_EPOLLET;
        else
            event |= RPC_EPOLLONESHOT;

        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_MOD, iut_fd,
                             event);

        if (strcmp(evts, "in") != 0)
        {
            TAPI_WAIT_NETWORK;
            RPC_WRITE(rc, pco_iut, iut_fd, buffer, data_size);
        }
    }
    else if (strcmp(refresh, "none") != 0)
        TEST_FAIL("Incorrect value of 'refresh' parameter.");
    TAPI_WAIT_NETWORK;

    if (strcmp(refresh, "same") == 0)
    {
        rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);
        if (rc != 1)
            TEST_FAIL("%s() returned %d instead of 1",
                      iomux_call_en2str(iomux), rc);
        else if (events[0].data.fd != iut_fd)
            TEST_FAIL("%s() retured incorrect fd %d instead of "
                      "%d iut_fd", iomux_call_en2str(iomux),
                      events[0].data.fd, iut_fd);
        else if (events[0].events != exp_ev)
            TEST_FAIL("%s() returned incorrect events",
                      iomux_call_en2str(iomux));
        TAPI_WAIT_NETWORK;
    }

    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, timeout);

    if (rc != 0)
    {
        if (rc == 1)
        {
            rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                                  maxevents, timeout);
            if (rc == 1)
            {
                rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                                  maxevents, 0);
                if (rc == 1)
                    TEST_VERDICT("Event is reported multiple times");
                else if (rc == 0)
                    TEST_VERDICT("Event is reported thrice");
            }
            else if (rc == 0)
                TEST_VERDICT("Event is reported twice");
        }
        TEST_FAIL("Unexpected epoll result");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);

    if (pco_tst != NULL)
        rcf_rpc_server_destroy(pco_tst);

    free(buffer);

    TEST_END;
}

