/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-multi_level_iomux I/O multiplexing function with epoll fd
 *
 * @objective Check that iomux functions correctly handle the situation
 *            when they are called with epoll descriptor.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param sock_type     Type of sockets using in the test
 * @param iomux         String parameter that contains the name of
 *                      iomux function (@c select, @c pselect, @c poll or
 *                      @c epoll_wait)
 * @param evts          One of @c in, @c out or @c inout
 * @param data_size     The amount of data to be sent or read
 * @param timeout       Timeout for @b epoll_wait() function
 * @param send_data     Send or do not send any data
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type connection between pco_iut and pco_tst. Two
 *    connected sockets iut_s and tst_s would appear.
 * -# Create @p epfd with @p iut_s socket and with the events according
 *    to @p evts paramter using @b epoll_create() and
 *    @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# If @p send_data is @c TRUE, evts is @c out or @c inout and
 *    @p sock_type is @c SOCK_STREAM call @b rpc_overfill_buffers() on
 *    @b iut_s socket.
 * -# Call @p iomux funtion to watch on read and write events on
 *    @p epfd descriptor with @p timeout.
 * -# If @p send data is @c TRUE and @p evts is equal to @c in send
 *    @p data_size bytes of data from @p tst_s socket to @p iut_s.
 * -# If @p send_data is @c TRUE, evts is @c out or @c inout read
 *    @p data_size bytes of data on @p iut_s socket.
 * -# In case of @c FALSE @p send_data and @c in @p evts check that
 *    @p iomux function returns @c 0. In all other cases check that
 *    @p iomux function exits with read event.
 * -# @b close() all sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/multi_level_iomux"

#include "sockapi-test.h"
#include "iomux.h"
#include "epoll_common.h"

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    rpc_socket_type         sock_type;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    iomux_evt_fd            events[2];
    uint32_t                event;

    int                     data_size;
    tarpc_timeval           iomux_t;
    int                     timeout;
    const char             *evts;

    int                     epfd = -1;
    struct rpc_epoll_event  evt;

    uint64_t                total_bytes;
    te_bool                 send_data;
    te_bool                 early_ctl;
    te_bool                 use_et;
    te_bool                 use_one_shot;
    te_bool                 get_ev_before;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(send_data);
    TEST_GET_BOOL_PARAM(early_ctl);
    TEST_GET_BOOL_PARAM(use_et);
    TEST_GET_BOOL_PARAM(use_one_shot);
    TEST_GET_BOOL_PARAM(get_ev_before);

    memset(events, 0, sizeof(events));

    /* Scenario */
    PARSE_EVTS(evts, event, event);
    if (use_et)
        event |= RPC_EPOLLET;
    if (use_one_shot)
        event |= RPC_EPOLLONESHOT;

    GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, FALSE, sock_type,
                           iut_addr, tst_addr, iut_s, tst_s, TRUE,
                           TRUE, epfd, early_ctl, event);

    if ((strcmp(evts, "out") == 0 || strcmp(evts, "inout") == 0) &&
        sock_type == RPC_SOCK_STREAM && send_data)
    {
        rpc_overfill_buffers_gen(pco_iut, iut_s, &total_bytes,
                                 iomux == IC_OO_EPOLL ? IC_EPOLL : iomux);
    }

    events[0].fd = epfd;
    events[0].events = EVT_RDWR;

    iomux_t.tv_sec = timeout / 1000;
    iomux_t.tv_usec = (timeout % 1000) * 1000;
    if (!get_ev_before)
    {
        pco_iut->op = RCF_RPC_CALL;
        iomux_call(iomux, pco_iut, events, 1, &iomux_t);
    }

    if (send_data)
    {
#define MAX_BUFF_SIZE 10240
        unsigned char  buffer[MAX_BUFF_SIZE];

        TAPI_WAIT_NETWORK;
        if (strcmp(evts, "in") == 0)
            RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
        if ((strcmp(evts, "out") == 0 || strcmp(evts, "inout") == 0) &&
            sock_type == RPC_SOCK_STREAM)
        {
            do {
                rc = rpc_read(pco_tst, tst_s, buffer, MAX_BUFF_SIZE);
                total_bytes -= rc;
            } while (total_bytes != 0);
        }
        TAPI_WAIT_NETWORK;
    }

    if (get_ev_before)
    {
        if (use_et | use_one_shot)
        {
            rc = rpc_epoll_wait(pco_iut, epfd, &evt, 1, timeout);
            if (send_data)
            {
                if (rc == 0)
                    TEST_VERDICT("epoll_wait() returned %d instead of %d",
                                 rc, rc ? 0 : 1);
            }
            else
            {
                if ((rc == 0 && strcmp(evts, "in") != 0) ||
                    (rc == 1 && strcmp(evts, "in") == 0))
                    TEST_VERDICT("epoll_wait() returned %d instead of %d",
                                 rc, rc ? 0 : 1);
            }
        }
    }
    else
        pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, events, 1, &iomux_t);
    if ((!send_data) && (strcmp(evts, "in") == 0))
    {
        if (rc != 0)
            TEST_VERDICT("iomux_call() returned %d instead of 0", rc);
    }
    else if (!(get_ev_before && (use_et | use_one_shot)))
    {
        if (rc != 1)
            TEST_VERDICT("iomux_call() returned %d instead of 1", rc);

        if (events[0].revents != EVT_RD)
        {
            TEST_VERDICT("Incorrect events have been reported.");
        }
    }
    else
    {
        if ((rc == 1) && (use_et | use_one_shot))
        {
            rc = rpc_epoll_wait(pco_iut, epfd, &evt, 1, timeout);
            if (rc == 0)
                TEST_VERDICT("epoll_wait() returned 0 instead of 1");
            else
                ERROR_VERDICT("Event is reported twice");
            rc = iomux_call(iomux, pco_iut, events, 1, &iomux_t);
        }
        if (rc != 0)
            TEST_VERDICT("iomux_call() returned %d instead of 0", rc);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
