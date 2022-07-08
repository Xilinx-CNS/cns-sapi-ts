/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-oo_epoll_read   Onload extension epoll after data reading
 *
 * @objective  Check that onload_ordered_epoll_wait() function returns
 *             events and actual bytes number after reading data on a
 *             socket. Send data via two flows, read amount of data from one
 *             of the flows, which is more, less or equal to bytes number of
 *             a one potential @b oo_event.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param sock_type     Type of socket used in the test
 * @param test_case     Determine how much data (less, more or equal to
 *                      bytes number of a one potential @b oo_event) should
 *                      be read before call Onload epoll.
 * 
 * @type Conformance.
 *
 * @par Scenario:
 * -# Create epoll socket @p epfd on IUT.
 * -# Repeat two times the following steps to create two flows:
 *   -# Create connected sockets pair on IUT and TST with test API macros
 *      @b GEN_CONNECTION, UDP or TCP in dependence on @p sock_type.
 *   -# Add IUT socket to the epoll set with @p epfd.
 * -# Send data via the both tester sockets to IUT. If @p test_case is
 *    @c more data should be passed three times from tester sockets in
 *    the following sequence first_socket-second_socket-first_socket.
 * -# Read amount (in dependence on @p test_case) of data from the
 *    first IUT socket.
 * -# Call @b onload_ordered_epoll_wait on IUT, check events number,
 *    @b timestamps and @b bytes numbers.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/oo_epoll_read"

#include "sockapi-test.h"
#include "oo_epoll.h"

#define MAX_EVENTS 10

typedef enum {
    OO_READ_LESS = 0,
    OO_READ_EQ,
    OO_READ_MORE,
} test_case_t;

#define TEST_CASE \
    { "less", OO_READ_LESS }, \
    { "equal", OO_READ_EQ }, \
    { "more", OO_READ_MORE }

/** Buffer size limits */
static int buf_size_min;
static int buf_size_max;

/**
 * Send data via two flows, read part of data from one of the
 * flows, check that Onload epoll returns events and actual bytes number.
 * 
 * @param pco_iut       IUT RPC server
 * @param pco_tst       Tester RPC server
 * @param tst_s         Array of sockets on IUT
 * @param tst_s         Array of sockets on tester
 * @param epfd          Epoll file descriptor on IUT
 * @param sock_type     Socket type
 */
static void
test_read_woda_less(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                    int *iut_s, int *tst_s, int epfd,
                    rpc_socket_type sock_type)
{
    rpc_onload_ordered_epoll_event  oo_events[MAX_EVENTS];
    struct rpc_epoll_event          events[MAX_EVENTS];

    int     buflen1 = rand_range(buf_size_min, buf_size_max);
    int     buflen2 = rand_range(buf_size_min, buf_size_max);
    int     readlen = buflen1 / 2;
    char   *buf = te_make_buf_by_len(buf_size_max);
    int     rc;

    rpc_send(pco_tst, tst_s[0], buf, buflen1, 0);
    rpc_send(pco_tst, tst_s[1], buf, buflen2, 0);

    if (rpc_recv(pco_iut, iut_s[0], buf, readlen, 0) != readlen)
        TEST_VERDICT("Read unexpected amount of data");

    TAPI_WAIT_NETWORK;
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       MAX_EVENTS, 2000);
    if ((sock_type == RPC_SOCK_DGRAM && rc != 1) ||
        (sock_type == RPC_SOCK_STREAM && rc != 2))
        TEST_VERDICT("Onload epoll returned wrong events number %d", rc);

    if (sock_type == RPC_SOCK_STREAM &&
        oo_epoll_cmp_ts(oo_epoll_get_event_by_fd(iut_s[0], events,
                                                 oo_events, 2),
                        oo_epoll_get_event_by_fd(iut_s[1], events,
                                                 oo_events, 2)) >= 0)
        RING_VERDICT("Timestamp value of the first stream is greater or "
                     "equal to the second stream value");

    if (sock_type == RPC_SOCK_STREAM &&
        oo_epoll_check_bytes(iut_s[0], events, oo_events, rc,
                             buflen1 - readlen))
        RING_VERDICT("Bytes field of the first stream has wrong value");

    if (oo_epoll_check_bytes(iut_s[1], events, oo_events, rc, buflen2))
        RING_VERDICT("Bytes field of the second stream has wrong value");

    free(buf);
}


/**
 * Send data via two flows, read amount of data from one of the
 * flows, which is more than bytes number of a one potential @b oo_event.
 * Check that Onload epoll returns events and actual bytes number.
 * 
 * @param pco_iut       IUT RPC server
 * @param pco_tst       Tester RPC server
 * @param tst_s         Array of sockets on IUT
 * @param tst_s         Array of sockets on tester
 * @param epfd          Epoll file descriptor on IUT
 * @param sock_type     Socket type
 */
static void
test_read_woda_more(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                    int *iut_s, int *tst_s, int epfd, int sock_type)
{
    rpc_onload_ordered_epoll_event  oo_events[MAX_EVENTS];
    struct rpc_epoll_event          events[MAX_EVENTS];
    rpc_onload_ordered_epoll_event *oo_ev_1;
    rpc_onload_ordered_epoll_event *oo_ev_2;

    int     buflen1 = rand_range(buf_size_min, buf_size_max);
    int     buflen2 = rand_range(buf_size_min, buf_size_max);
    int     buflen3 = rand_range(buf_size_min, buf_size_max);
    int     readlen = buflen1 + buflen3 / 2;
    char   *buf = te_make_buf_by_len(readlen);
    int     rc;

    rpc_send(pco_tst, tst_s[0], buf, buflen1, 0);
    rpc_send(pco_tst, tst_s[1], buf, buflen2, 0);
    rpc_send(pco_tst, tst_s[0], buf, buflen3, 0);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        if (rpc_recv(pco_iut, iut_s[0], buf, buflen1, 0) != buflen1)
            TEST_VERDICT("Read unexpected amount of data");
        if (rpc_recv(pco_iut, iut_s[0], buf, readlen - buflen1, 0) !=
                     readlen - buflen1)
            TEST_VERDICT("Read unexpected amount of data");
    }
    else
    {
        if (rpc_recv(pco_iut, iut_s[0], buf, readlen, 0) != readlen)
            TEST_VERDICT("Read unexpected amount of data");
    }

    TAPI_WAIT_NETWORK;
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       MAX_EVENTS, 2000);
    if ((sock_type == RPC_SOCK_DGRAM && rc != 1) ||
        (sock_type == RPC_SOCK_STREAM && rc != 2))
        TEST_VERDICT("Onload epoll returned wrong events number %d", rc);

    if (sock_type == RPC_SOCK_STREAM &&
        oo_epoll_check_bytes(iut_s[0], events, oo_events, rc,
                             buflen1 + buflen3 - readlen))
        RING_VERDICT("Bytes field of the first stream has wrong value");

    if (oo_epoll_check_bytes(iut_s[1], events, oo_events, rc, buflen2))
        RING_VERDICT("Bytes field of the second stream has wrong value");

    if (sock_type == RPC_SOCK_STREAM)
    {
        oo_ev_1 = oo_epoll_get_event_by_fd(iut_s[0], events, oo_events, 2);
        oo_ev_2 = oo_epoll_get_event_by_fd(iut_s[1], events, oo_events, 2);
        if (oo_epoll_cmp_ts(oo_ev_1, oo_ev_2) <= 0)
            RING_VERDICT("The first stream timestamp should be greater "
                         "than the second");
    }

    free(buf);
}

/**
 * Send data via two flows, read amount of data from one of the
 * flows, which is equal to bytes number of a one potential @b oo_event.
 * Check that Onload epoll returns events and actual bytes number.
 * 
 * @param pco_iut       IUT RPC server
 * @param pco_tst       Tester RPC server
 * @param tst_s         Array of sockets on IUT
 * @param tst_s         Array of sockets on tester
 * @param epfd          Epoll file descriptor on IUT
 */
static void
test_read_woda_eq(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                  int *iut_s, int *tst_s, int epfd)
{
    rpc_onload_ordered_epoll_event  oo_events_1[MAX_EVENTS];
    rpc_onload_ordered_epoll_event  oo_events_2[MAX_EVENTS];
    rpc_onload_ordered_epoll_event *oo_ev_1;
    rpc_onload_ordered_epoll_event *oo_ev_2;
    struct rpc_epoll_event          events_1[MAX_EVENTS];
    struct rpc_epoll_event          events_2[MAX_EVENTS];

    int     buflen1 = rand_range(buf_size_min, buf_size_max);
    int     buflen2 = rand_range(buf_size_min, buf_size_max);
    int     buflen3 = rand_range(buf_size_min, buf_size_max);
    char   *buf = te_make_buf_by_len(buf_size_max);
    int     rc;

    rpc_send(pco_tst, tst_s[0], buf, buflen1, 0);
    rpc_send(pco_tst, tst_s[1], buf, buflen2, 0);

    if (rpc_recv(pco_iut, iut_s[0], buf, buflen1, 0) != buflen1)
        TEST_VERDICT("Read unexpected amount of data");
    TAPI_WAIT_NETWORK;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events_1, oo_events_1,
                                       MAX_EVENTS, 2000);
    if (rc < 0)
    {
        if (RPC_ERRNO(pco_iut) == RPC_EINVAL)
            TEST_VERDICT("WODA is not supported");
        TEST_VERDICT("WODA function faild with unexpected errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (rc != 1)
        TEST_VERDICT("Onload epoll returned wrong events number %d", rc);

    if (oo_epoll_check_bytes(iut_s[1], events_1, oo_events_1, rc, buflen2))
        RING_VERDICT("Bytes field of the second stream has wrong value");

    rpc_send(pco_tst, tst_s[0], buf, buflen3, 0);

    TAPI_WAIT_NETWORK;
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events_2, oo_events_2,
                                       MAX_EVENTS, 2000);
    if (rc != 2)
        TEST_VERDICT("Onload epoll returned wrong events number %d", rc);

    if (oo_epoll_check_bytes(iut_s[0], events_2, oo_events_2, rc, buflen3))
        RING_VERDICT("Bytes field of the first stream has wrong value");
    if (oo_epoll_check_bytes(iut_s[1], events_2, oo_events_2, rc, buflen2))
        RING_VERDICT("Bytes field of the second stream has wrong value");

    oo_ev_1 = oo_epoll_get_event_by_fd(iut_s[1], events_1, oo_events_1, 1);
    oo_ev_2 = oo_epoll_get_event_by_fd(iut_s[1], events_2, oo_events_2, 2);
    if (oo_epoll_cmp_ts(oo_ev_1, oo_ev_2) != 0)
        RING_VERDICT("Timestamps are different for the second stream");

    oo_ev_1 = oo_epoll_get_event_by_fd(iut_s[0], events_2, oo_events_2, 2);
    if (oo_epoll_cmp_ts(oo_ev_1, oo_ev_2) <= 0)
        RING_VERDICT("The first stream timestamp should be greater "
                     "than the second");

    free(buf);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    int                   *iut_s = NULL;
    int                   *tst_s = NULL;
    rpc_socket_type        sock_type = RPC_SOCK_UNKNOWN;
    test_case_t            test_case;

    int epfd = -1;
    int streams_num = 2;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ENUM_PARAM(test_case, TEST_CASE);
    TEST_GET_INT_PARAM(buf_size_min);
    TEST_GET_INT_PARAM(buf_size_max);

    epfd = rpc_epoll_create(pco_iut, MAX_EVENTS);
    iut_s = te_calloc_fill(streams_num, sizeof(*iut_s), 0xff);
    tst_s = te_calloc_fill(streams_num, sizeof(*tst_s), 0xff);

    for (i = 0; i < streams_num; i++)
    {
        GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &iut_s[i], &tst_s[i]);
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s[i],
                             RPC_EPOLLIN);

        TAPI_SET_NEW_PORT(pco_iut, iut_addr);
        TAPI_SET_NEW_PORT(pco_tst, tst_addr);
    }

    switch (test_case)
    {
        case OO_READ_LESS:
            test_read_woda_less(pco_iut, pco_tst, iut_s, tst_s, epfd,
                                sock_type);
        break;

        case OO_READ_EQ:
            test_read_woda_eq(pco_iut, pco_tst, iut_s, tst_s, epfd);
        break;

        case OO_READ_MORE:
            test_read_woda_more(pco_iut, pco_tst, iut_s, tst_s, epfd,
                                sock_type);
        break;

        default:
            TEST_VERDICT("Unknown test iteration");
    }

    for (i = 0; i < streams_num; i++)
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_DEL, iut_s[i],
                             RPC_EPOLLIN);

    TEST_SUCCESS;

cleanup:
    if (iut_s != NULL && tst_s != NULL)
    {
        for (i = 0; i < streams_num; i++)
        {
            CLEANUP_RPC_CLOSE(pco_iut, iut_s[i]);
            CLEANUP_RPC_CLOSE(pco_tst, tst_s[i]);
        }
    }
    CLEANUP_RPC_CLOSE(pco_iut, epfd);

    free(iut_s);
    free(tst_s);

    TEST_END;
}
