/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-oo_epoll_dont_read   Call a number of Onload epoll in a row without data reading
 *
 * @objective  Call function onload_ordered_epoll_wait() a number times in a
 *             row without any data reading during this time, check that the
 *             calls handle events as expected.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param sock_type     Type of socket used in the test
 * @param test_case     Reproduce a sequence of sending packets and epoll
 *                      calls in dependence on this parameter:
 * @n
 *                      @b 1: A1 E1 A2 E2
 * @n
 *                      @b 2: A1 B1 E1 A2 E2
 * @n
 *                      @b 3: A1 B1 E1 B2 E2
 * @n
 *                      Where Ax - data segments on a one socket,
 *                            Bx - data segments on anoter socket,
 *                            Ex - @b onload_ordered_epoll_wait call.
 * 
 * @type Conformance.
 *
 * @par Scenario:
 * -# Create epoll socket @p epfd on IUT.
 * -# Reproduce the following steps to create a number of flows in
 *    dependence on @p test_case:
 * -#     Create connected sockets pair on IUT and TST with test API macros
 *        @b GEN_CONNECTION, UDP or TCP in dependence on @p sock_type.
 * -#     Add IUT socket to the epoll set with @p epfd.
 * -# Reproduce one of the allowed actions sequnces in dependence
 *    on @p test_case. Check that timestamps and bytes obtained with Onload
 *    epoll call have properly values in dependence on sent packets.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/oo_epoll_dont_read"

#include "sockapi-test.h"
#include "oo_epoll.h"

#define MAX_EVENTS 10

/** Buffer size limits */
static int buf_size_min;
static int buf_size_max;

/** Buffer to send packets */
static char *buf = NULL;

/**
 * Reproducing of the following plot:
 * time    t1 t2 t3 t4
 * -------------------
 * segment A1 E1 A2 E2
 * 
 * @param pco_iut       IUT RPC server
 * @param pco_tst       Tester RPC server
 * @param tst_s         Array of sockets on tester
 * @param epfd          Epoll file descriptor on IUT
 * @param streams_num   Created streams number
 */
static void
test_AEAE(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst, int *tst_s,
          int epfd, int streams_num)
{
    rpc_onload_ordered_epoll_event  oo_events_1[MAX_EVENTS];
    rpc_onload_ordered_epoll_event  oo_events_2[MAX_EVENTS];
    struct rpc_epoll_event          events[MAX_EVENTS];

    int     buflen1 = rand_range(buf_size_min, buf_size_max);
    int     buflen2 = rand_range(buf_size_min, buf_size_max);
    int     rc;

    if (streams_num != 1)
        TEST_VERDICT("Wrong streams number");

    rpc_send(pco_tst, tst_s[0], buf, buflen1, 0);
    TAPI_WAIT_NETWORK;
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events_1,
                                       MAX_EVENTS, 2000);
    if (rc != 1)
        TEST_VERDICT("Onload epoll doesn't see event");

    if (oo_events_1[0].bytes != buflen1)
        TEST_VERDICT("Bytes field has wrong value");

    rpc_send(pco_tst, tst_s[0], buf, buflen2, 0);
    TAPI_WAIT_NETWORK;
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events_2,
                                       MAX_EVENTS, 2000);
    if (rc != 1)
        TEST_VERDICT("Second call of Onload epoll doesn't see event");

    if (oo_epoll_cmp_ts(oo_events_1, oo_events_2) != 0)
        RING_VERDICT("Timestamps are different");

    if (oo_events_2[0].bytes != buflen1 + buflen2)
        TEST_VERDICT("Bytes field has wrong value after the second epoll");
}

/**
 * Reproducing of the following plot:
 * time    t1 t2 t3 t4 t5
 * ----------------------
 * segment A1 B1 E1 A2 E2
 * 
 * @param pco_iut       IUT RPC server
 * @param pco_tst       Tester RPC server
 * @param tst_s         Array of sockets on IUT
 * @param tst_s         Array of sockets on tester
 * @param epfd          Epoll file descriptor on IUT
 * @param streams_num   Created streams number
 */
static void
test_ABEAE(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst, int *iut_s,
           int *tst_s, int epfd, int streams_num)
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
    int     rc;

    if (streams_num != 2)
        TEST_VERDICT("Wrong streams number");

    rpc_send(pco_tst, tst_s[0], buf, buflen1, 0);
    rpc_send(pco_tst, tst_s[1], buf, buflen2, 0);

    TAPI_WAIT_NETWORK;
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events_1, oo_events_1,
                                       MAX_EVENTS, 2000);
    if (rc != 2)
        TEST_VERDICT("Onload epoll returned wrong events number");

    if (oo_epoll_cmp_ts(oo_epoll_get_event_by_fd(iut_s[0], events_1,
                                           oo_events_1, 2),
                        oo_epoll_get_event_by_fd(iut_s[1], events_1,
                                           oo_events_1, 2)) >= 0)
        TEST_VERDICT("Timestamp value of the first stream is greater or "
                     "equal to the second stream value");

    if (oo_epoll_check_bytes(iut_s[0], events_1, oo_events_1, rc, buflen1))
        TEST_VERDICT("Bytes field of the first stream has wrong value");
    if (oo_epoll_check_bytes(iut_s[1], events_1, oo_events_1, rc, buflen2))
        TEST_VERDICT("Bytes field of the second stream has wrong value");

    rpc_send(pco_tst, tst_s[0], buf, buflen3, 0);
    TAPI_WAIT_NETWORK;
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events_2, oo_events_2,
                                       MAX_EVENTS, 2000);
    if (rc != 2)
        TEST_VERDICT("Second call of Onload epoll returned wrong events "
                     "number");

    if (oo_epoll_check_bytes(iut_s[0], events_2, oo_events_2, rc, buflen1))
        TEST_VERDICT("Bytes field of the first stream has wrong value");
    if (oo_epoll_check_bytes(iut_s[1], events_2, oo_events_2, rc, buflen2))
        TEST_VERDICT("Bytes field of the second stream has wrong value");

    oo_ev_1 = oo_epoll_get_event_by_fd(iut_s[0], events_1, oo_events_1, 2);
    oo_ev_2 = oo_epoll_get_event_by_fd(iut_s[0], events_2, oo_events_2, 2);
    if (oo_epoll_cmp_ts(oo_ev_1, oo_ev_2) != 0)
        RING_VERDICT("Timestamps are different for the first stream");

    oo_ev_1 = oo_epoll_get_event_by_fd(iut_s[1], events_1, oo_events_1, 2);
    oo_ev_2 = oo_epoll_get_event_by_fd(iut_s[1], events_2, oo_events_2, 2);
    if (oo_epoll_cmp_ts(oo_ev_1, oo_ev_2) != 0)
        RING_VERDICT("Timestamps are different for the second stream");
}

/**
 * Reproducing of the following plot:
 * time    t1 t2 t3 t4 t5
 * ----------------------
 * segment A1 B1 E1 B2 E2
 * 
 * @param pco_iut       IUT RPC server
 * @param pco_tst       Tester RPC server
 * @param tst_s         Array of sockets on IUT
 * @param tst_s         Array of sockets on tester
 * @param epfd          Epoll file descriptor on IUT
 * @param streams_num   Created streams number
 */
static void
test_ABEBE(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst, int *iut_s,
           int *tst_s, int epfd, int streams_num)
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
    int     rc;

    if (streams_num != 2)
        TEST_VERDICT("Wrong streams number");

    rpc_send(pco_tst, tst_s[0], buf, buflen1, 0);
    rpc_send(pco_tst, tst_s[1], buf, buflen2, 0);

    TAPI_WAIT_NETWORK;
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events_1, oo_events_1,
                                       MAX_EVENTS, 2000);
    if (rc != 2)
        TEST_VERDICT("Onload epoll returned wrong events number");

    if (oo_epoll_cmp_ts(oo_epoll_get_event_by_fd(iut_s[0], events_1,
                                           oo_events_1, 2),
                        oo_epoll_get_event_by_fd(iut_s[1], events_1,
                                           oo_events_1, 2)) >= 0)
        TEST_VERDICT("Timestamp value of the first stream is greater or "
                     "equal to the second stream value");

    if (oo_epoll_check_bytes(iut_s[0], events_1, oo_events_1, rc, buflen1))
        TEST_VERDICT("Bytes field of the first stream has wrong value");
    if (oo_epoll_check_bytes(iut_s[1], events_1, oo_events_1, rc, buflen2))
        TEST_VERDICT("Bytes field of the second stream has wrong value");

    rpc_send(pco_tst, tst_s[1], buf, buflen3, 0);
    TAPI_WAIT_NETWORK;
    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events_2, oo_events_2,
                                       MAX_EVENTS, 2000);
    if (rc != 2)
        TEST_VERDICT("Second call of Onload epoll returned wrong events "
                     "number");

    if (oo_epoll_check_bytes(iut_s[0], events_2, oo_events_2, rc, buflen1))
        TEST_VERDICT("Bytes field of the first stream has wrong value");
    if (oo_epoll_check_bytes(iut_s[1], events_2, oo_events_2, rc,
                             buflen2 + buflen3))
        TEST_VERDICT("Bytes field of the second stream has wrong value");

    oo_ev_1 = oo_epoll_get_event_by_fd(iut_s[0], events_1, oo_events_1, 2);
    oo_ev_2 = oo_epoll_get_event_by_fd(iut_s[0], events_2, oo_events_2, 2);
    if (oo_epoll_cmp_ts(oo_ev_1, oo_ev_2) != 0)
        RING_VERDICT("Timestamps are different for the first stream");

    oo_ev_1 = oo_epoll_get_event_by_fd(iut_s[1], events_1, oo_events_1, 2);
    oo_ev_2 = oo_epoll_get_event_by_fd(iut_s[1], events_2, oo_events_2, 2);
    if (oo_epoll_cmp_ts(oo_ev_1, oo_ev_2) != 0)
        RING_VERDICT("Timestamps are different for the second stream");
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

    int epfd = -1;
    int streams_num = 2;
    int i;
    int test_case;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(test_case);
    TEST_GET_INT_PARAM(buf_size_min);
    TEST_GET_INT_PARAM(buf_size_max);

    buf = te_make_buf_by_len(buf_size_max);

    if (test_case == 1)
        streams_num = 1;

    epfd = rpc_epoll_create(pco_iut, MAX_EVENTS);
    iut_s = calloc(streams_num, sizeof(*iut_s));
    tst_s = calloc(streams_num, sizeof(*tst_s));

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
        case 1:
            test_AEAE(pco_iut, pco_tst, tst_s, epfd, streams_num);
        break;

        case 2:
            test_ABEAE(pco_iut, pco_tst, iut_s, tst_s, epfd, streams_num);
        break;

        case 3:
            test_ABEBE(pco_iut, pco_tst, iut_s, tst_s, epfd, streams_num);
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

    if (iut_s != NULL)
        free(iut_s);
    if (tst_s != NULL)
        free(tst_s);

    TEST_END;
}
