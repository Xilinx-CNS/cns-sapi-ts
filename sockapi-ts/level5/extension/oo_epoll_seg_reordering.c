/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-oo_epoll_seg_reordering Onload ordered epoll with reordered data
 *
 * @objective Check that WODA handles reordered TCP data segments properly.
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TST
 * @param test_case  Send sequence of segments in dependence on this
 *                   parameter:
 * @n
 *                   @b lost_retransmit_one: A1 A3 B1 B2 A2 B3
 * @n
 *                   @b lost_retransmit_two: A1 A3 B2 B3 A2 B1
 * @n
 *                   @b lost_retransmit_three: A2 A3 B1 B2 A1 B3
 * @n
 *                   @b empty_event: A2 A3 B2 A1 B1 B3
 * @n
 *                   @b duplicate: A1 A3 B1 B2 A2 B3 A2
 * @n
 *                   @b lost: A1 B1 B2 B3 A3
 * @n
 *                   Where Ax - data segments on a one stream,
 *                         Bx - data segments on anoter stream.
 * 
 * @type Conformance.
 *
 * @par Scenario:
 * -# Create epoll socket @p epfd on IUT.
 * -# Repeat two times the following steps to create two flows:
 *   -# Create connected sockets pair on IUT and TST with test API macros
 *        @b GEN_CONNECTION.
 *   -# Add IUT socket to the epoll set with @p epfd.
 * -# Send data via the both tester sockets to IUT. Split sent buffers to
 *    segments and pass segments in defined order in dependence
 *    on @p test_case.
 * -# Call @b onload_ordered_epoll_wait and read data, check that returned
 *    info and data are equal to expected.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/oo_epoll_seg_reordering"

#include "sockapi-test.h"
#include "te_ethernet.h"
#include "tapi_tcp.h"
#include "tapi_route_gw.h"
#include "oo_epoll.h"

#define BUF_LEN 1000
#define EVENTS_MAX 10

typedef enum {
    TEST_CASE_LOST_1 = 0,
    TEST_CASE_LOST_2,
    TEST_CASE_LOST_3,
    TEST_CASE_EMPTY,
    TEST_CASE_DUPLICATE,
    TEST_CASE_LOST,
} test_case_t;

#define TEST_CASE \
    { "lost_retransmit_one", TEST_CASE_LOST_1 }, \
    { "lost_retransmit_two", TEST_CASE_LOST_2 }, \
    { "lost_retransmit_three", TEST_CASE_LOST_3 }, \
    { "empty_event", TEST_CASE_EMPTY }, \
    { "duplicate", TEST_CASE_DUPLICATE }, \
    { "lost", TEST_CASE_LOST }

/**
 * Data segment unit
 */
typedef struct data_segment {
    tapi_tcp_pos_t pos;     /**< Segment position */
    size_t         len;     /**< Segment length */
    size_t         offt;    /**< Buffer offset */
} data_segment;

/**
 * Check if a segment with the same position exists or not
 * 
 * @param new_seg   New segment position
 * @param seg_arr   Segments array
 * @param num       Segments number
 * 
 * @return @c TRUE if such segment exists
 */
static te_bool
segment_exists(tapi_tcp_pos_t new_seg, data_segment *seg_arr,
               tapi_tcp_pos_t num)
{
    tapi_tcp_pos_t i;

    for (i = 0; i < num; i++)
    {
        if (seg_arr[i].pos == new_seg)
            return TRUE;
    }

    return FALSE;
}

/**
 * Move the last segment to its position
 * 
 * @param seg   Segments array
 * @param num   Segments number
 */
static void
set_segment_pos(data_segment *seg, tapi_tcp_pos_t num)
{
    tapi_tcp_pos_t tmp;
    int i;

    for (i = num; i - 1 >= 0; i--)
    {
        if (seg[i].pos < seg[i - 1].pos)
        {
            tmp = seg[i].pos;
            seg[i].pos = seg[i - 1].pos;
            seg[i - 1].pos = tmp;
        }
        else
            break;
    }
}

/**
 * Fill segments array
 * 
 * @param tcp_conn  TCP connection handler
 * @param len       Buffer length to be splitted to segments
 * @param seg       Segments array
 * @param num       Segments number
 */
static void
get_segments_seqn(tapi_tcp_handler_t tcp_conn, size_t len,
                  data_segment *seg, int num)
{
    int i;

    seg[0].pos = tapi_tcp_next_seqn(tcp_conn);

    for (i = 1; i < num; i++)
    {
        do {
            seg[i].pos = rand_range(seg[0].pos, seg[0].pos + len - 1);
        } while (segment_exists(seg[i].pos, seg, i - 1));

        set_segment_pos(seg, i);
    }

    for (i = 0; i < num; i++)
    {
        if (i == num - 1)
            seg[i].len = len;
        else
            seg[i].len = seg[i + 1].pos - seg[i].pos;
        len -= seg[i].len;
        seg[i].offt = seg[i].pos - seg[0].pos;
        RING("segment #%d, position %lu, offt %u, length %u", i, seg[i].pos,
             seg[i].offt, seg[i].len);
    }
}

/**
 * Send a segment
 * 
 * @param _tcp_conn     TCP connection handler
 * @param _buf          Buffer, whose segment should be sent
 * @param _seg          Segment unit
 */
#define SEND_SEGMENT(_tcp_conn, _buf, _seg) \
    CHECK_RC(tapi_tcp_send_msg(_tcp_conn, _buf + (_seg).offt,           \
                               (_seg).len, TAPI_TCP_EXPLICIT,           \
                               (_seg).pos, TAPI_TCP_AUTO, 0, NULL, 0))

/**
 * Send the following sequence of segments and check ordered epoll beahvior:
 *     time    t1 t2 t3 t4 t5 t6  t7
 *     ------------------------------
 *     segment A1 A3 B1 B2 A2 B3 (A2)
 * 
 * @param pco_iut    IUT RPC server
 * @param iut_s_a    IUT socket for stream A
 * @param iut_s_b    IUT socket for stream B
 * @param tcp_conn1  TCP connection handler for stream A
 * @param tcp_conn2  TCP connection handler for stream B
 * @param epfd       Epoll fd
 * @param dup        Send duplicated packet (the second A2) if @c TRUE
 */
static void
test_A1A3B1B2A2B3(rcf_rpc_server *pco_iut, int iut_s_a, int iut_s_b,
                  tapi_tcp_handler_t tcp_conn1,
                  tapi_tcp_handler_t tcp_conn2, int epfd, te_bool dup)
{
    data_segment seg_a[3];
    data_segment seg_b[3];
    uint8_t      sendbuf1[BUF_LEN];
    uint8_t      recvbuf1[BUF_LEN];
    uint8_t      sendbuf2[BUF_LEN];
    uint8_t      recvbuf2[BUF_LEN];
    int          rc;

    struct rpc_epoll_event          events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event  oo_events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event *ev_a;
    rpc_onload_ordered_epoll_event *ev_b;

    if (!dup)
        RING("Testing the following segments sequence: A1 A3 B1 B2 A2 B3");
    else
        RING("Testing the following segments sequence: "
             "A1 A3 B1 B2 A2 B3 A2");

    get_segments_seqn(tcp_conn1, BUF_LEN, seg_a, 3);
    get_segments_seqn(tcp_conn2, BUF_LEN, seg_b, 3);

    te_fill_buf(sendbuf1, BUF_LEN);
    te_fill_buf(recvbuf1, BUF_LEN);
    te_fill_buf(sendbuf2, BUF_LEN);
    te_fill_buf(recvbuf2, BUF_LEN);

    if (!dup)
    {
        SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[0]);
        SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[2]);
        SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[0]);
        SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[1]);

        SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[1]);
        SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[2]);
    }
    else
    {
        SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[0]);
        SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[2]);
        SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[0]);
        SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[1]);

        SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[1]);
        SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[2]);
        SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[1]);
    }

    TAPI_WAIT_NETWORK;

    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       EVENTS_MAX, 0);
    if (rc != 2)
        TEST_VERDICT("It is expected to see two events but oo_epoll_wait "
                     "returned %d", rc);

    ev_a = oo_epoll_get_event_by_fd(iut_s_a, events, oo_events, rc);
    ev_b = oo_epoll_get_event_by_fd(iut_s_b, events, oo_events, rc);

    if ((unsigned)ev_a->bytes != seg_a[0].len)
        TEST_VERDICT("Wrong bytes number for the first stream");
    if ((unsigned)ev_b->bytes != seg_b[0].len + seg_b[1].len)
        TEST_VERDICT("Wrong bytes number for the second stream");
    if (oo_epoll_cmp_ts(ev_a, ev_b) >= 0)
        TEST_VERDICT("Timestamp of the first stream should be less than "
                     "the second");

    rc = rpc_recv(pco_iut, iut_s_a, recvbuf1, ev_a->bytes, 0);
    if (rc != ev_a->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "first stream", rc);

    rc = rpc_recv(pco_iut, iut_s_b, recvbuf2, ev_b->bytes, 0);
    if (rc != ev_b->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "second stream", rc);



    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       EVENTS_MAX, 0);
    if (rc != 2)
        TEST_VERDICT("It is expected to see two events but oo_epoll_wait "
                     "returned %d", rc);

    ev_a = oo_epoll_get_event_by_fd(iut_s_a, events, oo_events, rc);
    ev_b = oo_epoll_get_event_by_fd(iut_s_b, events, oo_events, rc);

    if ((unsigned)ev_a->bytes != seg_a[1].len + seg_a[2].len)
        TEST_VERDICT("Wrong bytes number for the first stream");
    if ((unsigned)ev_b->bytes != seg_b[2].len)
        TEST_VERDICT("Wrong bytes number for the second stream");
    if (oo_epoll_cmp_ts(ev_a, ev_b) >= 0)
        TEST_VERDICT("Timestamp of the first stream should be less than "
                     "the second");

    rc = rpc_recv(pco_iut, iut_s_a, recvbuf1 + seg_a[0].len,
                  ev_a->bytes, 0);
    if (rc != ev_a->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "first stream", rc);

    rc = rpc_recv(pco_iut, iut_s_b, recvbuf2 + seg_b[0].len + seg_b[1].len,
                  ev_b->bytes, 0);
    if (rc != ev_b->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "second stream", rc);

    if (memcmp(recvbuf1, sendbuf1, BUF_LEN) != 0)
        TEST_VERDICT("Received data is corrupted on the first tream");
    if (memcmp(recvbuf2, sendbuf2, BUF_LEN) != 0)
        TEST_VERDICT("Received data is corrupted on the second tream");
}

/**
 * Send the following sequence of segments and check ordered epoll beahvior:
 *     time    t1 t2 t3 t4 t5 t6
 *     -------------------------
 *     segment A1 A3 B2 B3 A2 B1
 * 
 * @param pco_iut    IUT RPC server
 * @param iut_s_a    IUT socket for stream A
 * @param iut_s_b    IUT socket for stream B
 * @param tcp_conn1  TCP connection handler for stream A
 * @param tcp_conn2  TCP connection handler for stream B
 * @param epfd       Epoll fd
 */
static void
test_A1A3B2B3A2B1(rcf_rpc_server *pco_iut, int iut_s_a, int iut_s_b,
                  tapi_tcp_handler_t tcp_conn1,
                  tapi_tcp_handler_t tcp_conn2, int epfd)
{
    data_segment seg_a[3];
    data_segment seg_b[3];
    uint8_t      sendbuf1[BUF_LEN];
    uint8_t      recvbuf1[BUF_LEN];
    uint8_t      sendbuf2[BUF_LEN];
    uint8_t      recvbuf2[BUF_LEN];
    int          rc;

    struct rpc_epoll_event          events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event  oo_events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event *ev_a;
    rpc_onload_ordered_epoll_event *ev_b;

    RING("Testing the following segments sequence: A1 A3 B2 B3 A2 B1 ");

    get_segments_seqn(tcp_conn1, BUF_LEN, seg_a, 3);
    get_segments_seqn(tcp_conn2, BUF_LEN, seg_b, 3);

    te_fill_buf(sendbuf1, BUF_LEN);
    te_fill_buf(recvbuf1, BUF_LEN);
    te_fill_buf(sendbuf2, BUF_LEN);
    te_fill_buf(recvbuf2, BUF_LEN);

    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[0]);
    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[2]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[1]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[2]);

    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[1]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[0]);

    TAPI_WAIT_NETWORK;

    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       EVENTS_MAX, 0);
    if (rc != 2)
        TEST_VERDICT("It is expected to see two events but oo_epoll_wait "
                     "returned %d", rc);

    ev_a = oo_epoll_get_event_by_fd(iut_s_a, events, oo_events, rc);
    ev_b = oo_epoll_get_event_by_fd(iut_s_b, events, oo_events, rc);

    if (ev_a->bytes != BUF_LEN)
        TEST_VERDICT("Wrong bytes number for the first stream");
    if (ev_b->bytes != BUF_LEN)
        TEST_VERDICT("Wrong bytes number for the second stream");
    if (oo_epoll_cmp_ts(ev_a, ev_b) >= 0)
        TEST_VERDICT("Timestamp of the first stream should be less than "
                     "the second");

    rc = rpc_recv(pco_iut, iut_s_a, recvbuf1, ev_a->bytes, 0);
    if (rc != ev_a->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "first stream", rc);

    rc = rpc_recv(pco_iut, iut_s_b, recvbuf2, ev_b->bytes, 0);
    if (rc != ev_b->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "second stream", rc);

    if (memcmp(recvbuf1, sendbuf1, BUF_LEN) != 0)
        TEST_VERDICT("Received data is corrupted on the first tream");
    if (memcmp(recvbuf2, sendbuf2, BUF_LEN) != 0)
        TEST_VERDICT("Received data is corrupted on the second tream");
}

/**
 * Send the following sequence of segments and check ordered epoll beahvior:
 *     time    t1 t2 t3 t4 t5 t6
 *     -------------------------
 *     segment A2 A3 B1 B2 A1 B3
 * 
 * @param pco_iut    IUT RPC server
 * @param iut_s_a    IUT socket for stream A
 * @param iut_s_b    IUT socket for stream B
 * @param tcp_conn1  TCP connection handler for stream A
 * @param tcp_conn2  TCP connection handler for stream B
 * @param epfd       Epoll fd
 */
static void
test_A2A3B1B2A1B3(rcf_rpc_server *pco_iut, int iut_s_a, int iut_s_b,
                  tapi_tcp_handler_t tcp_conn1,
                  tapi_tcp_handler_t tcp_conn2, int epfd)
{
    data_segment seg_a[3];
    data_segment seg_b[3];
    uint8_t      sendbuf1[BUF_LEN];
    uint8_t      recvbuf1[BUF_LEN];
    uint8_t      sendbuf2[BUF_LEN];
    uint8_t      recvbuf2[BUF_LEN];
    int          rc;

    struct rpc_epoll_event          events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event  oo_events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event *ev_a;
    rpc_onload_ordered_epoll_event *ev_b;

    RING("Testing the following segments sequence: A2 A3 B1 B2 A1 B3");

    get_segments_seqn(tcp_conn1, BUF_LEN, seg_a, 3);
    get_segments_seqn(tcp_conn2, BUF_LEN, seg_b, 3);

    te_fill_buf(sendbuf1, BUF_LEN);
    te_fill_buf(recvbuf1, BUF_LEN);
    te_fill_buf(sendbuf2, BUF_LEN);
    te_fill_buf(recvbuf2, BUF_LEN);

    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[1]);
    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[2]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[0]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[1]);

    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[0]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[2]);

    TAPI_WAIT_NETWORK;

    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       EVENTS_MAX, 0);
    if (rc != 2)
        TEST_VERDICT("It is expected to see two events but oo_epoll_wait "
                     "returned %d", rc);

    ev_a = oo_epoll_get_event_by_fd(iut_s_a, events, oo_events, rc);
    ev_b = oo_epoll_get_event_by_fd(iut_s_b, events, oo_events, rc);

    if (ev_a->bytes != BUF_LEN)
        TEST_VERDICT("Wrong bytes number for the first stream");
    if ((unsigned)ev_b->bytes != seg_b[0].len + seg_b[1].len)
        TEST_VERDICT("Wrong bytes number for the second stream");
    if (oo_epoll_cmp_ts(ev_a, ev_b) <= 0)
        TEST_VERDICT("Timestamp of the first stream should be greater than "
                     "the second");

    rc = rpc_recv(pco_iut, iut_s_a, recvbuf1, ev_a->bytes, 0);
    if (rc != ev_a->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "first stream", rc);

    rc = rpc_recv(pco_iut, iut_s_b, recvbuf2, ev_b->bytes, 0);
    if (rc != ev_b->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "second stream", rc);


    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       EVENTS_MAX, 0);
    if (rc != 1)
        TEST_VERDICT("It is expected to see one event but oo_epoll_wait "
                     "returned %d", rc);

    ev_b = oo_epoll_get_event_by_fd(iut_s_b, events, oo_events, rc);

    if (ev_b->bytes != (int)seg_b[2].len)
        TEST_VERDICT("Wrong bytes number for the second stream");

    rc = rpc_recv(pco_iut, iut_s_b, recvbuf2 + seg_b[0].len + seg_b[1].len,
                  ev_b->bytes, 0);
    if (rc != ev_b->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "second stream", rc);

    if (memcmp(recvbuf1, sendbuf1, BUF_LEN) != 0)
        TEST_VERDICT("Received data is corrupted on the first tream");
    if (memcmp(recvbuf2, sendbuf2, BUF_LEN) != 0)
        TEST_VERDICT("Received data is corrupted on the second tream");
}

/**
 * Send the following sequence of segments and check ordered epoll beahvior:
 *     time    t1 t2 t3 t4 t5 t6
 *     -------------------------
 *     segment A2 A3 B2 A1 B1 B3
 * 
 * @param pco_iut    IUT RPC server
 * @param iut_s_a    IUT socket for stream A
 * @param iut_s_b    IUT socket for stream B
 * @param tcp_conn1  TCP connection handler for stream A
 * @param tcp_conn2  TCP connection handler for stream B
 * @param epfd       Epoll fd
 */
static void
test_empty_event(rcf_rpc_server *pco_iut, int iut_s_a, int iut_s_b,
                 tapi_tcp_handler_t tcp_conn1,
                 tapi_tcp_handler_t tcp_conn2, int epfd)
{
    data_segment seg_a[3];
    data_segment seg_b[3];
    uint8_t      sendbuf1[BUF_LEN];
    uint8_t      recvbuf1[BUF_LEN];
    uint8_t      sendbuf2[BUF_LEN];
    uint8_t      recvbuf2[BUF_LEN];
    int          rc;

    struct rpc_epoll_event          events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event  oo_events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event *ev_a;
    rpc_onload_ordered_epoll_event *ev_b;

    RING("Testing the following segments sequence: A2 A3 B2 A1 B1 B3");

    get_segments_seqn(tcp_conn1, BUF_LEN, seg_a, 3);
    get_segments_seqn(tcp_conn2, BUF_LEN, seg_b, 3);

    te_fill_buf(sendbuf1, BUF_LEN);
    te_fill_buf(recvbuf1, BUF_LEN);
    te_fill_buf(sendbuf2, BUF_LEN);
    te_fill_buf(recvbuf2, BUF_LEN);

    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[1]);
    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[2]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[1]);

    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[0]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[0]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[2]);

    TAPI_WAIT_NETWORK;

    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       EVENTS_MAX, 0);
    if (rc != 2)
        TEST_VERDICT("It is expected to see two events but oo_epoll_wait "
                     "returned %d", rc);

    ev_a = oo_epoll_get_event_by_fd(iut_s_a, events, oo_events, rc);
    ev_b = oo_epoll_get_event_by_fd(iut_s_b, events, oo_events, rc);

    if (ev_a->bytes != BUF_LEN)
        TEST_VERDICT("Wrong bytes number for the first stream");
    if (ev_b->bytes != BUF_LEN)
        TEST_VERDICT("Wrong bytes number for the second stream");
    if (oo_epoll_cmp_ts(ev_a, ev_b) >= 0)
        TEST_VERDICT("Timestamp of the first stream should be less than "
                     "the second");

    rc = rpc_recv(pco_iut, iut_s_a, recvbuf1, ev_a->bytes, 0);
    if (rc != ev_a->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "first stream", rc);

    rc = rpc_recv(pco_iut, iut_s_b, recvbuf2, ev_b->bytes, 0);
    if (rc != ev_b->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "second stream", rc);

    if (memcmp(recvbuf1, sendbuf1, BUF_LEN) != 0)
        TEST_VERDICT("Received data is corrupted on the first tream");
    if (memcmp(recvbuf2, sendbuf2, BUF_LEN) != 0)
        TEST_VERDICT("Received data is corrupted on the second tream");
}

/**
 * Send the following sequence of segments and check ordered epoll beahvior:
 *     time    t1 t2 t3 t4 t5 t6
 *     -------------------------
 *     segment A1 B1 B2 B3 A3 <no A2>
 * 
 * @param pco_iut    IUT RPC server
 * @param iut_s_a    IUT socket for stream A
 * @param iut_s_b    IUT socket for stream B
 * @param tcp_conn1  TCP connection handler for stream A
 * @param tcp_conn2  TCP connection handler for stream B
 * @param epfd       Epoll fd
 */
static void
test_A1B1B2B3A3(rcf_rpc_server *pco_iut, int iut_s_a, int iut_s_b,
                tapi_tcp_handler_t tcp_conn1,
                tapi_tcp_handler_t tcp_conn2, int epfd)
{
    data_segment seg_a[3];
    data_segment seg_b[3];
    uint8_t      sendbuf1[BUF_LEN];
    uint8_t      recvbuf1[BUF_LEN];
    uint8_t      sendbuf2[BUF_LEN];
    uint8_t      recvbuf2[BUF_LEN];
    int          rc;

    struct rpc_epoll_event          events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event  oo_events[EVENTS_MAX];
    rpc_onload_ordered_epoll_event *ev_a;
    rpc_onload_ordered_epoll_event *ev_b;

    RING("Testing the following segments sequence: A1 B1 B2 B3 A3");

    get_segments_seqn(tcp_conn1, BUF_LEN, seg_a, 3);
    get_segments_seqn(tcp_conn2, BUF_LEN, seg_b, 3);

    te_fill_buf(sendbuf1, BUF_LEN);
    te_fill_buf(recvbuf1, BUF_LEN);
    te_fill_buf(sendbuf2, BUF_LEN);
    te_fill_buf(recvbuf2, BUF_LEN);

    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[0]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[0]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[1]);
    SEND_SEGMENT(tcp_conn2, sendbuf2, seg_b[2]);
    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[2]);

    TAPI_WAIT_NETWORK;

    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       EVENTS_MAX, 0);
    if (rc != 2)
        TEST_VERDICT("It is expected to see two events but oo_epoll_wait "
                     "returned %d", rc);

    ev_a = oo_epoll_get_event_by_fd(iut_s_a, events, oo_events, rc);
    ev_b = oo_epoll_get_event_by_fd(iut_s_b, events, oo_events, rc);

    if ((unsigned)ev_a->bytes != seg_a[0].len)
        TEST_VERDICT("Wrong bytes number for the first stream");
    if (ev_b->bytes != BUF_LEN)
        TEST_VERDICT("Wrong bytes number for the second stream");
    if (oo_epoll_cmp_ts(ev_a, ev_b) >= 0)
        TEST_VERDICT("Timestamp of the first stream should be less than "
                     "the second");

    rc = rpc_recv(pco_iut, iut_s_a, recvbuf1, ev_a->bytes, 0);
    if (rc != ev_a->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "first stream", rc);

    rc = rpc_recv(pco_iut, iut_s_b, recvbuf2, ev_b->bytes, 0);
    if (rc != ev_b->bytes)
        TEST_VERDICT("Received unexpected amount of data %d from the "
                     "second stream", rc);

    rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                       EVENTS_MAX, 0);
    if (rc != 0)
        TEST_VERDICT("It is expected to see no events but oo_epoll_wait "
                     "returned %d", rc);

    /* Pass the missed segment to avoid finalization problems. */
    SEND_SEGMENT(tcp_conn1, sendbuf1, seg_a[1]);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *tst_fake_addr = NULL;
    const struct sockaddr     *alien_link_addr = NULL;
    struct sockaddr            iut_mac;
    tapi_tcp_handler_t         tcp_conn1 = 0;
    tapi_tcp_handler_t         tcp_conn2 = 0;
    test_case_t                test_case;

    int iut_srv_s = -1;
    int iut_s_a = -1;
    int iut_s_b = -1;

    int epfd = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_ENUM_PARAM(test_case, TEST_CASE);

    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_fake_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    CFG_WAIT_CHANGES;

    epfd = rpc_epoll_create(pco_iut, EVENTS_MAX);

    iut_srv_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_STREAM, 
                           RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_srv_s, iut_addr);
    rpc_listen(pco_iut, iut_srv_s, SOCKTS_BACKLOG_DEF);

    CHECK_RC(tapi_cfg_base_if_get_link_addr(pco_iut->ta, iut_if->if_name,
                                            &iut_mac));

    CHECK_RC(tapi_tcp_init_connection(pco_tst->ta, TAPI_TCP_CLIENT,
                                      (struct sockaddr *)tst_fake_addr,
                                      (struct sockaddr *)iut_addr,
                                      tst_if->if_name,
                                      (const uint8_t *)alien_link_addr->sa_data,
                                      (uint8_t *)iut_mac.sa_data,
                                      0, &tcp_conn1));
    CHECK_RC(tapi_tcp_wait_open(tcp_conn1, 3000));
    iut_s_a = rpc_accept(pco_iut, iut_srv_s, NULL, NULL); 
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s_a,
                         RPC_EPOLLIN);

    TAPI_SET_NEW_PORT(pco_tst, tst_fake_addr);
    CHECK_RC(tapi_tcp_init_connection(pco_tst->ta, TAPI_TCP_CLIENT,
                                      (struct sockaddr *)tst_fake_addr,
                                      (struct sockaddr *)iut_addr,
                                      tst_if->if_name,
                                      (const uint8_t *)alien_link_addr->sa_data,
                                      (uint8_t *)iut_mac.sa_data,
                                      0, &tcp_conn2));
    CHECK_RC(tapi_tcp_wait_open(tcp_conn2, 3000));
    iut_s_b = rpc_accept(pco_iut, iut_srv_s, NULL, NULL);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s_b,
                         RPC_EPOLLIN);

    switch (test_case)
    {
        case TEST_CASE_LOST_1:
            test_A1A3B1B2A2B3(pco_iut, iut_s_a, iut_s_b, tcp_conn1,
                              tcp_conn2, epfd, FALSE);
            break;

        case TEST_CASE_LOST_2:
            test_A1A3B2B3A2B1(pco_iut, iut_s_a, iut_s_b, tcp_conn1,
                              tcp_conn2, epfd);
            break;

        case TEST_CASE_LOST_3:
            test_A2A3B1B2A1B3(pco_iut, iut_s_a, iut_s_b, tcp_conn1,
                              tcp_conn2, epfd);
            break;

        case TEST_CASE_EMPTY:
            test_empty_event(pco_iut, iut_s_a, iut_s_b, tcp_conn1,
                             tcp_conn2, epfd);
            break;

        case TEST_CASE_DUPLICATE:
            test_A1A3B1B2A2B3(pco_iut, iut_s_a, iut_s_b, tcp_conn1,
                              tcp_conn2, epfd, TRUE);
            break;

        case TEST_CASE_LOST:
            test_A1B1B2B3A3(pco_iut, iut_s_a, iut_s_b, tcp_conn1,
                            tcp_conn2, epfd);
            break;

        default:
            TEST_VERDICT("Unknown test case %d", test_case);
    }

    tapi_tcp_update_sent_seq(tcp_conn1, BUF_LEN);
    tapi_tcp_update_sent_seq(tcp_conn2, BUF_LEN);

    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_DEL, iut_s_a,
                         RPC_EPOLLIN);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_DEL, iut_s_b,
                         RPC_EPOLLIN);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_srv_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_a);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_b);

    if (tcp_conn1 != 0)
    {
        CLEANUP_CHECK_RC(tapi_tcp_send_ack(tcp_conn1,
                                           tapi_tcp_next_ackn(tcp_conn1)));
        CLEANUP_CHECK_RC(tapi_tcp_send_fin_ack(tcp_conn1, 2000));
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn1));
    }

    if (tcp_conn2 != 0)
    {
        CLEANUP_CHECK_RC(tapi_tcp_send_ack(tcp_conn2,
                                           tapi_tcp_next_ackn(tcp_conn2)));
        CLEANUP_CHECK_RC(tapi_tcp_send_fin_ack(tcp_conn2, 2000));
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn2));
    }

    if (pco_iut != NULL)
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_iut->ta, 
                                                    iut_if->if_name)); 

    CLEANUP_RPC_CLOSE(pco_iut, epfd);


    TEST_END;
}
