/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 */

/** @page epoll-small_maxevents Small maxevents and a lot of polled FDs
 *
 * @objective Check that when there is much more polled FDs than
 *            maxevents value, for every FD event is reported within
 *            reasonable time if @b epoll_wait() is called repeatedly and
 *            some events are processed.
 *
 * @type conformance
 *
 * @param env                   Testing environment:
 *                              - @ref arg_types_env_peer2peer
 *                              - @ref arg_types_env_peer2peer_ipv6
 * @param iomux                 Which iomux function to test:
 *                              - @b epoll_wait()
 *                              - @b epoll_pwait()
 *                              - @b epoll_pwait2()
 * @param maxevents             Value of maxevents parameter:
 *                              - @c 3
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/small_maxevents"

#include "sockapi-test.h"
#include "onload.h"
#include "epoll_common.h"
#include "te_time.h"

/** Number of sockets on IUT is at least this times greater than maxevents */
#define MIN_CONNS_NUM_COEFF 10
/** Number of sockets on IUT is at most this times greater than maxevents */
#define MAX_CONNS_NUM_COEFF 20

/** Maximum length of sent packet */
#define MAX_PKT_LEN 1024

/** How long to call epoll_wait() in a loop, in microseconds */
#define RUN_TIME 5000000L

/**
 * Time within which an event should be reported for any socket,
 * in microseconds
 */
#define EVENT_TIMEOUT 1500000L

/** TCP or UDP connection */
typedef struct conn {
    int iut_s;  /**< IUT socket */
    int tst_s;  /**< Tester socket */

    struct timeval last_reported; /**< Last time event was seen for the
                                       socket */
    te_bool no_process; /**< If TRUE, do not process reported events */
    te_bool use_libc; /**< If TRUE, socket is system when Onload is
                           checked */

    rpc_socket_type sock_type; /** RPC_SOCK_STREAM or RPC_SOCK_DGRAM */
    char sent_data[MAX_PKT_LEN]; /** Data sent from peer the last time */
    int sent_len; /** Length of data sent from peer */
} conn;

/**
 * Set property to a new value for randomly chosen connection
 * structures in an array.
 *
 * @param conns       Array of connection structures.
 * @param conns_num   Number of structures in the array.
 * @param set_num     For how many connections to change a property.
 * @param f_set       Function that changes property value. It returns
 *                    TRUE if the property was changed successfully.
 */
static void
set_random_property(conn *conns, int conns_num, int set_num,
                    te_bool (*f_set)(conn *c))
{
    int i;
    while (set_num > 0)
    {
        i = rand_range(0, conns_num - 1);
        if (f_set(&conns[i]))
              set_num--;
    }
}

/** Function setting RPC_SOCK_STREAM as socket type */
static te_bool
set_sock_type_tcp(conn *c)
{
    if (c->sock_type == RPC_SOCK_STREAM)
        return FALSE;

    c->sock_type = RPC_SOCK_STREAM;
    return TRUE;
}

/** Function setting use_libc=TRUE */
static te_bool
set_use_libc(conn *c)
{
    if (c->use_libc)
        return FALSE;

    c->use_libc = TRUE;
    return TRUE;
}

/** Function setting no_process=TRUE */
static te_bool
set_no_process(conn *c)
{
    if (c->no_process)
        return FALSE;

    c->no_process = TRUE;
    return TRUE;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    struct sockaddr_storage iut_addr_bind;
    struct sockaddr_storage tst_addr_bind;

    iomux_call_type iomux;
    int epfd = -1;
    struct rpc_epoll_event event;
    struct rpc_epoll_event *evts = NULL;
    const char *iomux_name = NULL;

    conn *conns = NULL;
    conn *conn = NULL;
    int conns_num;
    int fd;

    int maxevents;
    int n_evts;

    int conn_id;
    int evt_id;

    char buf[MAX_PKT_LEN];

    struct timeval start_ts;
    struct timeval cur_ts;
    struct timeval min_ts;
    struct timeval *ts;
    long int wait_time = 0;
    long int max_wait_time = 0;

    te_string str_log = TE_STRING_INIT;
    te_string fds_str = TE_STRING_INIT;
    te_string proc_str = TE_STRING_INIT;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(maxevents);

    TEST_STEP("Choose @b conns_num to be multiple times greater than "
              "@p maxevents.");
    conns_num = rand_range(MIN_CONNS_NUM_COEFF * maxevents,
                           MAX_CONNS_NUM_COEFF * maxevents);
    RING("Chosen conns_num = %d", conns_num);

    evts = tapi_calloc(maxevents, sizeof(*evts));
    conns = tapi_calloc(conns_num, sizeof(*conns));

    for (conn_id = 0; conn_id < conns_num; conn_id++)
    {
        conns[conn_id].iut_s = -1;
        conns[conn_id].tst_s = -1;
        conns[conn_id].use_libc = FALSE;
        conns[conn_id].sock_type = RPC_SOCK_DGRAM;
    }

    set_random_property(conns, conns_num,
                        conns_num / 2,
                        set_sock_type_tcp);
    set_random_property(conns, conns_num,
                        conns_num / 2,
                        set_use_libc);
    set_random_property(conns, conns_num,
                        conns_num / 2,
                        set_no_process);

    iomux_name = sockts_iomux_call_en2str(iomux);

    TEST_STEP("Create epoll FD on IUT.");
    epfd = rpc_epoll_create(pco_iut, maxevents);

    TEST_STEP("Establish @b conns_num connections: some UDP, other TCP, "
              "some using accelerated sockets on IUT, others using system "
              "sockets on IUT. Add every connected IUT socket to the epoll "
              "set expecting @c EPOLLIN event.");
    for (conn_id = 0; conn_id < conns_num; conn_id++)
    {
        CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr,
                                     &iut_addr_bind));
        CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                     &tst_addr_bind));

        if (conns[conn_id].use_libc)
            pco_iut->use_libc = pco_iut->use_libc_once = TRUE;

        GEN_CONNECTION(pco_iut, pco_tst, conns[conn_id].sock_type,
                       RPC_PROTO_DEF,
                       SA(&iut_addr_bind), SA(&tst_addr_bind),
                       &conns[conn_id].iut_s, &conns[conn_id].tst_s);

        pco_iut->use_libc = pco_iut->use_libc_once = FALSE;

        event.events = RPC_EPOLLIN;
        event.data.fd = conns[conn_id].iut_s;
        rpc_epoll_ctl(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                      conns[conn_id].iut_s, &event);
    }

    TEST_STEP("Send some data from Tester to all IUT sockets.");
    for (conn_id = 0; conn_id < conns_num; conn_id++)
    {
        conns[conn_id].sent_len = rand_range(1, MAX_PKT_LEN);
        te_fill_buf(conns[conn_id].sent_data, conns[conn_id].sent_len);
        RPC_SEND(rc, pco_tst, conns[conn_id].tst_s,
                 conns[conn_id].sent_data, conns[conn_id].sent_len, 0);
    }

    CHECK_RC(te_gettimeofday(&start_ts, NULL));
    for (conn_id = 0; conn_id < conns_num; conn_id++)
    {
        memcpy(&conns[conn_id].last_reported, &start_ts,
               sizeof(start_ts));
    }

    TEST_STEP("In a loop call @p iomux a lot of times, each time expecting "
              "@p maxevents events from it. Process reported events by "
              "reading data for some IUT sockets, never read "
              "data for others. After reading data, send a new packet "
              "from Tester.");
    TEST_SUBSTEP("Check that for every socket @c EPOLLIN is reported "
                 "when it is readable (within reasonable time).");

    pco_iut->silent_pass = pco_iut->silent_pass_default = TRUE;
    pco_tst->silent_pass = pco_tst->silent_pass_default = TRUE;

    do {
        /*
         * Less than maxevents may be reported here if some packets from
         * Tester have not reached IUT yet.
         */
        RPC_AWAIT_ERROR(pco_iut);
        n_evts = iomux_epoll_call(iomux, pco_iut, epfd, evts, maxevents, 0);
        if (n_evts < 0)
        {
            TEST_VERDICT("%s() failed with error %r",
                         iomux_name, RPC_ERRNO(pco_iut));
        }
        else if (n_evts == 0)
        {
            TEST_VERDICT("%s() reported no events", iomux_name);
        }

        CHECK_RC(te_gettimeofday(&cur_ts, NULL));

        te_string_reset(&fds_str);
        te_string_reset(&proc_str);

        for (evt_id = 0; evt_id < n_evts; evt_id++)
        {
            fd = evts[evt_id].data.fd;
            conn = NULL;
            for (conn_id = 0; conn_id < conns_num; conn_id++)
            {
                if (conns[conn_id].iut_s == fd)
                {
                    conn = &conns[conn_id];
                    break;
                }
            }

            if (conn == NULL)
            {
                ERROR("Unknown FD %d in event data", fd);
                TEST_VERDICT("%s() returned unknown FD in event data",
                             iomux_name);
            }

            if (evts[evt_id].events != RPC_EPOLLIN)
            {
                ERROR("Unexpected events are reported for socket %d", fd);
                TEST_VERDICT("%s() reported unexpected events %s",
                             iomux_name,
                             epoll_event_rpc2str(evts[evt_id].events));
            }

            if (conn->use_libc)
                te_string_append(&fds_str, "%s", "libc.");

            te_string_append(&fds_str, "%d, ", fd);

            memcpy(&conn->last_reported, &cur_ts, sizeof(cur_ts));

            if (!conn->no_process)
            {
                rc = rpc_recv(pco_iut, conn->iut_s, buf, sizeof(buf), 0);
                if (rc != conn->sent_len ||
                    memcmp(conn->sent_data, buf, rc) != 0)
                {
                    TEST_VERDICT("Unexpected data was read on IUT");
                }

                conn->sent_len = rand_range(1, MAX_PKT_LEN);
                te_fill_buf(conn->sent_data, conn->sent_len);
                RPC_SEND(rc, pco_tst, conn->tst_s, conn->sent_data,
                         conn->sent_len, 0);

                if (conn->use_libc)
                    te_string_append(&proc_str, "%s", "libc.");

                te_string_append(&proc_str, "%d, ", fd);
            }
        }

        te_string_cut(&fds_str, 2);
        te_string_cut(&proc_str, 2);
        te_string_reset(&str_log);
        te_string_append(&str_log, "Events were reported for FDs %s",
                         fds_str.ptr);
        if (proc_str.len > 0)
        {
            te_string_append(&str_log, "; events were processed for FDs %s",
                             proc_str.ptr);
        }

        RING("%s", str_log.ptr);

        conn = NULL;
        memcpy(&min_ts, &cur_ts, sizeof(cur_ts));
        for (conn_id = 0; conn_id < conns_num; conn_id++)
        {
            ts = &conns[conn_id].last_reported;
            if (TIMEVAL_SUB(min_ts, *ts) > 0)
            {
                conn = &conns[conn_id];
                memcpy(&min_ts, ts, sizeof(min_ts));
            }
        }

        wait_time = TIMEVAL_SUB(cur_ts, min_ts);
        if (max_wait_time < wait_time)
            max_wait_time = wait_time;

        if (wait_time > EVENT_TIMEOUT)
        {
            ERROR("For IUT socket %s%d (%s) event is not "
                  "reported for too long: %ld us",
                  (conn->use_libc ? "libc." : ""),
                  conn->iut_s,
                  socktype_rpc2str(conn->sock_type),
                  wait_time);

            TEST_VERDICT("For one of the sockets event is not reported for "
                         "too long time");
        }

    } while (TIMEVAL_SUB(cur_ts, start_ts) < RUN_TIME);

    RING("Maximum time waiting for an event on a FD: %ld us",
         max_wait_time);

    pco_iut->silent_pass = pco_iut->silent_pass_default = FALSE;
    pco_tst->silent_pass = pco_tst->silent_pass_default = FALSE;

    TEST_STEP("Read and check all pending data on IUT sockets.");
    for (conn_id = 0; conn_id < conns_num; conn_id++)
    {
        rc = rpc_recv(pco_iut, conns[conn_id].iut_s, buf, sizeof(buf), 0);
        if (rc != conns[conn_id].sent_len ||
            memcmp(conns[conn_id].sent_data, buf, rc) != 0)
        {
            TEST_VERDICT("Unexpected data was read on IUT");
        }
    }

    TEST_SUCCESS;

cleanup:

    if (conns != NULL)
    {
        for (conn_id = 0; conn_id < conns_num; conn_id++)
        {
            CLEANUP_RPC_CLOSE(pco_iut, conns[conn_id].iut_s);
            CLEANUP_RPC_CLOSE(pco_tst, conns[conn_id].tst_s);
        }
    }

    CLEANUP_RPC_CLOSE(pco_iut, epfd);

    free(evts);
    free(conns);

    te_string_free(&str_log);
    te_string_free(&fds_str);
    te_string_free(&proc_str);

    TEST_END;
}
