/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/** @page extension-oo_epoll onload_ordered_epoll_wait() main functionality
 *
 * @objective Check that onload_ordered_epoll_wait() allows to
 *            retrieve data from multiple sockets in the order
 *            in which it was received from network.
 *
 * @param env                   Testing environment:
 *                              - @ref arg_types_env_peer2peer
 * @param sock_type             Type of sockets used in the test:
 *                              - @c tcp: all sockets are TCP;
 *                              - @c udp: all sockets are UDP;
 *                              - @c both: TCP and UDP sockets are added
 *                                         to epoll set.
 * @param streams_num           Number of sockets to use for sending
 *                              and receiving data
 * @param stream_packets_num    Number of packets to send from every
 *                              Tester socket (on average)
 * @param buf_size_min          Minimum size of data passed to @b send()
 *                              at once
 * @param buf_size_max          Maximum size of data passed to @b send()
 *                              at once
 *
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/oo_epoll"

#include "sockapi-test.h"

#include <stddef.h>

/** How many packets can be sent before reading. */
#define PACKETS_LIMIT 50

/** Size of buffer used to read data. */
#define BUF_SIZE 1024

/**
 * How long to wait after sending a big data chunk (or many packets)
 * to ensure that all the data is received, in ms.
 */
#define WAIT_AFTER_BIG_SEND 50

/** Default "grow factor" for te_dbuf. */
#define DBUF_DEF_GROW_FACTOR 50

/** Socket types in epoll set */
enum {
    SOCK_TYPE_TCP,    /**< All sockets are TCP */
    SOCK_TYPE_UDP,    /**< All sockets are UDP */
    SOCK_TYPE_BOTH,   /**< Both TCP and UDP sockets are present */
};

/** List of socket types to be used with TEST_GET_ENUM_PARAM() */
#define SOCK_TYPES \
    { "tcp", SOCK_TYPE_TCP },       \
    { "udp", SOCK_TYPE_UDP },       \
    { "both", SOCK_TYPE_BOTH }

/** Structure describing a single connection */
typedef struct sock_conn {
    int tst_s;              /**< Tester socket */
    int iut_s;              /**< IUT socket */
    int events;             /**< Events with which IUT socket was added
                                 to the epoll set */

    te_bool iut_writable;   /**< Whether IUT socket should be writable */
    te_bool out_reported;   /**< Whether EPOLLOUT event was reported by
                                 the last onload_ordered_epoll_wait()
                                 call */
    te_dbuf data;           /**< Buffer for storing data which was sent
                                 to an IUT socket not added to the epoll
                                 set with EPOLLIN event */
} sock_conn;

/**
 * Structure describing a single data chunk to be reported
 * by onload_ordered_epoll_wait().
 */
typedef struct sock_data {
    TAILQ_ENTRY(sock_data)    links;    /**< Queue links */

    int iut_s;                          /**< IUT socket FD */
    te_dbuf data;                       /**< Data to be reported */
} sock_data;

/**
 * Head of the queue of data chunks to be reported by
 * onload_ordered_epoll_wait().
 */
typedef TAILQ_HEAD(sock_data_queue, sock_data) sock_data_queue;

/**
 * Release resources allocated for the queue of data chunks.
 *
 * @param queue   Pointer to the queue head.
 */
static void
free_data_queue(sock_data_queue *queue)
{
    sock_data *data;
    sock_data *data_aux;

    TAILQ_FOREACH_SAFE(data, queue, links, data_aux)
    {
        TAILQ_REMOVE(queue, data, links);
        te_dbuf_free(&data->data);
        free(data);
    }
}

/**
 * Find sock_conn structure by IUT socket FD.
 *
 * @param conns       Array of sock_conn structures.
 * @param num         Number of elements in the array.
 * @param iut_s       IUT socket FD.
 *
 * @return Pointer to matching sock_conn structure or NULL if not found.
 */
static sock_conn *
get_conn_by_iut_s(sock_conn *conns, int num, int iut_s)
{
    int i;

    for (i = 0; i < num; i++)
    {
        if (conns[i].iut_s == iut_s)
            return &conns[i];
    }

    return NULL;
}

/**
 * Receive all data sent to IUT sockets from Tester. Firstly receive
 * data reported by onload_ordered_epoll_wait() and check that it is
 * reported in the same order in which it was sent. Also check that
 * EPOLLOUT events are reported when expected.
 *
 * @param pco_iut         RPC server on IUT.
 * @param epfd            Epoll FD.
 * @param streams_num     Number of connections.
 * @param conns           Array of connection structures.
 * @param data_queue      Queue of data chunks which should be reported
 *                        in the same order by onload_ordered_epoll_wait().
 * @param send_log_buf    String with log of all sending operations
 *                        since the previous receiving, will be
 *                        printed out in case of failure. Reset
 *                        on return.
 */
static void
receive_data(rcf_rpc_server *pco_iut, int epfd, int streams_num,
             sock_conn *conns, sock_data_queue *data_queue,
             te_string *send_log_buf)
{
#define REPORT_ERROR(_format...) \
    do {                                            \
        ERROR_VERDICT(_format);                     \
        RING("Sending log for the last bunch:\n%s", \
             send_log_buf->ptr);                    \
        failed = TRUE;                              \
        goto cleanup;                               \
    } while (0)

    rpc_onload_ordered_epoll_event *oo_events = NULL;
    struct rpc_epoll_event         *events = NULL;
    struct rpc_epoll_event         *events_aux = NULL;

    int       evts_num;
    int       evts_num_aux;
    int       i;
    ssize_t   remained;

    struct timespec *ts = NULL;
    static struct timespec ts_prev = { 0, 0 };
    static te_bool first_ts = TRUE;

    sock_data *data;
    sock_data *data_aux;
    int iut_s;
    sock_conn *conn;
    te_dbuf dbuf_aux = TE_DBUF_INIT(DBUF_DEF_GROW_FACTOR);
    te_bool no_epollin_evts = FALSE;
    te_bool all_out_reported = TRUE;

    te_bool failed = FALSE;

    oo_events = tapi_calloc(streams_num, sizeof(*oo_events));
    events = tapi_calloc(streams_num, sizeof(*events));
    events_aux = tapi_calloc(streams_num, sizeof(*events_aux));

    /*
     * Make sure that all data is ready - onload_ordered_epoll_wait()
     * will return immediately in presence of EPOLLOUT events.
     */
    MSLEEP(WAIT_AFTER_BIG_SEND);

    while (!no_epollin_evts)
    {
        for (i = 0; i < streams_num; i++)
        {
            conns[i].out_reported = FALSE;
        }

        evts_num = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events,
                                                 oo_events, streams_num,
                                                 TAPI_WAIT_NETWORK_DELAY);
        if (evts_num == 0)
            break;

        no_epollin_evts = TRUE;
        data = TAILQ_FIRST(data_queue);
        for (i = 0; i < evts_num; i++)
        {
            iut_s = events[i].data.fd;
            conn = get_conn_by_iut_s(conns, streams_num, iut_s);

            if (conn == NULL)
                REPORT_ERROR("Event for unknown socket was reported");

            if (events[i].events & RPC_EPOLLOUT)
            {
                if (~conn->events & RPC_EPOLLOUT)
                {
                    ERROR("EPOLLOUT event is reported unexpectedly for "
                          "socket %d", conn->iut_s);
                    REPORT_ERROR("EPOLLOUT event was reported for a "
                                 "socket which was not added to the "
                                 "epoll set with this event");
                }
                else if (!conn->iut_writable)
                {
                    ERROR("EPOLLOUT event is reported unexpectedly for "
                          "non-writable socket %d", conn->iut_s);

                    REPORT_ERROR("EPOLLOUT event was reported for a "
                                 "socket which should not be writable");
                }

                if (conn->out_reported)
                {
                    REPORT_ERROR("EPOLLOUT event is reported twice for "
                                 "the same socket");
                }
                conn->out_reported = TRUE;
            }
            else
            {
                if ((conn->events & RPC_EPOLLOUT) && conn->iut_writable)
                {
                    ERROR("EPOLLOUT event was not reported "
                          "unexpectedly for socket %d", conn->iut_s);

                    REPORT_ERROR("EPOLLOUT event was not reported "
                                 "unexpectedly");
                }
            }

            if (!(events[i].events & RPC_EPOLLIN))
                continue;

            no_epollin_evts = FALSE;

            if (data == NULL)
            {
                REPORT_ERROR("More EPOLLIN events than expected "
                             "are reported");
            }

            remained = oo_events[i].bytes;

            if (remained == 0)
                REPORT_ERROR("An event with bytes=0 was reported");

            if (iut_s != data->iut_s)
            {
                ERROR("Data for socket %d is expected firstly, "
                      "however EPOLLIN for %d is reported instead",
                      data->iut_s, iut_s);

                if (~conn->events & RPC_EPOLLIN)
                {
                    REPORT_ERROR("EPOLLIN event reported for a socket "
                                 "which was not added to the epoll set "
                                 "with EPOLLIN");
                }
                else
                {
                    REPORT_ERROR("EPOLLIN event for a socket is reported "
                                 "out of order");
                }
            }

            if (remained != (int)(data->data.len))
            {
                ERROR("%d bytes is expected for socket %d in the current "
                      "event, but %d bytes are reported instead",
                      (int)(data->data.len), iut_s, (int)remained);

                REPORT_ERROR("Incorrect number of bytes is reported "
                             "for a readable socket");
            }

            pco_iut->silent_pass = TRUE;
            rpc_read_fd2te_dbuf_append(pco_iut, iut_s, 0, data->data.len,
                                       &dbuf_aux);
            if (dbuf_aux.len < data->data.len)
            {
                ERROR("%u bytes instead of %u was read from socket %d",
                      (unsigned int)(dbuf_aux.len),
                      (unsigned int)(data->data.len),
                      iut_s);
                REPORT_ERROR("Failed to read all the bytes specified "
                             "in an event");
            }
            else if (memcmp(dbuf_aux.ptr, data->data.ptr,
                            data->data.len) != 0)
            {
                ERROR("Data received on socket %d does not match sent "
                      "data", iut_s);
                REPORT_ERROR("Data received on a socket does not match "
                             "data sent to it");
            }
            te_dbuf_reset(&dbuf_aux);

            data_aux = TAILQ_NEXT(data, links);
            TAILQ_REMOVE(data_queue, data, links);
            te_dbuf_free(&data->data);
            free(data);
            data = data_aux;

            ts = &oo_events[i].ts;

            if (ts->tv_sec == 0 && ts->tv_nsec == 0)
            {
                REPORT_ERROR("onload_ordered_epoll_wait() reported "
                             "zero timestamp");
            }

            if (!first_ts && (ts_prev.tv_sec > ts->tv_sec ||
                 (ts_prev.tv_sec == ts->tv_sec &&
                  ts_prev.tv_nsec > ts->tv_nsec)))
            {
                REPORT_ERROR("Previous event has bigger timestamp");
            }

            memcpy(&ts_prev, ts, sizeof(ts_prev));
            first_ts = FALSE;
        }

    }

    /*
     * Check that all the expected EPOLLOUT events are reported
     * by the last onload_ordered_epoll_wait() call (i.e. when
     * reporting EPOLLIN events in order does not interfere).
     */
    all_out_reported = TRUE;
    for (i = 0; i < streams_num; i++)
    {
        if (!conns[i].out_reported &&
            (conns[i].events & RPC_EPOLLOUT) &&
            conns[i].iut_writable)
        {
            all_out_reported = FALSE;
            ERROR("EPOLLOUT event was not reported unexpectedly for "
                  "socket %d", conns[i].iut_s);
        }
    }
    if (!all_out_reported)
    {
        REPORT_ERROR("EPOLLOUT event was not reported "
                     "unexpectedly");
    }

    if (!TAILQ_EMPTY(data_queue))
    {
        REPORT_ERROR("Not all the expected data was reported by "
                     "onload_ordered_epoll_wait()");
    }

    evts_num_aux = rpc_epoll_wait(pco_iut, epfd, events_aux,
                                  streams_num, 0);
    if (evts_num_aux != evts_num ||
        memcmp(events, events_aux, sizeof(*events) * evts_num) != 0)
    {
        REPORT_ERROR("epoll_wait() reports different events than the "
                     "last call of onload_ordered_epoll_wait()");
    }

    /*
     * Read data from sockets which were not added to the epoll set
     * with EPOLLIN event.
     */
    for (i = 0; i < streams_num; i++)
    {
        if (conns[i].data.len > 0)
        {
            pco_iut->silent_pass = TRUE;
            rpc_read_fd2te_dbuf_append(pco_iut, conns[i].iut_s,
                                       0, 0, &dbuf_aux);
            if (dbuf_aux.len != conns[i].data.len ||
                memcmp(dbuf_aux.ptr, conns[i].data.ptr,
                       dbuf_aux.len) != 0)
            {
                ERROR("%u bytes received on socket %d do not match "
                      "sent data", (unsigned int)(dbuf_aux.len),
                      conns[i].iut_s);
                REPORT_ERROR("Data received on a socket not added "
                             "to epoll set with EPOLLIN does not "
                             "match data sent from peer");
            }

            te_dbuf_reset(&dbuf_aux);
            te_dbuf_reset(&conns[i].data);
        }
    }

cleanup:

    te_dbuf_free(&dbuf_aux);
    te_string_reset(send_log_buf);
    free(oo_events);
    free(events);
    free(events_aux);
    if (failed)
        TEST_STOP;
#undef REPORT_ERROR
}

/**
 * Send a random sequence of bytes via multiple sockets on Tester, read
 * and reassemble it from multiple sockets on IUT with help of
 * onload_ordered_epoll_wait().
 *
 * @param pco_iut               RPC server on IUT.
 * @param pco_tst               RPC server on Tester.
 * @param conns                 Connections over which to send and receive
 *                              data.
 * @param streams_num           Number of connections.
 * @param data_queue            Queue to which to append sent data.
 * @param epfd                  Epoll file descriptor.
 * @param pkts_per_stream       How many packets should be sent from a
 *                              single Tester socket (on average).
 * @param min_size              Minimum size of data passed to send() at
 *                              once.
 * @param max_size              Maximum size of data passed to send() at
 *                              once.
 */
static void
data_transmission_loop(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                       sock_conn *conns, int streams_num,
                       sock_data_queue *data_queue,
                       int epfd, int pkts_per_stream,
                       int min_size, int max_size)
{
    sock_data *data;
    te_string log_buf = TE_STRING_INIT;

    size_t    sent_len = 0;
    int       pkts = 0;
    char     *buf = NULL;
    int       pkt_size;
    int       exp_bytes;
    size_t   *sent_bytes = NULL;
    int       i;
    int       j;
    ssize_t   rc;
    int       rcvbuf_val = 0;

    int prev_in_conn = -1;
    te_bool prev_out_only = FALSE;

    buf = TE_ALLOC(max_size);
    sent_bytes = TE_ALLOC(sizeof(*sent_bytes) * streams_num);
    if (buf == NULL || sent_bytes == NULL)
        TEST_FAIL("Out of memory");

    rpc_getsockopt(pco_iut, conns[0].iut_s, RPC_SO_RCVBUF, &rcvbuf_val);

    for (i = 0; i < streams_num * pkts_per_stream; i++)
    {
        pkt_size = rand_range(min_size, max_size);
        te_fill_buf(buf, pkt_size);

        if (prev_out_only && prev_in_conn >= 0 &&
            rand_range(1, 2) == 1)
        {
            /*
             * This is done to increase probability of
             * checking the scenario described in ST-2241.
             */
            j = prev_in_conn;
        }
        else
        {
            j = rand_range(0, streams_num - 1);
        }

        if ((conns[j].events & RPC_EPOLLOUT) && !conns[j].iut_writable)
        {
            if (rand_range(1, MAX(pkts_per_stream / 2, 1)) == 1)
            {
                te_string_append(&log_buf, "Make IUT socket %d writable\n",
                                 conns[j].iut_s);
                RPC_AWAIT_ERROR(pco_tst);
                pco_tst->silent_pass = TRUE;
                rc = rpc_drain_fd(pco_tst, conns[j].tst_s, max_size,
                                  TAPI_WAIT_NETWORK_DELAY, NULL);
                if (rc < 0 && RPC_ERRNO(pco_tst) != RPC_EAGAIN)
                {
                    RING("%s", log_buf.ptr);
                    te_string_free(&log_buf);
                    TEST_VERDICT("Failed to read all the data on Tester "
                                 "when making IUT socket writable, "
                                 "error " RPC_ERROR_FMT,
                                 RPC_ERROR_ARGS(pco_tst));
                }
                i--;
                conns[j].iut_writable = TRUE;
                continue;
            }
        }

        pco_tst->silent_pass = TRUE;
        RPC_SEND(rc, pco_tst, conns[j].tst_s, buf, pkt_size, 0);
        if (pkt_size > SOCKTS_MSG_STREAM_MAX)
        {
            /* Using usleep() to avoid extra logging */
            (void)usleep(TE_MS2US(WAIT_AFTER_BIG_SEND));
        }

        sent_bytes[j] += pkt_size;
        sent_len += pkt_size;
        pkts++;

        if (conns[j].events & RPC_EPOLLIN)
        {
            data = TAILQ_LAST(data_queue, sock_data_queue);
            if (data == NULL || data->iut_s != conns[j].iut_s)
            {
                data = tapi_calloc(1, sizeof(*data));
                data->data = (te_dbuf)TE_DBUF_INIT(DBUF_DEF_GROW_FACTOR);
                data->iut_s = conns[j].iut_s;
                TAILQ_INSERT_TAIL(data_queue, data, links);
            }

            CHECK_RC(te_dbuf_append(&data->data, buf, pkt_size));
            exp_bytes = data->data.len;
        }
        else
        {
            CHECK_RC(te_dbuf_append(&conns[j].data, buf, pkt_size));
            exp_bytes = 0;
        }

        te_string_append(
              &log_buf,
              "%d bytes were sent to IUT socket %d, %d bytes should "
              "be reported in the related event now\n",
              pkt_size, conns[j].iut_s, exp_bytes);

        if (i % PACKETS_LIMIT == PACKETS_LIMIT - 1 ||
            sent_bytes[j] > (size_t)rcvbuf_val / 2)
        {
            RING("Sent %lu bytes in %d packets, receiving",
                 (long unsigned)sent_len, pkts);
            receive_data(pco_iut, epfd, streams_num, conns, data_queue,
                         &log_buf);
            sent_len = 0;
            pkts = 0;
            memset(sent_bytes, 0, sizeof(*sent_bytes) * streams_num);
        }

        if (~conns[j].events & RPC_EPOLLIN)
        {
            prev_out_only = TRUE;
        }
        else
        {
            prev_out_only = FALSE;
            prev_in_conn = j;
        }
    }

    if (sent_len > 0)
    {
        RING("Sent %lu bytes in %d packets, receiving",
             (long unsigned)sent_len, pkts);
        receive_data(pco_iut, epfd, streams_num, conns, data_queue,
                     &log_buf);
    }

    free(buf);
    free(sent_bytes);
    te_string_free(&log_buf);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    int                    sock_type = -1;
    rpc_socket_type        stype = RPC_SOCK_UNKNOWN;

    struct sockaddr_storage iut_bind_addr;
    struct sockaddr_storage tst_bind_addr;

    int epfd = -1;
    int streams_num;
    int stream_packets_num;
    int i;
    int j;
    int buf_size_min;
    int buf_size_max;
    int tcp_sockets = 0;
    int udp_sockets = 0;

    sock_conn *conns = NULL;
    int *evts = NULL;
    int cur_event;

    sock_data_queue data_queue;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(sock_type, SOCK_TYPES);
    TEST_GET_INT_PARAM(streams_num);
    TEST_GET_INT_PARAM(stream_packets_num);
    TEST_GET_INT_PARAM(buf_size_min);
    TEST_GET_INT_PARAM(buf_size_max);

    TAILQ_INIT(&data_queue);

    /*
     * evts is an array of events variants with which sockets are
     * added to the epoll set. For every new socket a corresponding
     * member of this array will be chosen randomly.
     */
    evts = tapi_calloc(streams_num, sizeof(int));
    cur_event = RPC_EPOLLIN;
    for (i = 0; i < streams_num; i++)
    {
        if (i < MAX(streams_num / 2, 3))
        {
            /*
             * Make sure that a half (and at least 3) of
             * all the sockets are added to the epoll set
             * with EPOLLIN event.
             */
            evts[i] = RPC_EPOLLIN;
        }
        else
        {
            /*
             * Add at least one socket with EPOLLIN | EPOLLOUT
             * and at least one socket with EPOLLOUT, if number
             * of connections is big enough for this.
             */
            if (i == streams_num - 2 || rand_range(1, streams_num) == 1)
            {
                cur_event = RPC_EPOLLIN | RPC_EPOLLOUT;
            }
            else if (i == streams_num - 1 ||
                     rand_range(1, streams_num) == 1)
            {
                cur_event = RPC_EPOLLOUT;
            }
            evts[i] = cur_event;
        }
    }

    conns = tapi_calloc(streams_num, sizeof(*conns));
    for (i = 0; i < streams_num; i++)
    {
        conns[i].iut_s = -1;
        conns[i].tst_s = -1;
        conns[i].data = (te_dbuf)TE_DBUF_INIT(DBUF_DEF_GROW_FACTOR);
    }

    TEST_STEP("Create epoll descriptor.");
    epfd = rpc_epoll_create(pco_iut, streams_num);

    tapi_sockaddr_clone_exact(iut_addr, &iut_bind_addr);
    tapi_sockaddr_clone_exact(tst_addr, &tst_bind_addr);

    TEST_STEP("Create @p streams_num pairs of connected sockets on IUT and "
              "Tester. Add IUT sockets to epoll set with @c EPOLLIN, "
              "@c EPOLLIN | @c EPOLLOUT or @c EPOLLOUT events (chosen "
              "randomly for each socket). Choose randomly whether to "
              "overfill send buffers of some TCP sockets added with "
              "@c EPOLLOUT event to make them not writable for a while.");
    for (i = 0; i < streams_num; i++)
    {
        switch (sock_type)
        {
            case SOCK_TYPE_TCP:
                stype = RPC_SOCK_STREAM;
                break;

            case SOCK_TYPE_UDP:
                stype = RPC_SOCK_DGRAM;
                break;

            case SOCK_TYPE_BOTH:
                /*
                 * The first two conditions ensure that if all the
                 * previous sockets are of the same type by chance,
                 * then at least the last one will have different type.
                 */
                if (tcp_sockets == streams_num - 1)
                {
                    stype = RPC_SOCK_DGRAM;
                }
                else if (udp_sockets == streams_num - 1)
                {
                    stype = RPC_SOCK_STREAM;
                }
                else
                {
                    if (rand() % 2 == 0)
                        stype = RPC_SOCK_DGRAM;
                    else
                        stype = RPC_SOCK_STREAM;
                }

                if (stype == RPC_SOCK_DGRAM)
                    udp_sockets++;
                else
                    tcp_sockets++;

                break;
        }

        GEN_CONNECTION(pco_iut, pco_tst, stype, RPC_PROTO_DEF,
                       SA(&iut_bind_addr), SA(&tst_bind_addr),
                       &conns[i].iut_s, &conns[i].tst_s);

        if (stype == RPC_SOCK_STREAM)
            rpc_setsockopt_int(pco_tst, conns[i].tst_s, RPC_TCP_NODELAY, 1);

        conns[i].iut_writable = TRUE;
        do {
            j = rand_range(0, streams_num - 1);
            if (evts[j] != 0)
            {
                conns[i].events = evts[j];
                evts[j] = 0;
                break;
            }
        } while (TRUE);

        if ((conns[i].events & RPC_EPOLLOUT) && stype == RPC_SOCK_STREAM &&
            rand_range(1, 2) == 1)
        {
            RING("Make IUT socket %d not writable", conns[i].iut_s);
            rpc_overfill_buffers(pco_iut, conns[i].iut_s, NULL);
            conns[i].iut_writable = FALSE;
        }

        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                             conns[i].iut_s, conns[i].events);

        TAPI_SET_NEW_PORT(pco_iut, SA(&iut_bind_addr));
        TAPI_SET_NEW_PORT(pco_tst, SA(&tst_bind_addr));
    }

    TEST_STEP("Send from every Tester socket @p stream_packets_num (on "
              "average) data chunks, each chunk having size from "
              "@p buf_size_min to @p buf_size_max. For each new send() "
              "call choose Tester socket randomly, fill every data chunk "
              "with random data. On IUT call "
              "@b onload_ordered_epoll_wait(), check that it reports "
              "@c EPOLLIN events in correct order and with correct "
              "@b bytes field value, so that it is possible to read "
              "data in the same order in which it was sent.");
    TEST_SUBSTEP("Check also that @c EPOLLOUT events are reported "
                 "correctly and that they do not interfere with "
                 "reporting @c EPOLLIN events in the correct "
                 "order.");

    data_transmission_loop(pco_iut, pco_tst, conns, streams_num,
                           &data_queue, epfd, stream_packets_num,
                           buf_size_min, buf_size_max);

    TEST_SUCCESS;

cleanup:

    free_data_queue(&data_queue);

    if (conns != NULL)
    {
        for (i = 0; i < streams_num; i++)
        {
            CLEANUP_RPC_CLOSE(pco_iut, conns[i].iut_s);
            CLEANUP_RPC_CLOSE(pco_tst, conns[i].tst_s);
            te_dbuf_free(&conns[i].data);
        }
    }
    CLEANUP_RPC_CLOSE(pco_iut, epfd);

    free(conns);
    free(evts);

    TEST_END;
}
