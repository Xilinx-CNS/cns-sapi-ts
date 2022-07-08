/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocgstamp Usage of SIOCGSTAMP/SIOCGSTAMPNS request and SO_TIMESTAMP and SO_TIMESTAMPNS options
 *
 * @objective Check that @c SIOCGSTAMP, @c SIOCGSTAMPNS requests and
 *            @c SO_TIMESTAMP and @c SO_TIMESTAMPNS socket options return
 *            a @c timeval/@c timespec structure containing the time at
 *            which the datagram was received.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param use_so_timestamp Use @c SO_TIMESTAMP socket option to subtitute
 *                         @b ioctl() where possible
 * @param use_ns           Use @c SO_TIMESTAMPNS and @c SIOCGSTAMPNS
 *                         instead of  @c SO_TIMESTAMP and @c SIOCGSTAMP
 *                         respectively
 * 
 * @par Test sequence:
 * -# Create @p pco_iut socket of type @c SOCK_DGRAM on @p pco_iut.
 * -# Create @p pco_tst socket of type @c SOCK_DGRAM on @p pco_tst.
 * -# @b bind() @p pco_iut socket to a local address.
 * -# Create @p tx_buf buffer of size @p buf_len.
 * -# Create @p rx_buf buffer of size @p buf_len.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl() on @p pco_iut socket with @c SIOCGSTAMP request
 *    (there is no data on the socket).
 * -# Check that the function returns @c -1 and sets @b errno to @c ENOENT.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b poll() on @p pco_iut waiting for @p pco_iut socket becomes 
 *    "readable".
 * -# Get current time @p low_time on @p pco_tst.
 * -# @b sendto() @p tx_buf from @p pco_tst socket to @p pco_iut socket.
 * -# Wait for @b poll() completion.
 * -# Get current time @p high_time on @p pco_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl() on @p pco_iut socket with @c SIOCGSTAMP request
 *    (there is some data on the socket).
 * -# Log a result of the function and @b errno.
 *    See @ref ioctls_siocgstamp_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# According to @p use_so_timestamp parameter do:
 *      - if @c TRUE:
 *          - Call @b recv(@p pco_iut, @p rx_buf, @p buf_len, @c 0);
 *          - Check that the content of @p tx_buf and @p rx_buf are the
 *            same;
 *          - Call @b ioctl() on @p pco_iut socket with @c SIOCGSTAMP
 *            request to get arriving timestamp @p ts of the datagram;
 *      - if @c FALSE
 *          - Call @b recvmsg() to get time stamp;
 * -# Check that @p ts in range (@p low_time, @p high_time).
 * -# Call @b ioctl() on @p pco_iut socket with @c SIOCGSTAMP request.
 * -# Check obtained result according to @p use_so_timestamp.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Perform the following steps @p N times:
 *        - Get current time @p low_time{i} on @p pco_iut;
 *        - @b sendto() @p tx_buf from @p pco_tst socket to @p pco_iut socket;
 *        - Get current time @p high_time{i} on @p pco_iut;
 *        - Sleep for @p delay{i} time interval.
 *        .
 * -# Perform the following steps @p N times:
 *        - Get time stamp using @b ioctl() or @b recvmsg() according to
 *          @p use_so_timestamp;
 *        - Check that @p ts in range [@p low_time{i}, @p high_time{i}];
 *        - If @p use_so_timestamp is @c TRUE call @b ioctl() on @p pco_iut
 *          socket with @c SIOCGSTAMP request;
 *        - If @p use_so_timestamp is @c TRUE check that obtained value is
 *          the same as @p ts.
 *          \n @htmlonly &nbsp; @endhtmlonly
 *        .
 * -# Delete @p tx_buf and @p rx_buf buffers.
 * -# Close @p pco_iut and @p pco_tst sockets.
 * 
 * @note
 * -# @anchor ioctls_siocgstamp_1
 *    It is not obvious what should be returned, Linux returns @c ENOENT,
 *    but actually it is not specified and on the other systems it can set
*     @b errno to something different, so just report the result.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocgstamp"

#include "sockapi-test.h"

/* Precision of timestamp, in usec (1sec). */
#define TIMEVAL_ACCURACY 2000000L

#define TST_CMSG_LEN      300

#define SEND_RECV_TIME(low_time_, high_time_) \
    do {                                                                \
        rpc_gettimeofday(pco_iut, &(low_time_), NULL);                  \
        pco_iut->op = RCF_RPC_CALL;                                     \
        memset(&revent, 0, sizeof(revent));                             \
        rpc_epoll_wait(pco_iut, epfd, &revent, 1, -1);                  \
        RPC_SENDTO(rc, pco_tst, tst_s, tx_buf, buf_len, 0, iut_addr);   \
        pco_iut->op = RCF_RPC_WAIT;                                     \
        rc = rpc_epoll_wait(pco_iut, epfd, &revent, 1, -1);             \
        if (rc != 1 || revent.events != RPC_EPOLLIN)                    \
            TEST_FAIL("Incorrect result of epoll_wait() call");         \
        rpc_gettimeofday(pco_iut, &(high_time_), NULL);                 \
    } while (0)

#define CHECK_TIME(ts_, low_time_, high_time_, str_, check_ioctl_) \
    do {                                                                \
        low_diff = TIMEVAL_SUB((ts_), (low_time_));                     \
        high_diff = TIMEVAL_SUB((high_time_), (ts_));                   \
        if (low_diff < 0 || high_diff < 0)                              \
        {                                                               \
            RING("Low   : %d s %d ms\n"                                 \
                 "Hight : %d s %d ms\n"                                 \
                 "Got   : %d s %d ms",                                  \
                  (int)(low_time_).tv_sec, (int)(low_time_).tv_usec,    \
                  (int)(high_time_).tv_sec, (int)(high_time_).tv_usec,  \
                  (int)(ts_).tv_sec, (int)(ts_).tv_usec);               \
            if (low_diff < -TIMEVAL_ACCURACY ||                         \
                high_diff < -TIMEVAL_ACCURACY)                          \
                TEST_FAIL("Returned timestamp is incorrect");           \
            RING_VERDICT("%s%s precision is too low",                   \
                         (check_ioctl_) ?                               \
                            ioctl_rpc2str(ioctl_req) :                  \
                            sockopt_rpc2str(sock_opt),                  \
                         (str_));                                       \
        }                                                               \
    } while (0)

#define TS_TO_MS \
    do {                                                            \
        if (use_ns)                                                 \
        {                                                           \
            tmp_ts.tv_sec =                                         \
                ((struct tarpc_timespec *)ts)->tv_sec;              \
            tmp_ts.tv_usec =                                        \
                ((struct tarpc_timespec *)ts)->tv_nsec / 1000;      \
        }                                                           \
        else                                                        \
            memcpy(&tmp_ts, ts, time_size);                         \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr *iut_addr;
    void                  *tx_buf = NULL;
    void                  *rx_buf = NULL;
    size_t                 buf_len;

    uint8_t                *ts = NULL;
    struct tarpc_timeval    tmp_ts = { 0, 0 };
    uint8_t                *ts_bkp = NULL;
    uint8_t                *ts2 = NULL;

    struct tarpc_timeval    low_time_aux = { 0, 0 };
    struct tarpc_timeval    high_time_aux = { 0, 0 };
    struct tarpc_timeval    low_time = { 0, 0 };
    struct tarpc_timeval    high_time = { 0, 0 };

    long low_diff, high_diff;

    struct test_substep {
        unsigned int   delay;           /**< Delay to sleep between
                                             sending datagrams */
        struct tarpc_timeval low_time;  /**< Low boundary for timestamp 
                                             obtaind with ioctl() */
        struct tarpc_timeval high_time; /**< Upper boundary for timestamp
                                             obtaind with ioctl() */
    } test_cb [] = {
        {1, { 0, 0 }, { 0, 0 }},
        {2, { 0, 0 }, { 0, 0 }},
        {4, { 0, 0 }, { 0, 0 }},
        {5, { 0, 0 }, { 0, 0 }},
        {2, { 0, 0 }, { 0, 0 }},
        {1, { 0, 0 }, { 0, 0 }},
    };
    unsigned int i;

    rpc_socket_domain domain;

    te_bool          use_so_timestamp;
    te_bool          use_ns;
    int              on = 1;
    struct rpc_iovec vector;
    uint8_t          cmsg_buf[TST_CMSG_LEN];
    struct cmsghdr  *cmsg;
    rpc_msghdr       msg;
    rpc_msg_read_f   func;

    int             opt_data_len;
    unsigned char  *ptr;

    int             ioctl_req;
    int             sock_opt;
    int             time_size;
    te_bool         get_ioctl_after_sockopt = FALSE;
    te_bool         recv_before_sockopt = FALSE;

    struct rpc_epoll_event      event;
    struct rpc_epoll_event      revent;
    int                         epfd;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(use_so_timestamp);
    TEST_GET_BOOL_PARAM(use_ns);
    TEST_GET_BOOL_PARAM(get_ioctl_after_sockopt);
    TEST_GET_BOOL_PARAM(recv_before_sockopt);
    TEST_GET_MSG_READ_FUNC(func);

    if (use_ns)
    {
        ioctl_req = RPC_SIOCGSTAMPNS;
        sock_opt = RPC_SO_TIMESTAMPNS;
        time_size = sizeof(struct tarpc_timespec);
    }
    else
    {
        ioctl_req = RPC_SIOCGSTAMP;
        sock_opt = RPC_SO_TIMESTAMP;
        time_size = sizeof(struct tarpc_timeval);
    }

    ts = (uint8_t *)malloc(time_size);
    ts_bkp = (uint8_t *)malloc(time_size);
    ts2 = (uint8_t *)malloc(time_size);
    memset(ts, 0, time_size);
    memset(ts_bkp, 0, time_size);
    memset(ts2, 0, time_size);

    domain = rpc_socket_domain_by_addr(iut_addr);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);


    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_IPPROTO_UDP, TRUE, FALSE,
                                       iut_addr);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    epfd = rpc_epoll_create(pco_iut, 1);
    event.events = RPC_EPOLLIN | RPC_EPOLLET;
    event.data.fd = iut_s;
    rpc_epoll_ctl(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                  &event);
    
    /* There is no data on the socket yet */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts);
    if (rc != -1)
    {
        TEST_FAIL("ioctl(%s) called on a socket that has no data yet "
                  "returns %d, but expected -1", ioctl_rpc2str(ioctl_req),
                  rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_ENOENT,
            "ioctl(%s) called on a socket that has no data yet "
            "returns -1, but",  ioctl_rpc2str(ioctl_req));

    if (memcmp(ts, ts_bkp, time_size) != 0)
    {
        TEST_FAIL("ioctl(%s) returns -1, but updates time structure",
                  ioctl_rpc2str(ioctl_req));
    }

    if (get_ioctl_after_sockopt)
    {
        SEND_RECV_TIME(low_time_aux, high_time_aux);
        if (recv_before_sockopt)
        {
            rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);
            if (memcmp(tx_buf, rx_buf, buf_len) != 0)
                TEST_FAIL("The content of tx_buf and rx_buf "
                          "are not the same");
        }
    }

    SEND_RECV_TIME(low_time, high_time);

    if (!use_so_timestamp)
    {
        /* The data has already come, but has not been read yet */
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts);
        if (rc == 0)
        {
            RING("ioctl(%s) called on a socket that has some "
                 "pending data but no read operation has been performed "
                 "on it since creation returns 0",
                 ioctl_rpc2str(ioctl_req));
        }
        else
        {
            if (rc != -1)
            {
                TEST_FAIL("ioctl(%s) called on a socket that "
                          "has data that is not read yet "
                          "returns %d, but expected 0 or -1",
                          ioctl_rpc2str(ioctl_req), rc);
            }
            CHECK_RPC_ERRNO(pco_iut, RPC_ENOENT,
                            "ioctl(%s) called on a socket that has data "
                            "that is not read yet returns -1",
                            ioctl_rpc2str(ioctl_req));

            if (memcmp(ts, ts_bkp, time_size) != 0)
            {
                TEST_FAIL("ioctl(%s) returns -1, but updates "
                          "time structure", ioctl_rpc2str(ioctl_req));
            }
        }

        /* Receive data on the socket */
        rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);

        if (memcmp(tx_buf, rx_buf, buf_len) != 0)
        {
            TEST_FAIL("The content of tx_buf and rx_buf are not the same");
        }
    }

    SLEEP(1);

    if (use_so_timestamp)
    {
        rpc_setsockopt(pco_iut, iut_s, sock_opt, &on);

        vector.iov_base = rx_buf;
        vector.iov_len = vector.iov_rlen = buf_len;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iovlen = msg.msg_riovlen = 1;
        msg.msg_iov = &vector;
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = TST_CMSG_LEN;
        msg.msg_cmsghdr_num = 1;
        memset(cmsg_buf, 0, TST_CMSG_LEN);

        if (get_ioctl_after_sockopt && !recv_before_sockopt)
        {
            func(pco_iut, iut_s, &msg, 0);
            /*
             * Do not forget to restore control messages buffer size
             * before calling recvmsg() the next time - size of
             * related data type may be different on test machine!
             */
            msg.msg_controllen = TST_CMSG_LEN;
        }

        func(pco_iut, iut_s, &msg, 0);
        cmsg = sockts_msg_lookup_control_data(&msg, SOL_SOCKET,
                                              sockopt_rpc2h(sock_opt));
        if (cmsg == NULL)
            TEST_VERDICT("Ancillary data on rcv socket is not recieved");

       opt_data_len =  cmsg->cmsg_len - sizeof(*cmsg);
       if (time_size > opt_data_len)
       {
           memset(ts, 0, time_size);
           ptr = CMSG_DATA(cmsg);
           memcpy(ts, ptr, opt_data_len / 2);
           memcpy(&ts[time_size / 2], &ptr[(opt_data_len / 2)],
                  opt_data_len / 2);
       }
       else
            memcpy(ts, CMSG_DATA(cmsg), time_size);

        if (memcmp(tx_buf, rx_buf, buf_len) != 0)
        {
            TEST_FAIL("The content of tx_buf and rx_buf are not the same");
        }
    }
    else
    {
        /* The data has already been read */
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts);
        if (rc != 0)
        {
            TEST_FAIL("ioctl(%s) after reading datagram returns %d, "
                      "but expected 0", ioctl_rpc2str(ioctl_req), rc);
        }
    }

    TS_TO_MS;
    CHECK_TIME(tmp_ts, low_time, high_time, "", !use_so_timestamp);

    /* Call ioctl() once again */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts2);
    if (use_so_timestamp &&
        (!get_ioctl_after_sockopt || !recv_before_sockopt))
    {
        if (rc != -1)
            TEST_VERDICT("ioctl(%s) returned %d instead of -1 "
                         "when %s was set",
                         ioctl_rpc2str(ioctl_req), rc,
                         sockopt_rpc2str(sock_opt));

        CHECK_RPC_ERRNO(pco_iut, RPC_ENOENT,
                        "ioctl(%s) called on a socket with turned "
                        "on %s option returns -1, but",
                        ioctl_rpc2str(ioctl_req),
                        sockopt_rpc2str(sock_opt));
    }
    else
    {
        if (!get_ioctl_after_sockopt)
        {
            if (rc != 0)
            {
                TEST_FAIL("ioctl(%s) called the second time after "
                          "reading a single datagram returns %d, but "
                          "expected 0", ioctl_rpc2str(ioctl_req), rc);
            }
            if (memcmp(ts, ts2, time_size) != 0)
            {
                TEST_FAIL("Timestamps obtained on the first and "
                          "the second calls of ioctl(%s) are "
                          "different", ioctl_rpc2str(ioctl_req));
            }
        }
        else
        {
            if (rc != 0)
            {
                TEST_FAIL("ioctl(%s) called after socket option was set "
                          "returns %d, but expected 0",
                          ioctl_rpc2str(ioctl_req), rc);
            }
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts);
            if (rc != 0)
            {
                TEST_FAIL("ioctl(%s) called second time after socket "
                          "option was set returns %d, but expected 0",
                          ioctl_rpc2str(ioctl_req), rc);
            }
            TS_TO_MS;
            CHECK_TIME(tmp_ts, low_time_aux, high_time_aux,
                       "For ioctl() after socket option set, ", TRUE);
            if (memcmp(ts, ts2, time_size) != 0)
            {
                TEST_FAIL("Timestamps obtained on the first and "
                          "the second calls of ioctl(%s) are "
                          "different", ioctl_rpc2str(ioctl_req));
            }
        }
    }

    for (i = 0; i < sizeof(test_cb) / sizeof(test_cb[0]); i++)
    {
        rpc_gettimeofday(pco_iut, &(test_cb[i].low_time), NULL);

        RPC_SENDTO(rc, pco_tst, tst_s, tx_buf, buf_len, 0, iut_addr);
        SLEEP(test_cb[i].delay);

        rpc_gettimeofday(pco_iut, &(test_cb[i].high_time), NULL);
    }

    for (i = 0; i < sizeof(test_cb) / sizeof(test_cb[0]); i++)
    {
        if (use_so_timestamp)
        {
            memset(cmsg_buf, 0, TST_CMSG_LEN);

            msg.msg_controllen = TST_CMSG_LEN;
            func(pco_iut, iut_s, &msg, 0);
            cmsg = sockts_msg_lookup_control_data(&msg, SOL_SOCKET,
                                                  sockopt_rpc2h(sock_opt));
            if (cmsg == NULL)
                TEST_FAIL("Ancillary data on rcv socket is not recieved");

            opt_data_len =  cmsg->cmsg_len - sizeof(*cmsg);
            if (time_size > opt_data_len)
            {
                memset(ts, 0, time_size);
                ptr = CMSG_DATA(cmsg);
                memcpy(ts, ptr, opt_data_len / 2);
                memcpy(&ts[time_size / 2],
                       &ptr[(opt_data_len / 2)], opt_data_len / 2);
            }
            else
                 memcpy(ts, CMSG_DATA(cmsg), time_size);
        }
        else
        {
            rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);

            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts);

            if (rc != 0)
            {
                TEST_FAIL("ioctl(%s) after reading datagram "
                          "returns %d, but expected 0",
                          ioctl_rpc2str(ioctl_req), rc);
            }
        }

        TS_TO_MS;

        low_diff = TIMEVAL_SUB(tmp_ts, test_cb[i].low_time);
        high_diff = TIMEVAL_SUB(test_cb[i].high_time, tmp_ts);
        if (low_diff < -TIMEVAL_ACCURACY || high_diff < -TIMEVAL_ACCURACY)
        {
            TEST_FAIL("Incorrect timestamp was returned "
                      "on %d turn: it is expected to be in "
                      "the range: [%s, %s], but it equals to %s",
                      i + 1,
                      tarpc_timeval2str(&test_cb[i].low_time),
                      tarpc_timeval2str(&test_cb[i].high_time),
                      tarpc_timeval2str(&tmp_ts));
        }
        else if (low_diff < 0 || high_diff < 0)
        {
            RING("Timestamp accuracy on %d turn: %1.2f sec, too %s",
                 i + 1,
                 1 + (MAX(-low_diff,-high_diff) - 1) / 1000000.,
                 low_diff < 0 ? "early" : "late");
        }

        if (!use_so_timestamp)
        {
            /* Call ioctl() once again */
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts2);
            if (rc != 0)
            {
                TEST_FAIL("ioctl(%s) called second time after "
                          "reading datagram returns %d, but expected 0",
                          ioctl_rpc2str(ioctl_req), rc);
            }

            if (memcmp(ts, ts2, time_size) != 0)
            {
                TEST_FAIL("Timestamps obtained on the first and "
                          "the second calls of ioctl(%s) are different",
                          ioctl_rpc2str(ioctl_req));
            }
        }
    }

    TEST_SUCCESS;

cleanup:
    free(tx_buf);
    free(rx_buf);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
