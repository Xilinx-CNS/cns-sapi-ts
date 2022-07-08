/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page ioctls-siocgstamp_two_senders SIOCGSTAMP[,NS] IOCTL request and SO_TIMESTAMP[,NS] in case of two senders
 *
 * @objective Check the behavior of @c SIOCGSTAMP @c SIOCGSTAMPNS
 *            @p ioctl() requests and @c SO_TIMESTAMP and
 *            @c SO_TIMESTAMPNS with two senders
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst1          PCO on Tester
 * @param pco_tst2          PCO on Tester
 * @param use_so_timestamp  Use @c SO_TIMESTAMP instead of @c SIOCGSTAMP
 * @param use_ns            Use @c SO_TIMESTAMPNS and @c SIOCGSTAMPNS
 *                          instead of @c SO_TIMESTAMP and @c SIOCGSTAMP
 *
 * @par Test sequence:
 * -# Create datagram socket @p iut_s on @b pco_iut and bind it to
 *    @p iut_addr address/port.
 * -# Call @b ioctl() with @c SIOCGSTAMP request on @p iut_s. Check that
 *    it returns @c -1 with @c ENOENT errno. This step is required to
 *    enable timestamping on Linux 2.6 kernel.
 * -# Create datagram socket @p tst_s1 on @b pco_tst1.
 * -# Create datagram socket @p tst_s2 on @b pco_tst2.
 * -# Send datagram via @p tst_s1 to @p iut_addr address.
 * -# Receive it on @p iut_s.
 * -# Call @b ioctl() with @c SIOCGSTAMP request on @p iut_s.
 * -# Check that it returned @c 0 with correct timestamp.
 * -# Send datagram via @p tst_s2 to @p iut_addr address.
 * -# Receive it on @p iut_s.
 * -# Call @b ioctl() with @c SIOCGSTAMP request on @p iut_s.
 * -# Check that it returned @c 0 with correct timestamp.
 * -# Close all sockets.
 *
 * @author Georgij Volfson <Georgij.Volfson@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocgstamp_two_senders"

#include "sockapi-test.h"
#include "iomux.h"

/* Precision of timestamp, in usec (1sec). */
#define TIMEVAL_ACCURACY 2000000L

#define TST_CMSG_LEN      300

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;

    rcf_rpc_server         *pco_tester = NULL;
    int                     tst_socket = -1;

    int                     iut_s = -1;
    int                     tst_s1 = -1;
    int                     tst_s2 = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *iut1_addr;
    const struct sockaddr  *iut2_addr;

    void                   *tx_buf;
    void                   *rx_buf;

    size_t                  tx_buf_len;
    size_t                  rx_buf_len;

    uint8_t                *ts = NULL;
    tarpc_timeval           tmp_ts = {0, 0};

    tarpc_timeval           low_time = {0, 0};
    tarpc_timeval           high_time = {0, 0};

    long                    low_diff, high_diff;

    int i;

    te_bool          use_so_timestamp;
    te_bool          use_ns;
    int              on = 1;
    struct rpc_iovec vector;
    uint8_t          cmsg_buf[TST_CMSG_LEN];
    struct cmsghdr  *cmsg;
    rpc_msghdr       msg;

    int             opt_data_len;
    unsigned char  *ptr;

    int             ioctl_req;
    int             sock_opt;
    int             time_size;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR_NO_PORT(iut1_addr);
    TEST_GET_ADDR_NO_PORT(iut2_addr);
    te_sockaddr_set_port(SA(iut1_addr), te_sockaddr_get_port(iut_addr));
    te_sockaddr_set_port(SA(iut2_addr), te_sockaddr_get_port(iut_addr));
    TEST_GET_BOOL_PARAM(use_so_timestamp);
    TEST_GET_BOOL_PARAM(use_ns);

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
    memset(ts, 0, time_size);

    CHECK_NOT_NULL(tx_buf = sockts_make_buf_dgram(&tx_buf_len));
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    tst_s1 = rpc_socket(pco_tst1, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s2 = rpc_socket(pco_tst2, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    /*
     * Linux 2.6 has disabled timestamping by default.
     * The first request enables it.
     */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts);
    if (rc != -1)
    {
        TEST_FAIL("%s IOCTL request was called on just created "
                  "socket but it returned %d instead of -1",
                  ioctl_rpc2str(ioctl_req), rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_ENOENT,
                    "%s IOCTL request was called on just "
                    "created socket", ioctl_rpc2str(ioctl_req));

    if (use_so_timestamp)
    {
        rpc_setsockopt(pco_iut, iut_s, sock_opt, &on);

        vector.iov_base = rx_buf;
        vector.iov_len = vector.iov_rlen = rx_buf_len;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iovlen = msg.msg_riovlen = 1;
        msg.msg_iov = &vector;
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = TST_CMSG_LEN;
        msg.msg_cmsghdr_num = 1;
        memset(cmsg_buf, 0, TST_CMSG_LEN);
    }

    for (i = 0; i < 2; i++)
    {
        if (i != 0)
            SLEEP(1);

        if (i == 0)
        {
            pco_tester = pco_tst1;
            tst_socket = tst_s1;
            iut_addr = iut1_addr;
        }
        else
        {
            pco_tester = pco_tst2;
            tst_socket = tst_s2;
            iut_addr = iut2_addr;
        }


        rpc_gettimeofday(pco_iut, &low_time, NULL);

        pco_iut->op = RCF_RPC_CALL;
        iomux_call_default_simple(pco_iut, iut_s, EVT_RD, NULL, -1);

        rpc_sendto(pco_tester, tst_socket, tx_buf, tx_buf_len, 0, iut_addr);

        pco_iut->op = RCF_RPC_WAIT;
        iomux_call_default_simple(pco_iut, iut_s, EVT_RD, NULL, -1);

        rpc_gettimeofday(pco_iut, &high_time, NULL);

        if (use_so_timestamp)
        {
            memset(cmsg_buf, 0, TST_CMSG_LEN);

            msg.msg_controllen = TST_CMSG_LEN;
            rpc_recvmsg(pco_iut, iut_s, &msg, 0);
            cmsg = sockts_msg_lookup_control_data(&msg, SOL_SOCKET,
                                                  sockopt_rpc2h(sock_opt));
            if (cmsg == NULL)
                TEST_VERDICT("Auxiliary data on rcv socket is not "
                             "recieved");

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
        }
        else
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts);
            if (i == 0 && rc != -1)
                TEST_FAIL("ioctl returned non-error although the packet "
                          "was not actually passed to userland");
            else if (i == 1 && rc != 0)
                TEST_FAIL("ioctl returned error although was expected to "
                          "return zero and timestamp from the previous "
                          "packet");

            rpc_recv(pco_iut, iut_s, rx_buf, rx_buf_len, 0);

            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_ioctl(pco_iut, iut_s, ioctl_req, ts);
            if (rc == -1)
            {
                TEST_VERDICT("%s IOCTL request returned -1, but the "
                             "datagram was recieved on the socket",
                             ioctl_rpc2str(ioctl_req));
            }
        }

        if (use_ns)
        {
            tmp_ts.tv_sec = ((struct tarpc_timeval *)ts)->tv_sec;
            tmp_ts.tv_usec = ((struct tarpc_timeval *)ts)->tv_usec / 1000;
        }
        else
            memcpy(&tmp_ts, ts, time_size);
        low_diff = TIMEVAL_SUB(tmp_ts, low_time);
        high_diff = TIMEVAL_SUB(high_time, tmp_ts);
        if (low_diff < 0 || high_diff < 0)
        {
            RING("Low   : %d s %d ms\n"
                 "Hight : %d s %d ms\n"
                 "Got   : %d s %d ms",
                 (int)low_time.tv_sec, (int)low_time.tv_usec,
                 (int)high_time.tv_sec, (int)high_time.tv_usec,
                 (int)tmp_ts.tv_sec, (int)tmp_ts.tv_usec);
            if (low_diff < -TIMEVAL_ACCURACY || high_diff < -TIMEVAL_ACCURACY)
                TEST_FAIL("ioctl(SIOCGSTAMP) returns incorrect timestamp");
            RING_VERDICT("SIOCGSTAMP precision is too low");
        }
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst1, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
