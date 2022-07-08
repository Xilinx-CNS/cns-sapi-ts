/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 * 
 * $Id$
 */

/** @page timestamps-siocshwtstamp_tx Usage of SIOCSHWTSTAMP request and SO_TIMESTAMPING option for TX
 *
 * @objective Check that @c SIOCSHWTSTAMP request and @c SO_TIMESTAMPING
 *            socket option return a @c scm_timestamping structure
 *            containing the time at which the packet was sent.
 *
 * @type conformance
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param sock_type        Socket type
 * @param use_hw_tx        Use @c SOF_TIMESTAMPING_TX_HARDWARE flag
 * @param use_raw_hw_ts    Use @c SOF_TIMESTAMPING_RAW_HARDWARE flag
 * @param use_sys_hw_ts    Use @c SOF_TIMESTAMPING_SYS_HARDWARE flag
 * @param use_sw_ts        Use @c SOF_TIMESTAMPING_SOFTWARE flag
 * @param use_tx_sched     Use @c SOF_TIMESTAMPING_TX_SCHED flag
 * @param none_ioctl       If it is @c TRUE use @c RPC_HWTSTAMP_FILTER_NONE
 *                         else use @c RPC_HWTSTAMP_FILTER_ALL
 * 
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/siocshwtstamp_tx"

#include "sockapi-test.h"
#include "timestamps.h"
#include "onload.h"

/* Auxiliary type to avoid calling the ioctl() at all. */
#define HWTSTAMP_TX_NONE (RPC_HWTSTAMP_TX_ONESTEP_SYNC + 1)

#define IOCTL_TX \
    { "HWTSTAMP_TX_OFF", RPC_HWTSTAMP_TX_OFF }, \
    { "HWTSTAMP_TX_ON", RPC_HWTSTAMP_TX_ON },   \
    { "HWTSTAMP_TX_ONESTEP_SYNC", RPC_HWTSTAMP_TX_ONESTEP_SYNC }, \
    { "HWTSTAMP_TX_NONE", HWTSTAMP_TX_NONE }

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rpc_socket_type        sock_type;

    struct cmsghdr  *cmsg;
    rpc_msghdr       msg;
    void            *tx_buf = NULL;
    void            *rx_buf = NULL;
    size_t           buf_len;

    const struct if_nameindex *iut_if;
    rpc_hwtstamp_config        hw_cfg;
    struct sock_extended_err   template = {.ee_errno = ENOMSG,
                                           .ee_info = 0,
                                           .ee_origin =
                                                SO_EE_ORIGIN_TIMESTAMPING};
    te_bool use_raw_hw_ts;
    te_bool use_sys_hw_ts;
    te_bool use_sw_ts;
    te_bool use_tx_sched;
    te_bool use_onload_stream;
    te_bool use_hw_tx;
    te_bool onload = FALSE;

    rpc_scm_timestamping               *ts;
    rpc_scm_timestamping                ts_prev;
    rpc_onload_scm_timestamping_stream *ts_tx;
    rpc_onload_scm_timestamping_stream  ts_tx_prev;

    test_substep test_cb [] = {
        {1, { 0, 0 }, { 0, 0 }},
        {2, { 0, 0 }, { 0, 0 }},
        {1, { 0, 0 }, { 0, 0 }},
        {0, { 0, 0 }, { 0, 0 }},
    };
    te_bool vlan = FALSE;
    te_bool exp_ts;
    size_t  num;
    size_t  i;
    size_t  dev = 1;

    int iut_s = -1;
    int tst_s = -1;
    int flags = 0;
    int ioctl_tx;
    int hsize = 0;
    int ad = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_GET_BOOL_PARAM(use_raw_hw_ts);
    TEST_GET_BOOL_PARAM(use_sys_hw_ts);
    TEST_GET_BOOL_PARAM(use_sw_ts);
    TEST_GET_BOOL_PARAM(use_tx_sched);
    TEST_GET_BOOL_PARAM(use_onload_stream);
    TEST_GET_BOOL_PARAM(use_hw_tx);
    TEST_GET_ENUM_PARAM(ioctl_tx, IOCTL_TX);

    tx_buf = sockts_make_buf_stream(&buf_len);
    rx_buf = te_make_buf_by_len(buf_len);
    ts_init_msghdr(TRUE, &msg, buf_len + 300);

    onload = tapi_onload_run();

    if (sock_type == RPC_SOCK_DGRAM)
        hsize = LINUX_DGRAM_HEADER_LEN;
    else
        hsize = LINUX_TCP_HEADER_LEN;

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Set @c SIOCSHWTSTAMP ioctl value in according to @p ioctl_tx.");
    memset(&hw_cfg, 0, sizeof(hw_cfg));
    hw_cfg.tx_type = ioctl_tx;
    hw_cfg.rx_filter = RPC_HWTSTAMP_FILTER_NONE;
    if (ioctl_tx != HWTSTAMP_TX_NONE)
        CHECK_RC(ioctl_set_ts(pco_iut->ta, iut_if->if_name, &hw_cfg));

    TEST_STEP("Set @c SO_TIMESTAMPING socket option according to @p use_raw_hw_ts, "
              "@p use_sys_hw_ts, @p use_sw_ts, @p use_tx_sched, @p use_hw_tx and "
              "@p use_onload_stream.");
    if (use_hw_tx)
        flags |= RPC_SOF_TIMESTAMPING_TX_HARDWARE;
    if (use_raw_hw_ts)
        flags |= RPC_SOF_TIMESTAMPING_RAW_HARDWARE;
    if (use_sys_hw_ts)
        flags |= RPC_SOF_TIMESTAMPING_SYS_HARDWARE;
    if (use_tx_sched)
        flags |= RPC_SOF_TIMESTAMPING_TX_SCHED |
                 RPC_SOF_TIMESTAMPING_SOFTWARE;
    if (use_sw_ts)
        flags |= RPC_SOF_TIMESTAMPING_TX_SOFTWARE |
                 RPC_SOF_TIMESTAMPING_SOFTWARE;
    if (use_onload_stream)
        flags |= RPC_ONLOAD_SOF_TIMESTAMPING_STREAM;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_SO_TIMESTAMPING, &flags);
    if (rc < 0)
    {
        if (RPC_ERRNO(pco_iut) == RPC_EINVAL)
        {
            if (use_onload_stream && 
                (sock_type == RPC_SOCK_DGRAM || !use_hw_tx))
                TEST_SUCCESS;
            if (use_tx_sched && !tapi_getenv_bool("IUT_TS_TX_SCHED"))
                TEST_SUCCESS;
        }

        TEST_FAIL("setsockopt failed with unexpected error %s",
                  errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (tapi_getenv_bool("IUT_TS_SYS_ZERO"))
        use_sys_hw_ts = FALSE;
    if (!tapi_getenv_bool("IUT_TS_TX_HW"))
    {
        use_raw_hw_ts = FALSE;
        use_sys_hw_ts = FALSE;
    }
    if (!tapi_getenv_bool("IUT_TS_TX_SW"))
        use_sw_ts = FALSE;

    if (!tapi_getenv_bool("IUT_TS_TX_SCHED"))
        use_tx_sched = FALSE;

    if (sock_type == RPC_SOCK_DGRAM && !tapi_getenv_bool("IUT_TS_TX_SW_UDP"))
    {
        use_sw_ts = FALSE;
        use_tx_sched = FALSE;
    }

    if ((!onload && hw_cfg.tx_type != RPC_HWTSTAMP_TX_ON) || !use_hw_tx)
    {
        use_sys_hw_ts = FALSE;
        use_raw_hw_ts = FALSE;
    }

    if (sock_type == RPC_SOCK_STREAM &&
        !tapi_getenv_bool("IUT_TS_TX_TCP") && !use_onload_stream)
    {
        use_sw_ts = FALSE;
        use_sys_hw_ts = FALSE;
        use_raw_hw_ts = FALSE;
        use_tx_sched = FALSE;
    }

    RING("Expected timestamps sw_ts %d, use_tx_sched %dsys_hw_ts %d, "
         "raw_hw_ts %d", use_sw_ts, use_tx_sched, use_sys_hw_ts,
         use_raw_hw_ts);

    TEST_STEP("Send and receive a few packets from @p pco_iut to @p pco_tst and "
              "store the time for futher analysis.");
    for (i = 0; i < sizeof(test_cb) / sizeof(test_cb[0]); i++)
    {
        rpc_gettimeofday(pco_iut, &(test_cb[i].low_time), NULL);

        memset(rx_buf, 0, sizeof(*rx_buf));
        if (rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0) != (int)buf_len)
            TEST_FAIL("Not all data was sent");
        if (rpc_recv(pco_tst, tst_s, rx_buf, buf_len, 0) != (int)buf_len)
            TEST_FAIL("Not all data was received");
        if (memcmp(tx_buf, rx_buf, buf_len) != 0)
            TEST_FAIL("Different data was received on tester.");
        rpc_gettimeofday(pco_iut, &(test_cb[i].high_time), NULL);

        SLEEP(test_cb[i].delay);
    }

    memset(&ts, 0, sizeof(ts));
    memset(&ts_prev, 0, sizeof(ts_prev));

    num = sizeof(test_cb) / sizeof(test_cb[0]);
    if (use_sw_ts && use_tx_sched)
    {
        if (vlan)
            dev = 3;
        else
            dev = 2;
    }
    else if (use_tx_sched && vlan)
        dev = 2;
    num *= dev;

    TEST_STEP("Try to retrieve timestamps with recvmsg(MSG_ERRQUEUE) calls. Compare "
              "timestamps with the saved host time and check that delay between "
              "previous and current iterations is about expected.");
    for (i = 0; i < num; i++)
    {
        /* Timeout is necessary when spinning is enabled. */
        TAPI_WAIT_TS;
        RING("Host timestamp before %s, after %s",
             tarpc_timeval2str(&test_cb[i / dev].low_time),
             tarpc_timeval2str(&test_cb[i / dev].high_time));

        msg.msg_controllen = SOCKTS_CMSG_LEN;

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
        if (rc < 0 && RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            TEST_FAIL("recvmsg failed with unexpected error %s",
                      errno_rpc2str(RPC_ERRNO(pco_iut)));

        if (use_onload_stream)
        {
            if (rc < 0)
            {
                if (!use_hw_tx)
                    TEST_SUCCESS;
                TEST_VERDICT("Timestamp was not retrieved");
            }

            if (rc != 0)
                TEST_VERDICT("Wrong value was returned by recvmsg()");

            cmsg = sockts_msg_lookup_control_data(&msg, SOL_SOCKET,
                         sockopt_rpc2h(RPC_ONLOAD_SCM_TIMESTAMPING_STREAM));

            ts_tx = (rpc_onload_scm_timestamping_stream *)CMSG_DATA(cmsg);
            ts_print_tcp_tx(ts_tx);

            if (!ts_timespec_is_zero(&ts_tx->last_sent))
                TEST_VERDICT("last_sent is not zero, perhaps the packet "
                             "was retransmitted");

            if (ts_tx->len != buf_len)
                TEST_VERDICT("TX timestamp returned wrong segment size");

            cmp_ts_with_hosttime(&ts_tx->first_sent, test_cb + i,
                                 "HW TX TCP");
            if (i > 0)
                cmp_ts_with_prev(&ts_tx_prev.first_sent, &ts_tx->first_sent,
                                 test_cb + i - 1, test_cb + i);

            memcpy(&ts_tx_prev, ts_tx, sizeof(ts_tx_prev));
        }
        else
        {
            if (use_raw_hw_ts || use_sys_hw_ts || use_sw_ts || use_tx_sched)
                exp_ts = TRUE;
            else
                exp_ts = FALSE;

            /** UDP datagram is returned with VLAN addition with Onload, it
             * is thought to be correct, see bug 56367. */
            if (vlan && (sock_type == RPC_SOCK_STREAM || onload))
                ad = 4;
            else
                ad = 0;

            if (use_tx_sched)
            {
                /* ee_info field determines software timestamp type. */
                if (use_sw_ts &&
                    ((!vlan && i % 2 == 1) || (vlan && i % 3 == 2)))
                    template.ee_info = 0;
                else
                    template.ee_info = RPC_SCM_TSTAMP_SCHED;
                ad = 0;
            }

            if (rc < 0)
            {
                if (!exp_ts)
                    TEST_SUCCESS;
                TEST_VERDICT("Timestamp was not retrieved");
            }

            if (rc - hsize - ad != (int)buf_len)
                TEST_VERDICT("recvmsg() function returned unexpected value");
            if (memcmp(tx_buf, msg.msg_iov->iov_base + hsize + ad, buf_len) != 0)
                TEST_VERDICT("Packet data is corrupted!");

            ts = ts_check_msg_control_data(&msg, TRUE, &template, NULL);
            ts_print_sys(ts);

            if (!exp_ts)
                TEST_VERDICT("Timestamp was unexpectedly retrieved");

            if (use_sys_hw_ts)
            {
                if (ts_timespec_is_zero(&ts->hwtimetrans))
                    TEST_VERDICT("SYS HW timestamps were not set");

                cmp_ts_with_hosttime(&ts->hwtimetrans, test_cb + i,
                                     "HW trans");
                if (i > 0)
                    cmp_ts_with_prev(&ts_prev.hwtimetrans, &ts->hwtimetrans,
                                     test_cb + i - 1, test_cb + i);
            }
            else if (!ts_timespec_is_zero(&ts->hwtimetrans))
                TEST_VERDICT("HW sys timestamps were set but "
                             "SOF_TIMESTAMPING_SYS_HARDWARE flag is not.");

            if (use_raw_hw_ts)
            {
                if (ts_timespec_is_zero(&ts->hwtimeraw))
                    TEST_VERDICT("SYS HW timestamps were not set");

                cmp_ts_with_hosttime(&ts->hwtimeraw, test_cb + i, "HW raw");
                if (i > 0)
                    cmp_ts_with_prev(&ts_prev.hwtimeraw, &ts->hwtimeraw,
                                     test_cb + i - 1, test_cb + i);
            }
            else if (!ts_timespec_is_zero(&ts->hwtimeraw))
                TEST_VERDICT("HW sys timestamps were set but "
                             "SOF_TIMESTAMPING_SYS_HARDWARE flag is not.");

            if (use_sw_ts || use_tx_sched)
            {
                if (dev == 1 || i % dev == 0)
                    cmp_ts_with_hosttime(&ts->systime, test_cb + i / dev, "SW");
                else if (ts_check_deviation(&ts_prev.systime, &ts->systime,
                                            0, HWTIMETRANS_PRECISION))
                    TEST_VERDICT("Scheduled software timestamp "
                                 "differs too much");
            }
            else if (!ts_timespec_is_zero(&ts->systime))
                TEST_VERDICT("SW timestamps were set but "
                             "SOF_TIMESTAMPING_SOFTWARE flag is not.");

            memcpy(&ts_prev, ts, sizeof(ts_prev));
        }

    }

    TEST_SUCCESS;

cleanup:
    free(tx_buf);
    free(rx_buf);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_release_msghdr(&msg);

    TEST_END;
}
