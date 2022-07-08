/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 * 
 * $Id$
 */

/** @page timestamps-siocshwtstamp Usage of SIOCSHWTSTAMP request and SO_TIMESTAMPING option
 *
 * @objective Check that @c SIOCSHWTSTAMP request and
 *            @c SO_TIMESTAMPING socket option return
 *            a @c scm_timestamping structure containing the time at
 *            which the packet was received.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param sock_type        Socket type
 * @param use_raw_hw_ts    Use @c SOF_TIMESTAMPING_RAW_HARDWARE
 * @param use_sys_hw_ts    Use @c SOF_TIMESTAMPING_SYS_HARDWARE
 * @param use_sw_ts        Use @c SOF_TIMESTAMPING_SOFTWARE
 * @param none_ioctl       If it is @c TRUE use @c RPC_HWTSTAMP_FILTER_NONE
 *                         else use @c RPC_HWTSTAMP_FILTER_ALL
 * 
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/siocshwtstamp"

#include "sockapi-test.h"
#include "timestamps.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rpc_socket_type        sock_type;

    test_substep test_cb [] = {
        {1, { 0, 0 }, { 0, 0 }},
        {2, { 0, 0 }, { 0, 0 }},
        {4, { 0, 0 }, { 0, 0 }},
        {5, { 0, 0 }, { 0, 0 }},
        {2, { 0, 0 }, { 0, 0 }},
        {0, { 0, 0 }, { 0, 0 }},
    };
    unsigned int i;

    struct cmsghdr  *cmsg;
    rpc_msghdr       msg;
    void            *tx_buf = NULL;
    size_t           buf_len;

    int so_timestamping_flags = 0;

    const struct if_nameindex *iut_if;
    rpc_hwtstamp_config        hw_cfg;

    te_bool call_ioctl;
    te_bool none_ioctl;
    te_bool use_raw_hw_ts;
    te_bool use_sys_hw_ts;
    te_bool use_sw_ts;
    te_bool onload;
    te_bool ts_sys_zero;

    rpc_scm_timestamping ts;
    rpc_scm_timestamping ts_prev;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_BOOL_PARAM(call_ioctl);
    TEST_GET_BOOL_PARAM(none_ioctl);
    TEST_GET_BOOL_PARAM(use_raw_hw_ts);
    TEST_GET_BOOL_PARAM(use_sys_hw_ts);
    TEST_GET_BOOL_PARAM(use_sw_ts);

    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);

    ts_sys_zero = tapi_getenv_bool("IUT_TS_SYS_ZERO");
    onload = tapi_onload_lib_exists(pco_iut->ta);

    tx_buf = sockts_make_buf_dgram(&buf_len);

    TEST_STEP("Create connection betwee Tester and IUT TCP or UDP in dependece on "
              "type @p sock_type.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Set @c SO_TIMESTAMPING socket option according to @p use_raw_hw_ts, "
              "@p use_sys_hw_ts, @p use_sw_ts.");
    so_timestamping_flags = RPC_SOF_TIMESTAMPING_RX_HARDWARE;
    if (use_raw_hw_ts)
        so_timestamping_flags |= RPC_SOF_TIMESTAMPING_RAW_HARDWARE;
    if (use_sys_hw_ts)
        so_timestamping_flags |= RPC_SOF_TIMESTAMPING_SYS_HARDWARE;
    if (use_sw_ts)
        so_timestamping_flags |= RPC_SOF_TIMESTAMPING_SOFTWARE |
                                 RPC_SOF_TIMESTAMPING_RX_SOFTWARE;

    rpc_setsockopt(pco_iut, iut_s, RPC_SO_TIMESTAMPING,
                   &so_timestamping_flags);

    if (ts_sys_zero)
        use_sys_hw_ts = FALSE;

    TEST_STEP("Set @c SIOCSHWTSTAMP ioctl value ioctl "
              "according to @p none_ioctl value if @p call_ioctl is @c TRUE.");
    memset(&hw_cfg, 0, sizeof(hw_cfg));
    hw_cfg.tx_type = RPC_HWTSTAMP_TX_OFF;
    hw_cfg.rx_filter = none_ioctl ? RPC_HWTSTAMP_FILTER_NONE :
                                    RPC_HWTSTAMP_FILTER_ALL;
    if (call_ioctl)
        CHECK_RC(ioctl_set_ts(pco_iut->ta, iut_if->if_name, &hw_cfg));

    ts_init_msghdr(FALSE, &msg, buf_len);

    TEST_STEP("Send a few packets from @p pco_tst to @p pco_iut and store the time "
              "for futher checks.");
    for (i = 0; i < sizeof(test_cb) / sizeof(test_cb[0]); i++)
    {
        rpc_gettimeofday(pco_iut, &(test_cb[i].low_time), NULL);
        RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);
        rpc_gettimeofday(pco_iut, &(test_cb[i].high_time), NULL);

        SLEEP(test_cb[i].delay);
    }

    memset(&ts, 0, sizeof(ts));
    memset(&ts_prev, 0, sizeof(ts_prev));

    TEST_STEP("Recieve the packets on @p pco_iut, and check that "
              "@c SO_TIMESTAMPING controll message contains the stucture which is "
              "filled accoring to @p use_raw_hw_ts, @p use_sys_hw_ts, @p use_sw_ts "
              "and @p none_ioctl parameters. And check the time.");
    for (i = 0; i < sizeof(test_cb) / sizeof(test_cb[0]); i++)
    {
        msg.msg_controllen = SOCKTS_CMSG_LEN;
        rpc_recvmsg(pco_iut, iut_s, &msg, 0);
        cmsg = sockts_msg_lookup_control_data(&msg, SOL_SOCKET,
                                        sockopt_rpc2h(RPC_SO_TIMESTAMPING));

        if (cmsg != NULL)
        {
            memcpy(&ts, CMSG_DATA(cmsg), sizeof(ts));
            ts_print_sys(&ts);

            RING("Host timestamp before %s, after %s",
                 tarpc_timeval2str(&test_cb[i].low_time),
                 tarpc_timeval2str(&test_cb[i].high_time));
        }

        if ((!onload && none_ioctl && !use_sw_ts) ||
            (!use_raw_hw_ts && !use_sys_hw_ts && !use_sw_ts))
        {
            if (cmsg != NULL)
                TEST_VERDICT("Ancillary data was recieved");
            continue;
        }
        else if (cmsg == NULL)
            TEST_VERDICT("Ancillary data was not recieved");

        ts_check_msg_control_data(&msg, FALSE, NULL, NULL);

        if (use_sw_ts)
            cmp_ts_with_hosttime(&ts.systime, test_cb + i, "SW");
        else if (!ts_timespec_is_zero(&ts.systime))
            TEST_VERDICT("SW timestamps were set but "
                         "SOF_TIMESTAMPING_SOFTWARE flag is not.");

        if (use_sys_hw_ts && (!none_ioctl || onload))
        {
            if (ts_timespec_is_zero(&ts.hwtimetrans))
                RING_VERDICT("SYS HW timestamps were not set");

            cmp_ts_with_hosttime(&ts.hwtimetrans, test_cb + i, "HW trans");
            if (i > 0)
                cmp_ts_with_prev(&ts_prev.hwtimetrans, &ts.hwtimetrans,
                                 test_cb + i - 1, test_cb + i);
        }
        else if (!ts_timespec_is_zero(&ts.hwtimetrans))
        {
            if (!use_sys_hw_ts)
                TEST_VERDICT("HW sys timestamps were set but "
                             "SOF_TIMESTAMPING_SYS_HARDWARE flag "
                             "is not.");
            else
                TEST_VERDICT("HW sys timestamps were set but "
                             "HWTSTAMP_FILTER_NONE was set");
        }

        if (use_raw_hw_ts && (!none_ioctl || onload))
        {
            if (ts_timespec_is_zero(&ts.hwtimeraw))
                RING_VERDICT("RAW HW timestamps were not set");

            cmp_ts_with_hosttime(&ts.hwtimeraw, test_cb + i, "HW raw");
            if (i > 0)
                cmp_ts_with_prev(&ts_prev.hwtimeraw, &ts.hwtimeraw,
                                 test_cb + i - 1, test_cb + i);
        }
        else if (ts_timespec_is_zero(&ts.hwtimeraw) == FALSE)
        {
            if (!use_raw_hw_ts)
                TEST_VERDICT("HW raw timestamps were set but "
                             "SOF_TIMESTAMPING_RAW_HARDWARE flag "
                             "is not.");
            else
                TEST_VERDICT("HW raw timestamps were set but "
                             "HWTSTAMP_FILTER_NONE was set");
        }

        if (use_sw_ts && use_sys_hw_ts && use_raw_hw_ts &&
            (!none_ioctl || onload))
        {
            if (ts_check_deviation(&ts.systime, &ts.hwtimetrans, 0, 1000000))
                TEST_VERDICT("HW sys timestamps differ from HW raw "
                             "timestamps");

            if (ts_check_deviation(&ts.hwtimetrans, &ts.hwtimeraw, 0, 1000000))
                TEST_VERDICT("HW sys timestamps are incorrect");
        }

        memcpy(&ts_prev, &ts, sizeof(ts_prev));
    }

    TEST_SUCCESS;

cleanup:
    free(tx_buf);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_release_msghdr(&msg);

    TEST_END;
}
