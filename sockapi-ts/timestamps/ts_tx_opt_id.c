/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 *
 * $Id$
 */

/** @page timestamps-ts_tx_opt_id Timestamping flag SOF_TIMESTAMPING_OPT_ID usage
 *
 * @objective  Check if flag SOF_TIMESTAMPING_OPT_ID is set a uniqe packet
 *             identifier is generated.
 *
 * @param pco_iut     PCO on IUT
 * @param pco_tst     PCO on TST
 * @param sock_type   Socket type
 * @param packets_num Packets number
 * @param length_min  Minimum packets length
 * @param length_max  Minimum packets length
 * @param mtu         MTU value to set on IUT interface
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_tx_opt_id"

#include "sockapi-test.h"
#include "timestamps.h"

#include <linux/errqueue.h>

/**
 * Check control messages sanity.
 * 
 * @param msghdr     The message with the control data
 * @param sock_type  Socket type
 * @param onload_ext Onload extenstion TX TCP timestamp
 * @param ts_h       Host time before the packet transmission time
 * 
 * @return ee_data value of extended error (IP_RECVERR) message is returned.
 */
static uint32_t
check_msg(rpc_msghdr *msghdr, rpc_socket_type sock_type, te_bool onload_ext,
          struct timespec *ts_h)
{
    rpc_onload_scm_timestamping_stream *ts_tx = NULL;
    struct sock_extended_err *err = NULL;
    struct sockaddr            sa;
    struct msghdr              msg;
    struct cmsghdr            *cmsg = NULL;
    rpc_scm_timestamping      *ts = NULL;
    struct timespec            ts_o;

    /* Bug 56027: don't use type cast rpc_msghdr -> 'struct msghdr'! */
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = msghdr->msg_control;
    msg.msg_controllen = msghdr->msg_controllen;

    if (msg.msg_controllen == 0)
        TEST_VERDICT("Control data length is zero");

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL)
        TEST_VERDICT("Failed to extrat any control message");

    if (onload_ext)
    {
        if (cmsg->cmsg_level != socklevel_rpc2h(RPC_SOL_SOCKET) ||
            cmsg->cmsg_type != sockopt_rpc2h(RPC_ONLOAD_SCM_TIMESTAMPING_STREAM))
            TEST_VERDICT("First control data message should contain Onload "
                         "extension TCP timestamps");
        ts_tx = (rpc_onload_scm_timestamping_stream *)CMSG_DATA(cmsg);
        ts_print_tcp_tx(ts_tx);

        if (!ts_timespec_is_zero(&ts_tx->last_sent))
            TEST_VERDICT("last_sent is not zero, probably the packet was "
                         "retransmitted");

        ts_check_deviation(&ts_tx->first_sent, ts_h, 0, 100000);

        cmsg = CMSG_NXTHDR(&msg, cmsg);
        if (cmsg != NULL)
            TEST_VERDICT("An extra control message was returned");
        return 0;
    }
    else
    {
        if (cmsg->cmsg_level != socklevel_rpc2h(RPC_SOL_SOCKET) ||
            cmsg->cmsg_type != sockopt_rpc2h(RPC_SO_TIMESTAMPING))
            TEST_VERDICT("First control data message should contain timestamps");
        ts = (rpc_scm_timestamping *)CMSG_DATA(cmsg);

        if (ts_is_supported(TS_SOFTWARE, TRUE, sock_type))
        {
            if(ts_timespec_is_zero(&ts->systime))
                TEST_VERDICT("Software timestamp is zero");
            memcpy(&ts_o, &ts->systime, sizeof(ts_o));
        }

        if (ts_is_supported(TS_SYS_HARDWARE, TRUE, sock_type))
        {
            if(ts_timespec_is_zero(&ts->hwtimetrans))
                TEST_VERDICT("HW transformed timestamp is zero");
            memcpy(&ts_o, &ts->hwtimetrans, sizeof(ts_o));
        }

        if (ts_is_supported(TS_RAW_HARDWARE, TRUE, sock_type))
        {
            if(ts_timespec_is_zero(&ts->hwtimeraw))
                TEST_VERDICT("Raw HW timestamp is zero");
            memcpy(&ts_o, &ts->hwtimeraw, sizeof(ts_o));
        }
        ts_check_deviation(&ts_o, ts_h, 0, 100000);
    }

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if (cmsg == NULL)
        TEST_VERDICT("Failed to extract the second control message");

    if (cmsg->cmsg_level != socklevel_rpc2h(RPC_SOL_IP) ||
        cmsg->cmsg_type != sockopt_rpc2h(RPC_IP_RECVERR))
        TEST_VERDICT("The second control mesage should be IP_RECVERR, but "
                     "it is %s",
                     sockopt_rpc2str(cmsg_type_h2rpc(cmsg->cmsg_level,
                                                     cmsg->cmsg_type)));

    err = (struct sock_extended_err *)CMSG_DATA(cmsg);
    sockts_print_sock_extended_err(err);
    if (err->ee_errno != ENOMSG ||
        err->ee_origin != SO_EE_ORIGIN_TIMESTAMPING)
        TEST_VERDICT("Bad IP_RECVERR message was retrieved");

    memset(&sa, 0, sizeof(sa));
    if (memcmp(&sa, (struct sockaddr_in *)SO_EE_OFFENDER(err),
               sizeof(sa)) != 0)
        TEST_VERDICT("sockadd in IP_RECVERR control message has "
                     "been changed");

    if ((cmsg = CMSG_NXTHDR(&msg, cmsg)) != NULL)
        TEST_VERDICT("Extra cmsg was extracted: level %d, type %d: %s",
                     cmsg->cmsg_level, cmsg->cmsg_type,
                     sockopt_rpc2str(cmsg_type_h2rpc(cmsg->cmsg_level,
                                                     cmsg->cmsg_type)));

    return err->ee_data;
}

int
main(int argc, char *argv[])
{
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    rpc_socket_type sock_type;
    size_t          packets_num;
    size_t          length_min;
    size_t          length_max;
    int             mtu;
    te_bool         onload_ext;

    char           *sndbuf = NULL;
    char           *recvbuf = NULL;
    size_t          length;
    rpc_msghdr      msg = {.msg_iov = NULL, .msg_control = NULL};
    struct timespec ts_h;
    tarpc_timeval   tv_h = {.tv_sec = 0, .tv_usec = 0};
    te_bool         no_events = FALSE;

    uint32_t count = 0;
    uint32_t ee_data = 0;
    size_t i;
    int flags;
    int iut_s = -1;
    int tst_s = -1;

    te_saved_mtus   iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus   tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(packets_num);
    TEST_GET_INT_PARAM(length_min);
    TEST_GET_INT_PARAM(length_max);
    TEST_GET_INT_PARAM(mtu);
    TEST_GET_BOOL_PARAM(onload_ext);

    if (!onload_ext && !ts_any_event(TRUE, sock_type))
        no_events = TRUE;

    sndbuf = te_make_buf_by_len(length_max);
    recvbuf = te_make_buf_by_len(length_max);
    ts_init_msghdr(TRUE, &msg, length_max + 300);

    TEST_STEP("Set MTU if it is required.");
    if (mtu != 0)
    {
        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                        mtu, &iut_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                        mtu, &tst_mtus));
    }
    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name, &mtu));

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Enable hardware timestamping.");
    flags = RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
        RPC_SOF_TIMESTAMPING_RAW_HARDWARE | RPC_SOF_TIMESTAMPING_SOFTWARE |
        RPC_SOF_TIMESTAMPING_TX_HARDWARE | RPC_SOF_TIMESTAMPING_TX_SOFTWARE |
        RPC_SOF_TIMESTAMPING_OPT_ID;

    if (onload_ext)
        flags |= RPC_ONLOAD_SOF_TIMESTAMPING_STREAM;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_TIMESTAMPING, flags);
    if (rc < 0)
        TEST_VERDICT("setsockopt() failed with %r", RPC_ERRNO(pco_iut));

    rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_RECVERR, 1);

    TEST_STEP("Repeat the following action in the loop @p packets_num times:");
    for (i = 0; i < packets_num; i++)
    {
        length = rand_range(length_min, length_max);;
        TEST_STEP("Send a packet from IUT.");
        rpc_gettimeofday(pco_iut, &tv_h, NULL);
        rpc_send(pco_iut, iut_s, sndbuf, length, 0);
        rc = 0;
        do {
            rc += rpc_recv(pco_tst, tst_s, recvbuf, length_max, 0);
        } while (rc < (int)length);
        USLEEP(100000);

        TEST_STEP("Retrieve and check timestamp, payload data should not be "
                  "returned.");
        TIMEVAL_TO_TIMESPEC(&tv_h, &ts_h);
        memset(msg.msg_control, 0, SOCKTS_CMSG_LEN);
        msg.msg_controllen = SOCKTS_CMSG_LEN;
        if (no_events)
            RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
        if (no_events)
        {
            if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                TEST_VERDICT("recvmsg() had to fail with EAGAIN");
            continue;
        }

        if ((onload_ext && rc != 0) || (!onload_ext && rc == 0))
            TEST_VERDICT("recvmsg() returned unexpected value");

        ee_data = check_msg(&msg, sock_type, onload_ext, &ts_h);
        if (onload_ext)
            continue;

        if (sock_type == RPC_SOCK_STREAM)
        {
            /* The bytes counter starts from zero. */
            if (count + length - (i == 0 ? 1 : 0) != ee_data)
                TEST_VERDICT("Wrong stream bytes counter value");
        }
        else if (ee_data != i)
            TEST_VERDICT("Unexpected datagram number is returned in "
                         "ee_data field");
        count = ee_data;

    }

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_release_msghdr(&msg);
    free(sndbuf);
    free(recvbuf);

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    TEST_END;
}
