/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 *
 * $Id$
 */

/** @page timestamps-ts_tx_ack  Timestamping flag SOF_TIMESTAMPING_TX_ACK usage
 *
 * @objective  Check if flag SOF_TIMESTAMPING_TX_ACK is used new transmit
 *             timestamp event is generated when ACK is received.
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TST
 * @param sock_type  Socket type
 * @param tx_ack     Set timetamping flag SOF_TIMESTAMPING_TX_ACK
 * @param opt_cmsg   Set timetamping flag SOF_TIMESTAMPING_OPT_CMSG
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_tx_ack"

#include "sockapi-test.h"
#include "timestamps.h"

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rpc_socket_type sock_type;
    te_bool         opt_cmsg;

    rpc_scm_timestamping *ts_tx = NULL;
    char           *sndbuf = NULL;
    size_t          length;
    rpc_msghdr      msg = {.msg_iov = NULL, .msg_control = NULL};
    struct timespec ts;
    struct timespec ts_h;
    tarpc_timeval   tv_h = {.tv_sec = 0, .tv_usec = 0};
    te_bool         tx_ack;
    te_bool         vlan = FALSE;
    te_bool         zero_reported = FALSE;

    int flags;
    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(tx_ack);
    TEST_GET_BOOL_PARAM(opt_cmsg);
    TEST_GET_IF(iut_if);

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    sndbuf = sockts_make_buf_stream(&length);
    ts_init_msghdr(TRUE, &msg, length + 300);

    if (!ts_any_event(TRUE, sock_type))
    {
        RING("This timestamp type is not supported");
        TEST_SUCCESS;
    }

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Enable hardware timestamping and TX ACK timestamps with flag "
              "@c SOF_TIMESTAMPING_TX_ACK.");
    flags = RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
            RPC_SOF_TIMESTAMPING_RAW_HARDWARE |
            RPC_SOF_TIMESTAMPING_SOFTWARE |
            RPC_SOF_TIMESTAMPING_TX_HARDWARE |
            RPC_SOF_TIMESTAMPING_TX_SOFTWARE;

    if (!tapi_onload_run())
        flags |= RPC_SOF_TIMESTAMPING_OPT_TX_SWHW;

    if (tx_ack)
        flags |= RPC_SOF_TIMESTAMPING_TX_ACK;

    TEST_STEP("Check that flag @c SOF_TIMESTAMPING_OPT_CMSG is ignored.");
    if (opt_cmsg)
        flags |= RPC_SOF_TIMESTAMPING_OPT_CMSG;

    if (tx_ack || opt_cmsg)
        RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_TIMESTAMPING, flags);
    if (rc < 0)
    {
        if (tx_ack && !tapi_getenv_bool("IUT_TS_TX_ACK"))
        {
            RING("Option SOF_TIMESTAMPING_TX_ACK is not supported");
            TEST_SUCCESS;
        }
        else if (opt_cmsg && !tapi_getenv_bool("IUT_TS_OPT_CMSG"))
        {
            RING("Option SOF_TIMESTAMPING_OPT_CMSG is not supported");
            TEST_SUCCESS;
        }

        TEST_VERDICT("setsockopt() failed with %r", RPC_ERRNO(pco_iut));
    }

    TEST_STEP("Send a packet from IUT.");
    rpc_gettimeofday(pco_iut, &tv_h, NULL);
    rpc_send(pco_iut, iut_s, sndbuf, length, 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Retrieve and check timestamp, payload data should not be returned.");
    TIMEVAL_TO_TIMESPEC(&tv_h, &ts_h);
    rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
    if (opt_cmsg)
    {
        ts_check_cmsghdr_addr(&msg, rc, length, length, sndbuf, TRUE,
                              sock_type, FALSE, vlan, TRUE, iut_addr,
                              &ts, &ts_h);
    }
    else
    {
        ts_check_cmsghdr(&msg, rc, length, sndbuf, TRUE, sock_type, FALSE,
                         vlan, &ts, &ts_h);
    }
    ts_check_deviation(&ts, &ts_h, 0, 100000);
    TIMEVAL_TO_TIMESPEC(&tv_h, &ts_h);
    ts_check_second_cmsghdr(pco_iut, iut_s, NULL, &ts_h,
                            opt_cmsg ? iut_addr : NULL, NULL, FALSE,
                            &zero_reported, NULL);

    TEST_STEP("Check that TX ACK event is generated for TCP packets.");
    if (tx_ack && sock_type == RPC_SOCK_STREAM)
    {
        memset(msg.msg_control, 0, SOCKTS_CMSG_LEN);
        msg.msg_controllen = SOCKTS_CMSG_LEN;
        rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
        ts_tx = ts_get_tx_ack_ts(&msg, rc, length, sndbuf);

        ts_check_deviation(&ts_tx->systime, &ts_h, 0, 100000);
        ts_timespec_is_zero(&ts_tx->hwtimetrans);
        ts_timespec_is_zero(&ts_tx->hwtimeraw);

        RING("Transmitted packet ACK waiting time %lld microseconds",
             ts_timespec_diff_us(&ts, &ts_tx->systime));
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    memset(msg.msg_control, 0, SOCKTS_CMSG_LEN);
    msg.msg_controllen = SOCKTS_CMSG_LEN;
    rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
    if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        TEST_VERDICT("recvmsg() should fail with EAGAIN");

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_release_msghdr(&msg);
    free(sndbuf);

    TEST_END;
}
