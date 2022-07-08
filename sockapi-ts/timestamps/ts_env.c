/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 *
 * $Id$
 */

/** @page timestamps-ts_env  Check env influence to timestamps retrieving
 *
 * @objective  Check env EF_TIMESTAMPING_REPORTING, EF_TX_TIMESTAMPING,
 *             EF_RX_TIMESTAMPING influence to timestamps retrieving.
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TST
 * @param tx         Determine is it TX or RX packet handling
 * @param sock_type  Socket type
 * @param length     Packets length
 * @param num        Packets number
 * @param sync       If it is @c TRUE NICs clock should be synced
 * @param ef_timestamping_reporting  Value to set EF_TIMESTAMPING_REPORTING
 * @param ef_tx_timestamping         Value to set EF_TX_TIMESTAMPING
 * @param ef_rx_timestamping         Value to set EF_RX_TIMESTAMPING
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_env"

#include "sockapi-test.h"
#include "timestamps.h"
#include "tapi_sfptpd.h"

/** Allowed time deviation in microseconds */
#define TST_PRECISION 500000

/** Possible errors */
typedef enum ts_error {
    TS_ERR_OK = 0,
    TS_ERR_FIRST_RECV_EAGAIN,
    TS_ERR_IS_ZERO,
    TS_ERR_HW_RX_TRAN_DIFF,
} ts_error;

/** IUT RPC server handler */
static rcf_rpc_server *pco_iut = NULL;

/** Tester RPC server handler */
static rcf_rpc_server *pco_tst = NULL;

/**
 * Check received cmsg sanity
 * 
 * @param msg       cmsg itself
 * @param rc        Returned bytes number of message payload
 * @param length    Expeted bytes number of message payload
 * @param sndbuf    Buffer with sent data
 * @param tx        Determine is it TX or RX packet handling
 * @param sock_type Socket type
 * @param vlan      IUT is VLAN
 * @param ts_o      Extracted timestamp
 * @param ts_prev   Extracted in the  previous iteration timestamp
 * 
 * @return Status code
 */
static ts_error
check_cmsghdr(rpc_msghdr *msg, int rc, int length, char *sndbuf, te_bool tx,
              rpc_socket_type sock_type, te_bool vlan, struct timespec *ts_o,
              struct timespec *ts_prev)
{
    rpc_onload_scm_timestamping_stream *ts_tx;
    rpc_scm_timestamping *ts;
    struct cmsghdr *cmsg = NULL;
    int hsize = 0;

    if (tx)
    {
        if (sock_type == RPC_SOCK_DGRAM)
            hsize = LINUX_DGRAM_HEADER_LEN;
        else
            hsize = LINUX_TCP_HEADER_LEN;
    }

    if (tx && sock_type == RPC_SOCK_STREAM)
    {
        cmsg = sockts_msg_lookup_control_data(msg, SOL_SOCKET,
                         sockopt_rpc2h(RPC_ONLOAD_SCM_TIMESTAMPING_STREAM));
        if (cmsg == NULL)
            TEST_VERDICT("No control data was received");

        ts_tx = (rpc_onload_scm_timestamping_stream *)CMSG_DATA(cmsg);
        ts_print_tcp_tx(ts_tx);

        if (!ts_timespec_is_zero(&ts_tx->last_sent))
            TEST_VERDICT("last_sent is not zero, probably the packet was "
                         "retransmitted");

        if ((int)ts_tx->len != length)
            TEST_VERDICT("TX timestamp returned wrong segment size");

        memcpy(ts_o, &ts_tx->first_sent, sizeof(*ts_o));
    }
    else
    {
        /** UDP datagram is returned with VLAN addition with Onload, it
         * is thought to be correct, see bug 56367. */
        if (tx && vlan)
            hsize += 4;

        if (rc - hsize != length ||
            memcmp(sndbuf, msg->msg_iov->iov_base + hsize, length) != 0)
            TEST_VERDICT("Bad packet was extracted with timestamps.");

        ts = ts_check_msg_control_data(msg, tx, NULL, NULL);
        ts_print_sys(ts);

        /* SF bug 46396 */
        if (tx && !ts_timespec_is_zero(&ts->systime))
            TEST_VERDICT("systime timestamp field must be 0 for UDP TX");

        if (ts_check_deviation(&ts->hwtimetrans, &ts->hwtimeraw, 0, 1000))
            return TS_ERR_HW_RX_TRAN_DIFF;
        memcpy(ts_o, &ts->hwtimeraw, sizeof(*ts_o));
    }

    if (ts_timespec_is_zero(ts_o))
        return TS_ERR_IS_ZERO;

    if (ts_cmp(ts_prev, ts_o) >= 0)
        RING_VERDICT("Timestamps are not monotonic");
    memcpy(ts_prev, ts_o, sizeof(*ts_prev));

    return TS_ERR_OK;
}

/**
 * Send, receive packet and verify timestamps
 * 
 * @param iut_s     IUT socket
 * @param tst_s     Tester socket
 * @param tx        Determine is it TX or RX packet handling
 * @param sock_type Socket type
 * @param length    Packets length
 * @param num       Packets number
 * @param vlan      IUT is VLAN
 * @param ts_o      Extracted timestamp
 * 
 * @return Status code
 */
static ts_error
send_receive_packet(int iut_s, int tst_s, te_bool tx,
                    rpc_socket_type sock_type, int length, int num,
                    te_bool vlan, struct timespec *ts_o)
{
    struct rpc_mmsghdr *mmsg;
    char               *rcvbuf = NULL;
    char              **sndbuf = NULL;
    struct timespec     ts = {0, 0};

    int rc;
    int flags = 0;
    int i;

    sndbuf = te_calloc_fill(num, sizeof(*sndbuf), 0);

    ts_init_mmsghdr(tx, num,
                    length + (sock_type == RPC_SOCK_DGRAM ? 300 : 0),
                    &mmsg);

    for (i = 0; i < num; i++)
    {
        sndbuf[i] = te_make_buf_by_len(length);

        TEST_STEP("Send a number @p num packets from IUT if TX timestamps are "
                  "tested and from tester if - RX.");
        if (tx)
        {
            rcvbuf = mmsg[i].msg_hdr.msg_iov->iov_base;
            if (rpc_send(pco_iut, iut_s, sndbuf[i], length, 0) != length)
                TEST_FAIL("Failed to send full data");

            TEST_STEP("Receive packets on tester if it is TX ts testing.");
            if (rpc_recv(pco_tst, tst_s, rcvbuf, length, 0) != length ||
                memcmp(sndbuf[i], rcvbuf, length) != 0)
                TEST_FAIL("Bad packet was received.");
        }
        else if (rpc_send(pco_tst, tst_s, sndbuf[i], length, 0) != length)
            TEST_FAIL("Failed to send full data");
    }

    TEST_STEP("Use flag @c MSG_ERRQUEUE to geather TX timestamps.");
    if (tx)
        flags |= RPC_MSG_ERRQUEUE;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    TEST_STEP("Retrieve timestamps of sent/received packets and check they "
              "sanity.");
    for (i = 0; i < num; i++)
    {
        /*
         * It's required to set msg_controllen again because it may
         * be changed by the previous call.
         */
        mmsg[i].msg_hdr.msg_controllen = SOCKTS_CMSG_LEN;

        TAPI_WAIT_TS;
        rc = rpc_recvmsg(pco_iut, iut_s, &mmsg[i].msg_hdr, flags);
        if (rc < 0)
        {
            if (RPC_ERRNO(pco_iut) == RPC_EAGAIN)
            {
                RING("First recvmsg() call returned error with EAGAIN.");
                rc = TS_ERR_FIRST_RECV_EAGAIN;
                goto send_receive_cleanup;
            }
            TEST_VERDICT("First recvmsg() call failed with unexpected "
                         "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
        }

        if ((rc = check_cmsghdr(&mmsg[i].msg_hdr, rc, length, sndbuf[i], tx,
                                sock_type, vlan, ts_o, &ts)) != TS_ERR_OK)
            goto send_receive_cleanup;
    }

    rc = TS_ERR_OK;
send_receive_cleanup:
    cleanup_mmsghdr(mmsg, num);
    for (i = 0; i < num; i++)
        free(sndbuf[i]);
    free(sndbuf);

    return rc;
}

int
main(int argc, char *argv[])
{
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if;
    rpc_socket_type            sock_type;
    te_bool                    tx;
    te_bool                    sync;
    int                        length;
    int                        num;

    int ef_timestamping_reporting;
    int ef_tx_timestamping;
    int ef_rx_timestamping;

    int ef_ts_rep = 0;
    te_bool ef_ts_rep_ext;
    int ef_ts_rx = 0;
    te_bool ef_ts_rx_ext;
    int ef_ts_tx = 0;
    te_bool ef_ts_tx_ext;
    te_bool vlan = FALSE;

    int iut_s = -1;
    int tst_s = -1;
    int timeout = 1;

    struct timespec ts1;
    struct timespec ts2;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(tx);
    TEST_GET_BOOL_PARAM(sync);
    TEST_GET_INT_PARAM(ef_timestamping_reporting);
    TEST_GET_INT_PARAM(ef_tx_timestamping);
    TEST_GET_INT_PARAM(ef_rx_timestamping);
    TEST_GET_INT_PARAM(length);
    TEST_GET_INT_PARAM(num);
    TEST_GET_IF(iut_if);

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    TEST_STEP("Set tested environments combination in dependence on paramaters "
              "@p ef_timestamping_reporting, @p ef_tx_timestamping, "
              "@p ef_rx_timestamping.");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_TIMESTAMPING_REPORTING",
        ef_timestamping_reporting, FALSE, &ef_ts_rep_ext, &ef_ts_rep));
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_TX_TIMESTAMPING",
        ef_tx_timestamping, FALSE, &ef_ts_rx_ext, &ef_ts_rx));
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_RX_TIMESTAMPING",
        ef_rx_timestamping, TRUE, &ef_ts_tx_ext, &ef_ts_tx));

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Enable timestamps setting @c SO_TIMESTAMPING socket option with "
              "appropriate flags.");
    ts_enable_hw_ts(pco_iut, iut_s, sock_type, tx, TRUE);

    TEST_STEP("Send and receive a number @p num packets, virfy timestamps "
              "retrieving results.");
    rc = send_receive_packet(iut_s, tst_s, tx, sock_type, length, num,
                             vlan, &ts1);

#define TS_CHECK_ERR(_cond, _res, _err, _msg...) \
do {                                    \
    if ((_cond))                        \
    {                                   \
        if (_res != _err)               \
            TEST_VERDICT(_msg);         \
        TEST_SUCCESS;                   \
    }                                   \
} while (0)

    TS_CHECK_ERR((tx &&  ef_tx_timestamping == 0),
                 rc, TS_ERR_FIRST_RECV_EAGAIN,
                 "first recvmsg() call must fail with errno EAGAIN");

    TEST_STEP("Check that timestamps retrieving fails as expected.");
    if (sync)
    {
        TS_CHECK_ERR((!tx && ef_rx_timestamping == 0),
                      rc, TS_ERR_IS_ZERO, "Timestamp must be zero");
    }
    else
        TEST_SUCCESS;

    if (rc != TS_ERR_OK)
        TEST_VERDICT("Unhandled error, rc %d", rc);

    TEST_STEP("Sleep 1 second to have approximate known difference between two "
              "timestamps.");
    SLEEP(timeout);

    TEST_STEP("Again send and receive a number @p num packets, virfy timestamps.");
    rc = send_receive_packet(iut_s, tst_s, tx, sock_type, length, num, vlan,
                             &ts2);
    if (rc != TS_ERR_OK)
        TEST_FAIL("Second packet transmission has unhandled error, rc %d", rc);

    TEST_STEP("Check that timestamps of last sent packets of the first and second "
              "packs differ about to @p timeout.");
    if (ts_check_deviation(&ts1, &ts2, timeout * 1000000, TST_PRECISION))
        TEST_VERDICT("Two transmitted packets have unexpected timestamps "
                     "difference");

    TEST_SUCCESS;
cleanup:
    /* Order matters: avoid TIME_WAIT on IUT side */
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_TIMESTAMPING_REPORTING",
                                              ef_ts_rep_ext, ef_ts_rep, FALSE));
    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_TX_TIMESTAMPING",
                                              ef_ts_rx_ext, ef_ts_rx, FALSE));
    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_RX_TIMESTAMPING",
                                              ef_ts_tx_ext, ef_ts_tx, TRUE));

    TEST_END;
}
