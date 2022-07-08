/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 *
 * $Id$
 */

/** @page timestamps-ts_queued_packets Read queued packets after timestamps disabling
 *
 * @objective  Read queued packets after timestamps disabling check
 *             timestamps extracting.
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TST
 * @param tx         Determine is it TX or RX packet handling
 * @param sock_type  Socket type
 * @param length     Packets length
 * @param send_num   Packets number
 * @param iomux      I/O multiplexing function type
 * @param onload_ext Onload extension TCP timestamps
 * @param send_after_disabling  Send more packets after TS disabling
 * @param select_err_queue      Set SO_SELECT_ERR_QUEUE socket option
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_queued_packets"

#include "sockapi-test.h"
#include "timestamps.h"
#include "onload.h"
#include "iomux.h"

/** RPC server handlers */
static rcf_rpc_server *pco_iut = NULL;
static rcf_rpc_server *pco_tst = NULL;

/* If IUT interface is VLAN. */
static te_bool vlan = FALSE;

/**
 * Receive packets and verify timestamps.
 * 
 * @param iut_s     IUT socket
 * @param tst_s     Tester socket
 * @param tx        Determine is it TX or RX packet handling
 * @param sock_type Socket type
 * @param length    Packets length
 * @param mmsg      mmsghdr container
 * @param sndbuf    Send buffers array
 * @param num       Packets number
 * @param num_no_ts Sent packets number after TS disabling
 * @param iomux     I/O multiplexing function type
 * @param onload_ext Onload extension TCP timestamps
 */
static void
receive_packets(int iut_s, int tst_s, te_bool tx, rpc_socket_type sock_type,
                struct rpc_mmsghdr *mmsg, char **sndbuf, int length,
                int num, int num_no_ts, iomux_call_type iomux,
                te_bool onload_ext, te_bool select_err_queue)
{
    struct sock_extended_err *err;
    struct sock_extended_err  template = {.ee_errno = ENOMSG,
                                          .ee_origin = SO_EE_ORIGIN_TIMESTAMPING};
    struct cmsghdr *cmsg;
    char           *rcvbuf = NULL;
    struct timespec ts_o = {0, 0};
    struct timespec ts = {0, 0};
    tarpc_timeval   timeout = {.tv_sec = 0, .tv_usec = 0};
    iomux_evt_fd    event;
    struct sockaddr sa;

    int flags = 0;
    int i;
    int exp;
    int rc;
    int rc_exp;

    memset(&sa, 0, sizeof(sa));
    exp = iomux_init_rd_error(&event, iut_s, iomux, select_err_queue, &rc_exp);

    TEST_STEP("Use flag @c MSG_ERRQUEUE to geather TX timestamps.");
    if (tx)
    {
        flags |= RPC_MSG_ERRQUEUE;
        /** Linux bug (see bug 56326): SO_SELECT_ERR_QUEUE does not work
         *  for TCP. */
        if (select_err_queue && sock_type == RPC_SOCK_STREAM &&
            !tapi_onload_run())
        {
            rc_exp = 1;
            if (iomux == IC_SELECT || iomux == IC_PSELECT)
                exp = EVT_RD;
            else
                exp = EVT_EXC | EVT_ERR;
        }
    }
    else
    {
        exp = EVT_RD;
        rc_exp = 1;
        flags |= RPC_MSG_DONTWAIT;
    }

    for (i = 0; i < num + num_no_ts; i++)
    {
        /** It is needed to set msg_controllen againg in accordance to 
         * rpc_rcvmsg implementation. */
        mmsg->msg_hdr.msg_controllen = SOCKTS_CMSG_LEN;

        if (tx)
        {
            rcvbuf = mmsg->msg_hdr.msg_iov->iov_base;
            if (rpc_recv(pco_tst, tst_s, rcvbuf, length, 0) != length ||
                memcmp(sndbuf[i % num], rcvbuf, length) != 0)
                TEST_FAIL("Bad packet was received");
        }

        if (i < num || !tx)
            IOMUX_CHECK_EXP(rc_exp, exp, event,
                            iomux_call(iomux, pco_iut, &event, 1, &timeout));
        else
            IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

        if (tx && i >= num)
            RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, &mmsg->msg_hdr, flags);

        if (!tx)
        {
            if (mmsg->msg_hdr.msg_controllen != 0)
                TEST_VERDICT("RX timestamp was retrieved, controllen is "
                             "not zero");
            continue;
        }

        if (i < num)
        {
            if (sock_type == RPC_SOCK_STREAM && onload_ext)
            {
                ts_check_cmsghdr(&mmsg->msg_hdr, rc, length, sndbuf[i % num],
                                 tx, sock_type, onload_ext, vlan, &ts_o, &ts);
                continue;
            }

            cmsg = sockts_msg_lookup_control_data(&mmsg->msg_hdr, 0,
                                             sockopt_rpc2h(RPC_IP_RECVERR));
            if (cmsg == NULL)
                TEST_VERDICT("Ancillary message IP_RECVERR was not retrieved");

            err = (struct sock_extended_err *)CMSG_DATA(cmsg);
            sockts_print_sock_extended_err(err);

            if (memcmp(&template, err, sizeof(template)) != 0)
                TEST_VERDICT("Bad IP_RECVERR message was retrieved");

            if (memcmp(&sa, (struct sockaddr_in *)SO_EE_OFFENDER(err),
                       sizeof(sa)) != 0)
                TEST_VERDICT("Unexpected sockadd value in IP_RECVERR "
                             "control message");
            continue;
        }

        if (rc < 0 && RPC_ERRNO(pco_iut) == RPC_EAGAIN)
            continue;

        if (rc >= 0)
            TEST_VERDICT("recvmsg() must fail with EAGAIN for TX ts");
        TEST_VERDICT("recvmsg() failed but with unexpected errno %r",
                     RPC_ERRNO(pco_iut));
    }
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));
}

/**
 * Send packets.
 * 
 * @param iut_s     IUT socket
 * @param tst_s     Tester socket
 * @param tx        Determine is it TX or RX packet handling
 * @param length    Packets length
 * @param sndbuf    Buffers array to be sent
 * @param num       Packets number
 */
static void
send_packets(int iut_s, int tst_s, te_bool tx, int length, char **sndbuf,
             int num)
{
    rcf_rpc_server     *rpcs = pco_tst;
    int                 sock = tst_s;
    int i;

    if (tx)
    {
        rpcs = pco_iut;
        sock = iut_s;
    }

    for (i = 0; i < num; i++)
        if (rpc_send(rpcs, sock, sndbuf[i], length, 0) != length)
                TEST_FAIL("Failed to send full data");
}

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rpc_socket_type        sock_type;
    te_bool                tx;
    struct rpc_mmsghdr    *mmsg = NULL;
    char                 **sndbuf = NULL;
    int                    length;
    int                    send_num;
    te_bool                send_after_disabling;
    iomux_call_type        iomux;
    te_bool                onload_ext;
    te_bool                select_err_queue;

    int iut_s = -1;
    int tst_s = -1;

    int flags;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(tx);
    TEST_GET_INT_PARAM(length);
    TEST_GET_INT_PARAM(send_num);
    TEST_GET_BOOL_PARAM(send_after_disabling);
    TEST_GET_BOOL_PARAM(onload_ext);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(select_err_queue);
    TEST_GET_IF(iut_if);

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    sndbuf = te_calloc_fill(send_num, sizeof(*sndbuf), 0);
    for (i = 0; i < send_num; i++)
        sndbuf[i] = te_make_buf_by_len(length);
    ts_init_mmsghdr(tx, 1, length + (tx ? 300 : 0), &mmsg);

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("Enable @c TCP_NODELAY socket option on the TX socket "
                  "to ensure that TCP packets of specified size are sent.");
        if (tx)
            rpc_setsockopt_int(pco_iut, iut_s, RPC_TCP_NODELAY, 1);
        else
            rpc_setsockopt_int(pco_tst, tst_s, RPC_TCP_NODELAY, 1);
    }

    flags = RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
            RPC_SOF_TIMESTAMPING_RAW_HARDWARE |
            RPC_SOF_TIMESTAMPING_SOFTWARE;

    TEST_STEP("Use @c ONLOAD_SOF_TIMESTAMPING_STREAM flag to retrieve TCP TX "
              "timestamps.");
    if (tx && sock_type == RPC_SOCK_STREAM &&
        tapi_onload_lib_exists(pco_iut->ta))
        flags |= RPC_ONLOAD_SOF_TIMESTAMPING_STREAM;

    TEST_STEP("Depending on @p tx parameter:");
    if (tx)
    {
        TEST_SUBSTEP("Use @c SOF_TIMESTAMPING_TX_HARDWARE flag to retrieve TX "
                     "timestamps.");
        flags |= RPC_SOF_TIMESTAMPING_TX_HARDWARE |
                 RPC_SOF_TIMESTAMPING_TX_SOFTWARE;
    }
    else
    {
        TEST_SUBSTEP("Use @c SOF_TIMESTAMPING_RX_HARDWARE flag to retrieve RX "
                     "timestamps.");
        flags |= RPC_SOF_TIMESTAMPING_RX_HARDWARE |
                 RPC_SOF_TIMESTAMPING_RX_SOFTWARE;
    }

    TEST_STEP("Enable timestamps setting @c SO_TIMESTAMPING socket option with "
              "appropriate flags.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_TIMESTAMPING, flags);
    if (select_err_queue)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SELECT_ERR_QUEUE, 1);

    TEST_STEP("Send a number @p send_num packets.");
    send_packets(iut_s, tst_s, tx, length, sndbuf, send_num);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Disable timestamps.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_TIMESTAMPING, 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Send more packets if @p send_after_disabling is @c TRUE.");
    if (send_after_disabling)
        send_packets(iut_s, tst_s, tx, length, sndbuf, send_num);

    TEST_STEP("Receive the packets and validate timestamps.");
    receive_packets(iut_s, tst_s, tx, sock_type, mmsg, sndbuf, length,
                    send_num, send_after_disabling ? send_num : 0, iomux,
                    onload_ext, select_err_queue);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (sndbuf != NULL)
    {
        for (i = 0; i < send_num; i++)
            free(sndbuf[i]);
        free(sndbuf);
    }

    cleanup_mmsghdr(mmsg, 1);

    TEST_END;
}
