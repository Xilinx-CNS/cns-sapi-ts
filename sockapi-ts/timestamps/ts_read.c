/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Timestamps
 */

/** @page timestamps-ts_read Retrieve timestamps in blocking and non-blocking modes
 *
 * @objective  Check TX and RX timestamps values which are retrieved in
 *             blocking or non-blocking modes.
 *
 * @type Conformance.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 * @param tx                If @c TRUE, check TX timestamps, otherwise
 *                          check RX
 * @param sock_type         Socket type:
 *                          - @c SOCK_STREAM
 *                          - @c SOCK_DGRAM
 * @param length            Packets length:
 *                          - @c 1000
 * @param num               Packets number:
 *                          - @c 1
 *                          - @c 3
 * @param func              Function to retrieve timestamps:
 *                          - @b recvmsg()
 *                          - @b recvmmsg()
 *                          - @b onload_zc_recv()
 *                          - @b onload_zc_hlrx_recv_copy()
 * @param blocking          Call @p func in a blocking mode if @c TRUE
 * @param iomux             I/O multiplexing function type:
 *                          - @b select()
 *                          - @b pselect()
 *                          - @b poll()
 *                          - @b ppoll()
 *                          - @b epoll()
 *                          - @b epoll_pwait()
 *                          - @b oo_epoll()
 * @param onload_ext        If @c TRUE, check Onload extension TCP
 *                          timestamps
 * @param select_err_queue  If @c TRUE, set @c SO_SELECT_ERR_QUEUE socket
 *                          option
 * @param opt_before_bind   If @c TRUE, set @c SO_TIMESTAMPING option on
 *                          IUT socket before binding it.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_read"

#include "sockapi-test.h"
#include "timestamps.h"
#include "iomux.h"
#include "onload.h"

/**
 * Tested function list
 */
typedef enum {
    FUNC_RECVMSG = 0,       /**< Call recvmsg() function to retrieve ts */
    FUNC_RECVMMSG,          /**< Call recvmmsg() function to retrieve ts */
    FUNC_ZC_RECV,           /**< Call onload_zc_recv() function to
                                 retrieve ts */
    FUNC_ZC_HLRX_RECV_COPY, /**< Call onload_zc_hlrx_recv_copy() function to
                                 retrieve ts */
} test_functions;

#define FUNCS_MAP  \
    { "recvmsg", FUNC_RECVMSG },  \
    { "recvmmsg", FUNC_RECVMMSG }, \
    { "onload_zc_recv", FUNC_ZC_RECV }, \
    { "onload_zc_hlrx_recv_copy", FUNC_ZC_HLRX_RECV_COPY }

/** Allowed time deviation in microseconds */
#define TST_PRECISION 500000

/** RPC server handlers */
static rcf_rpc_server *pco_iut = NULL;
static rcf_rpc_server *pco_iut_aux = NULL;
static rcf_rpc_server *pco_tst = NULL;

/** IUT interface handler. */
static const struct if_nameindex *iut_if;

/**
 * Send, receive packet and verify timestamps
 * 
 * @param iut_s     IUT socket
 * @param tst_s     Tester socket
 * @param tx        Determine is it TX or RX packet handling
 * @param sock_type Socket type
 * @param blocking  Use blocking mode if @c TRUE
 * @param length    Packets length
 * @param num       Packets number
 * @param func      Function to retrieve timestamps
 * @param iomux     I/O multiplexing function type
 * @param onload_ext        Onload extension TCP timestamps
 * @param select_err_queue  Set SO_SELECT_ERR_QUEUE socket option
 */
static void
send_receive_packet(int iut_s, int tst_s, te_bool tx,
                    rpc_socket_type sock_type, te_bool blocking, int length,
                    int num, test_functions func, iomux_call_type iomux,
                    te_bool onload_ext, te_bool select_err_queue)
{
    struct rpc_mmsghdr *mmsg;
    struct rpc_msghdr   args_msg;
    struct rpc_msghdr  *checked_msg;
    char               *rcvbuf = NULL;
    char              **sndbuf = NULL;
    struct timespec     ts = {0, 0};
    struct timespec     tsh;
    struct timespec     ts_o;
    struct tarpc_timeval *tv;
    iomux_evt_fd         event;
    tarpc_timeval        timeout = {.tv_sec = 0, .tv_usec = 500000};
    te_bool              any_event = ts_any_event(tx, sock_type) ||
                                     onload_ext || !tx;

    te_bool vlan = FALSE;

    int exp_rc;
    int exp_ev;
    int rc;
    int flags = 0;
    int i;

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    exp_ev = iomux_init_rd_error(&event, iut_s, iomux, select_err_queue,
                                 &exp_rc);
    if (tx)
    {
        /** Linux bug (see bug 56326): SO_SELECT_ERR_QUEUE does not work
         *  for TCP. */
        if (select_err_queue && sock_type == RPC_SOCK_STREAM &&
            !tapi_onload_run())
        {
            exp_rc = 1;
            if (iomux == IC_SELECT || iomux == IC_PSELECT)
                exp_ev = EVT_RD;
            else
                exp_ev = EVT_EXC | EVT_ERR;
        }
    }
    else
    {
        exp_ev = EVT_RD;
        exp_rc = 1;
    }

    sndbuf = te_calloc_fill(num, sizeof(*sndbuf), 0);
    tv = te_calloc_fill(num, sizeof(*tv), 0);

    ts_init_mmsghdr(tx, num, length + (tx ? 300 : 0), &mmsg);
    ts_init_msghdr(tx, &args_msg, 0);

    if (tx)
        flags |= RPC_MSG_ERRQUEUE;

    if (!blocking)
        flags |= RPC_MSG_DONTWAIT;

    /* recvmmsg() with TCP is not supported by Onload. */
    if (sock_type == RPC_SOCK_STREAM && func == FUNC_RECVMMSG &&
        tapi_onload_lib_exists(pco_iut->ta))
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmmsg_alt(pco_iut, iut_s, mmsg, num, flags, NULL);
        if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_ENOSYS)
        {
            TEST_VERDICT("recvmmsg failure with ENOSYS was expected, but "
                         "rc is %d and errno %s", rc,
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }

        TEST_SUCCESS;
    }

    RING("Call receiving function. In blocking mode for RX timestamps it "
         "must hang and wait for the event. In other cases the call must "
         "fail with errno @c EAGAIN.");
    if (!tx && blocking)
    {
        pco_iut->op = RCF_RPC_CALL;
        if (func == FUNC_RECVMMSG)
        {
            rpc_recvmmsg_alt(pco_iut, iut_s, mmsg, num, flags, NULL);
        }
        else if (func == FUNC_RECVMSG)
        {
            rpc_recvmsg(pco_iut, iut_s, &mmsg[0].msg_hdr, flags);
        }
        else if (func == FUNC_ZC_HLRX_RECV_COPY)
        {
            rpc_simple_hlrx_recv_copy(pco_iut, iut_s, &mmsg[0].msg_hdr, flags,
                                      TRUE);
        }
        else
        {
            rpc_simple_zc_recv(pco_iut, iut_s, &mmsg[0].msg_hdr, flags);
        }
    }
    else
    {
        RPC_AWAIT_ERROR(pco_iut);
        if (func == FUNC_RECVMMSG)
        {
            rc = rpc_recvmmsg_alt(pco_iut, iut_s, mmsg, num, flags, NULL);
        }
        else if (func == FUNC_RECVMSG)
        {
            rc = rpc_recvmsg(pco_iut, iut_s, &mmsg[0].msg_hdr, flags);
        }
        else if (func == FUNC_ZC_HLRX_RECV_COPY)
        {
            rc = rpc_simple_hlrx_recv_copy(pco_iut, iut_s, &mmsg[0].msg_hdr,
                                           flags, TRUE);
        }
        else
        {
            rc = rpc_simple_zc_recv(pco_iut, iut_s, &mmsg[0].msg_hdr,
                                    flags);
        }

        if (rc >= 0)
        {
            TEST_VERDICT("Receive function succeeded instead of failing "
                         "with RPC_EAGAIN before events were generated");
        }
        else if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        {
            TEST_VERDICT("Receive function failed with unexpected error "
                         RPC_ERROR_FMT " instead of RPC_EAGAIN before "
                         "events were generated",
                         RPC_ERROR_ARGS(pco_iut));
        }
    }

    RING("Send @p num packets from IUT if TX timestamps are "
         "tested or from Tester if RX ones are tested.");
    for (i = 0; i < num; i++)
    {
        sndbuf[i] = te_make_buf_by_len(length);

        /** It is needed to set msg_controllen againg in accordance to 
         * rpc_rcvmsg implementation. */
        mmsg[i].msg_hdr.msg_controllen = SOCKTS_CMSG_LEN;

        rpc_gettimeofday(pco_iut_aux, &tv[i], NULL);
        if (tx)
        {
            rcvbuf = mmsg[i].msg_hdr.msg_iov->iov_base;
            if (rpc_send(pco_iut_aux, iut_s, sndbuf[i], length, 0) != length)
                TEST_FAIL("Failed to send full data");

            if (rpc_recv(pco_tst, tst_s, rcvbuf, length, 0) != length ||
                memcmp(sndbuf[i], rcvbuf, length) != 0)
                TEST_FAIL("Bad packet was received.");
            TAPI_WAIT_TS;
        }
        else if (rpc_send(pco_tst, tst_s, sndbuf[i], length, 0) != length)
        {
            TEST_FAIL("Failed to send full data");
        }
    }

    if (!tx && blocking)
        pco_iut->op = RCF_RPC_WAIT;

    RING("Retrieve timestamps of sent/received packets and check their "
         "sanity.");
    if (func != FUNC_RECVMMSG)
    {
        for (i = 0; i < num; i++)
        {
            if (!blocking || i > 0)
            {
                if (any_event)
                    IOMUX_CHECK_EXP(exp_rc, exp_ev, event,
                                    iomux_call(iomux, pco_iut, &event, 1,
                                               &timeout));
                else
                    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1,
                                                &timeout));
            }

            RPC_AWAIT_ERROR(pco_iut);

            checked_msg = &mmsg[i].msg_hdr;
            if (func == FUNC_RECVMSG)
            {
                rc = rpc_recvmsg(pco_iut, iut_s, &mmsg[i].msg_hdr, flags);
            }
            else if (func == FUNC_ZC_HLRX_RECV_COPY)
            {
                rc = rpc_simple_hlrx_recv_copy(pco_iut, iut_s,
                                               &mmsg[i].msg_hdr,
                                               flags, TRUE);
            }
            else
            {
                /*
                 * In case of Onload TCP TX timestamps, callback passed to
                 * onload_zc_recv() is not called at all, however timestamp
                 * is reported in args.msg.msghdr.
                 */
                rc = rpc_simple_zc_recv_gen_mmsg(
                                            pco_iut, iut_s, &mmsg[i], 1,
                                            &args_msg, flags, NULL, TRUE);
                if (rc == 0)
                {
                    if (!tx || !onload_ext)
                    {
                        TEST_VERDICT("onload_zc_recv() did not return any "
                                     "messages but succeeded");
                    }
                    checked_msg = &args_msg;
                }
                else if (rc > 0 && tx && onload_ext)
                {
                    TEST_VERDICT("onload_zc_recv() unexpectedly returned "
                                 "a message when it should receive TCP TX "
                                 "timestamp");
                }

                if (rc > 0)
                    rc = mmsg[i].msg_len;
            }

            if (!any_event)
            {
                if (rc >= 0)
                {
                    TEST_VERDICT("Receive function succeeded instead of "
                                 "failing with RPC_EAGAIN when no events "
                                 "are expected");
                }
                else if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                {
                    TEST_VERDICT("Receive function failed with unexpected "
                                 "error " RPC_ERROR_FMT " instead of "
                                 "RPC_EAGAIN when no events are expected",
                                 RPC_ERROR_ARGS(pco_iut));
                }
            }
            else if (rc < 0)
            {
                TEST_VERDICT("Receive function failed with unexpected "
                             "error " RPC_ERROR_FMT " instead of "
                             "receiving expected events",
                             RPC_ERROR_ARGS(pco_iut));
            }

            if (rc >= 0)
            {
                ts_check_cmsghdr(checked_msg, rc, length, sndbuf[i], tx,
                                 sock_type, onload_ext, vlan, &ts_o, &ts);
                TIMEVAL_TO_TIMESPEC(&tv[i], &tsh);
                if (checked_msg->msg_controllen > 0 &&
                    ts_check_deviation(&ts_o, &tsh, 0, TST_PRECISION * 2))
                {
                    TEST_VERDICT("HW timestamp differs from the host time "
                                 "too much");
                }
            }
        }
    }
    else
    {
        if (!blocking)
            IOMUX_CHECK_EXP(exp_rc, exp_ev, event,
                            iomux_call(iomux, pco_iut, &event, 1, &timeout));
        rc = rpc_recvmmsg_alt(pco_iut, iut_s, mmsg, num, flags, NULL);
        if (rc != num)
            TEST_VERDICT("Unexpected events number was received.");

        for (i = 0; i < num; i++)
        {
            ts_check_cmsghdr(&mmsg[i].msg_hdr, mmsg[i].msg_len, length,
                             sndbuf[i], tx, sock_type, onload_ext, vlan,
                             &ts_o, &ts);
            TIMEVAL_TO_TIMESPEC(&tv[i], &tsh);
            if (mmsg[i].msg_hdr.msg_controllen > 0 &&
                ts_check_deviation(&ts_o, &tsh, 0, TST_PRECISION * 2))
                TEST_VERDICT("HW timestamp differs from the host time too much");
        }
    }

    memset(&timeout, 0, sizeof(timeout));
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

    cleanup_mmsghdr(mmsg, num);

    for (i = 0; i < num; i++)
        free(sndbuf[i]);
    free(sndbuf);
    free(tv);
}

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rpc_socket_type        sock_type;
    te_bool                tx;
    te_bool                blocking;
    int                    length;
    int                    num;
    test_functions         func;
    iomux_call_type        iomux;
    te_bool                onload_ext;
    te_bool                select_err_queue;
    te_bool                opt_before_bind;

    int iut_s = -1;
    int tst_s = -1;
    int flags;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(onload_ext);
    TEST_GET_BOOL_PARAM(tx);
    TEST_GET_BOOL_PARAM(blocking);
    TEST_GET_INT_PARAM(length);
    TEST_GET_INT_PARAM(num);
    TEST_GET_ENUM_PARAM(func, FUNCS_MAP);
    TEST_GET_IF(iut_if);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(select_err_queue);
    TEST_GET_BOOL_PARAM(opt_before_bind);

    if (blocking)
    {
        TEST_STEP("If @p blocking is @c TRUE, create a thread "
                  "@b pco_iut_aux on IUT. It will be used to obtain host "
                  "time and send packets on IUT while @p func is blocked "
                  "on @b pco_iut.");
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "iut_thread",
                                              &pco_iut_aux));
    }
    else
    {
        pco_iut_aux = pco_iut;
    }

    TEST_STEP("Initialize @b flags to @c SOF_TIMESTAMPING_SYS_HARDWARE | "
              "@c SOF_TIMESTAMPING_RAW_HARDWARE | "
              "@c SOF_TIMESTAMPING_TX_SOFTWARE | "
              "@c SOF_TIMESTAMPING_SOFTWARE.");
    flags = RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
            RPC_SOF_TIMESTAMPING_RAW_HARDWARE |
            RPC_SOF_TIMESTAMPING_TX_SOFTWARE |
            RPC_SOF_TIMESTAMPING_SOFTWARE;

    TEST_STEP("If @p tx and @p onload_ext are @c TRUE and @p sock_type "
              "is @c SOCK_STREAM, add to @b flags "
              "@c ONLOAD_SOF_TIMESTAMPING_STREAM.");
    if (tx && sock_type == RPC_SOCK_STREAM && onload_ext)
        flags |= RPC_ONLOAD_SOF_TIMESTAMPING_STREAM;

    if (tx)
    {
        TEST_STEP("If @p tx is @c TRUE, add to @b flags "
                  "@c SOF_TIMESTAMPING_TX_HARDWARE.");
        flags |= RPC_SOF_TIMESTAMPING_TX_HARDWARE;
    }
    else
    {
        TEST_STEP("If @p tx is @c FALSE, add to @b flags "
                  "@c SOF_TIMESTAMPING_RX_HARDWARE.");
        flags |= RPC_SOF_TIMESTAMPING_RX_HARDWARE;
    }

    if (opt_before_bind)
    {
        TEST_STEP("If @p opt_before_bind is @c TRUE, create a socket "
                  "of type @p sock_type on IUT.");
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);
    }
    else
    {
        TEST_STEP("If @p opt_before_bind is @c FALSE, create a pair of "
                  "connected sockets of type @p sock_type on IUT and "
                  "Tester.");
        GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &iut_s, &tst_s);
    }

    TEST_STEP("Enable timestamps setting @c SO_TIMESTAMPING socket option "
              "with @b flags on the IUT socket.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_TIMESTAMPING, flags);

    TEST_STEP("If @p select_err_queue, enable @c SO_SELECT_ERR_QUEUE "
              "socket option on the IUT socket.");
    if (select_err_queue)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SELECT_ERR_QUEUE, 1);

    if (opt_before_bind)
    {
        TEST_STEP("If @p opt_before_bind is @c TRUE, create a socket of "
                  "type @p sock_type on Tester and establish connection "
                  "between IUT and Tester sockets.");
        sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr,
                          (sock_type == RPC_SOCK_DGRAM ?
                              SOCKTS_SOCK_UDP : SOCKTS_SOCK_TCP_ACTIVE),
                          FALSE, TRUE, NULL, &iut_s, &tst_s, NULL,
                          SOCKTS_SOCK_FUNC_SOCKET);
    }

    TEST_STEP("Send and receive @p num packets, retrieving timestamps with "
              "@p func and checking that they match host time. Use "
              "@p iomux to check whether timestamp is received.");
    send_receive_packet(iut_s, tst_s, tx, sock_type, blocking, length, num,
                        func, iomux, onload_ext, select_err_queue);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (pco_iut_aux != pco_iut)
        rcf_rpc_server_destroy(pco_iut_aux);

    TEST_END;
}
