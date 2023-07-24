/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 *
 * $Id$
 */

/** @page timestamps-ts_fin FIN packet timestamps
 *
 * @objective  Try to get timestamps for the FIN packet with or without
 *             data.
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TST
 * @param tx        Determine is it TX or RX packet handling
 * @param data      Send FIN with data
 * @param iomux     I/O multiplexing function type
 * @param onload_ext Onload extension TCP timestamps
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_fin"

#include "sockapi-test.h"
#include "timestamps.h"
#include "onload.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    iomux_call_type iomux;
    te_bool         tx;
    te_bool         onload_ext;

    te_bool                data;
    struct rpc_mmsghdr    *mmsg = NULL;
    char                  *sndbuf = NULL;
    char                  *rcvbuf = NULL;
    size_t                 length;
    iomux_evt_fd           event;
    tarpc_timeval          timeout = {.tv_sec = 0, .tv_usec = 500000};
    te_bool                vlan = FALSE;
    te_bool                zero_reported = FALSE;

    int exp;
    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(tx);
    TEST_GET_BOOL_PARAM(onload_ext);
    TEST_GET_BOOL_PARAM(data);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_IF(iut_if);

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    sndbuf = sockts_make_buf_stream(&length);
    rcvbuf = te_make_buf_by_len(length);
    ts_init_mmsghdr(TRUE, 1, length + (tx ? 300 : 0), &mmsg);

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    exp = iomux_init_rd_error(&event, iut_s, iomux, FALSE, NULL);

    ts_enable_hw_ts(pco_iut, iut_s, RPC_SOCK_STREAM, tx, onload_ext);

    TEST_STEP("In case if @p tx is @c TRUE. Send packet from IUT, check that TX "
              "timestamps are enabled.");
    if (tx)
    {
        RPC_SEND(rc, pco_iut, iut_s, sndbuf, length, 0);
        if (rpc_recv(pco_tst, tst_s, rcvbuf, length, 0) != (int)length ||
            memcmp(sndbuf, rcvbuf, length) != 0)
            TEST_FAIL("Bad packet was received");

        if (ts_any_event(tx, RPC_SOCK_STREAM) || onload_ext)
        {
            IOMUX_CHECK_EXP(1, exp, event,
                            iomux_call(iomux, pco_iut, &event, 1, &timeout));
            rc = rpc_recvmsg(pco_iut, iut_s, &mmsg->msg_hdr, RPC_MSG_ERRQUEUE);
            ts_check_cmsghdr(&mmsg->msg_hdr, rc, length, sndbuf, tx,
                             RPC_SOCK_STREAM, onload_ext, vlan, NULL, NULL);
            ts_check_second_cmsghdr(pco_iut, iut_s, NULL, NULL, NULL, NULL,
                                    FALSE, &zero_reported, NULL);
        }
        else
        {
            IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_recvmsg(pco_iut, iut_s, &mmsg->msg_hdr, RPC_MSG_ERRQUEUE);
            if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                TEST_VERDICT("recvmsg() fail with EAGAIN was expected");

            if (data)
                TEST_SUCCESS;
        }

        TEST_STEP("If @p data is @c TRUE pass data packet to send queue on IUT.");
        if (data)
            RPC_SEND(rc, pco_iut, iut_s, sndbuf, length, RPC_MSG_MORE);

        TEST_STEP("Shutdown IUT socket to send FIN packet.");
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
        TAPI_WAIT_NETWORK;

        memset(&timeout, 0, sizeof(timeout));
        if (data)
            IOMUX_CHECK_EXP(1, exp, event,
                            iomux_call(iomux, pco_iut, &event, 1, &timeout));
        else
            IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

        TEST_STEP("Try to get timestamps.");
        mmsg->msg_hdr.msg_controllen = SOCKTS_CMSG_LEN;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, &mmsg->msg_hdr, RPC_MSG_ERRQUEUE);

        if (!data || (!ts_any_event(tx, RPC_SOCK_STREAM) && !onload_ext))
        {
            if (rc != -1)
            {
                ts_check_cmsghdr(&mmsg->msg_hdr, rc, length, sndbuf, tx,
                                 RPC_SOCK_STREAM, TRUE, vlan, NULL, NULL);
                TEST_VERDICT("recvmsg() must fail with EAGAIN");
            }

            if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                TEST_VERDICT("recvmsg() must fail with EAGAIN, but it failed "
                             "with %r", RPC_ERRNO(pco_iut));
        }
        else
        {
            ts_check_cmsghdr(&mmsg->msg_hdr, rc, length, sndbuf, tx,
                             RPC_SOCK_STREAM, onload_ext, vlan, NULL, NULL);
            zero_reported = FALSE;
            ts_check_second_cmsghdr(pco_iut, iut_s, NULL, NULL, NULL, NULL,
                                    FALSE, &zero_reported, NULL);
        }

        memset(&timeout, 0, sizeof(timeout));
        IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));
    }
    else
    {
        TEST_STEP("In case if @p tx is @c FALSE. Send packet from tester, check that RX "
                  "timestamps are enabled.");

        exp = EVT_RD;
        RPC_SEND(rc, pco_tst, tst_s, sndbuf, length, 0);
        IOMUX_CHECK_EXP(1, exp, event, iomux_call(iomux, pco_iut, &event, 1,
                                                  &timeout));
        rc = rpc_recvmsg(pco_iut, iut_s, &mmsg->msg_hdr, 0);
        ts_check_cmsghdr(&mmsg->msg_hdr, rc, length, sndbuf, tx,
                         RPC_SOCK_STREAM, FALSE, vlan, NULL, NULL);

        TEST_SUBSTEP("If @p data is @c TRUE pass data packet to send queue on tester.");
        if (data)
            RPC_SEND(rc, pco_tst, tst_s, sndbuf, length, RPC_MSG_MORE);

        TEST_SUBSTEP("Shutdown IUT socket to send FIN packet.");
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);
        TAPI_WAIT_NETWORK;

        IOMUX_CHECK_EXP(1, exp, event, iomux_call(iomux, pco_iut, &event, 1,
                                                  &timeout));

        TEST_SUBSTEP("Try to get timestamps.");
        mmsg->msg_hdr.msg_controllen = SOCKTS_CMSG_LEN;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, &mmsg->msg_hdr, RPC_MSG_DONTWAIT);

        if (!data && rc != 0)
            TEST_VERDICT("recvmsg() must returns 0");

        IOMUX_CHECK_EXP(1, exp, event, iomux_call(iomux, pco_iut, &event, 1,
                                                  &timeout));
    }

    TEST_STEP("If @p data is @c TRUE timestamps must be retrieved, "
              "else - must not.");
    if (data)
    {
        if (rc < 0)
            TEST_VERDICT("Timestmp was not retrieved");

        ts_check_cmsghdr(&mmsg->msg_hdr, rc, length, sndbuf, tx,
                         RPC_SOCK_STREAM, onload_ext, vlan, NULL, NULL);
    }

    mmsg->msg_hdr.msg_controllen = SOCKTS_CMSG_LEN;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvmsg(pco_iut, iut_s, &mmsg->msg_hdr, RPC_MSG_DONTWAIT);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    cleanup_mmsghdr(mmsg, 1);
    free(sndbuf);
    free(rcvbuf);

    TEST_END;
}
