/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 *
 * $Id$
 */

/** @page timestamps-ts_select_err_queue  Flag SO_SELECT_ERR_QUEUE usage
 *
 * @objective  Check flag SO_SELECT_ERR_QUEUE sanity
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TST
 * @param sock_type  Socket type
 * @param tx         Determine if it is TX or RX packet handling
 * @param iomux      I/O multiplexing function type
 * @param onload_ext Onload extension TCP timestamps
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_select_err_queue"

#include "sockapi-test.h"
#include "timestamps.h"
#include "onload.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rpc_socket_type sock_type;
    iomux_call_type iomux;
    te_bool         tx;
    te_bool         onload_ext;

    char                  *sndbuf = NULL;
    size_t                 length;
    iomux_evt_fd           event;
    tarpc_timeval          timeout = {.tv_sec = 0, .tv_usec = 500000};
    rpc_msghdr             msg = {.msg_iov = NULL, .msg_control = NULL};
    te_bool                vlan = FALSE;

    int exp_ev = 0;
    int exp_rc = 0;
    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(tx);
    TEST_GET_BOOL_PARAM(onload_ext);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_IF(iut_if);

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    sndbuf = sockts_make_buf_stream(&length);
    ts_init_msghdr(tx, &msg, length + 300);

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    exp_ev = iomux_init_rd_error(&event, iut_s, iomux, TRUE, &exp_rc);
    if (!ts_any_event(tx, sock_type) && !onload_ext)
        exp_rc = 0;

    if (tx)
    {
        /** Linux bug (see bug 56326): SO_SELECT_ERR_QUEUE does not work
         *  for TCP. */
        if (sock_type == RPC_SOCK_STREAM && !tapi_onload_run())
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

    TEST_STEP("Enable hardware timestamping.");
    ts_enable_hw_ts(pco_iut, iut_s, sock_type, tx, onload_ext);

    TEST_STEP("Set socket option SO_SELECT_ERR_QUEUE.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SELECT_ERR_QUEUE, 1);

    TEST_STEP("Send a packet from IUT if @p tx is @c TRUE, else from the tester.");
    if (tx)
        rpc_send(pco_iut, iut_s, sndbuf, length, 0);
    else
        rpc_send(pco_tst, tst_s, sndbuf, length, 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Call iomux function to check events.");
    if (exp_rc > 0)
        IOMUX_CHECK_EXP(exp_rc, exp_ev, event,
                        iomux_call(iomux, pco_iut, &event, 1, &timeout));
    else
        IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

    TEST_STEP("Retrieve and check timestamp.");
    if (exp_rc == 0)
        RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvmsg(pco_iut, iut_s, &msg, tx ? RPC_MSG_ERRQUEUE : 0);
    if (exp_rc == 0)
    {
        if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            TEST_VERDICT("recvmsg() had to fail with EAGAIN");
    }
    else
        ts_check_cmsghdr(&msg, rc, length, sndbuf, tx, sock_type, onload_ext,
                         vlan, NULL, NULL);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_release_msghdr(&msg);
    free(sndbuf);

    TEST_END;
}
