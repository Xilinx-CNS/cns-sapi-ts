/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 *
 * $Id$
 */

/** @page timestamps-ts_tx_shut_rd  TX timestamps retrieving after shutdown(RD)
 *
 * @objective  Check that TX timestamps can be retrieved after calling
 *             shutdown() on IUT.
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TST
 * @param sock_type  Socket type
 * @param iomux      I/O multiplexing function type
 * @param onload_ext Onload extension TCP timestamps
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_tx_shut_rd"

#include "sockapi-test.h"
#include "timestamps.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rpc_socket_type sock_type;
    te_bool         onload_ext;
    iomux_call_type iomux;

    char           *sndbuf = NULL;
    size_t          length;
    rpc_msghdr      msg = {.msg_iov = NULL, .msg_control = NULL};
    struct timespec ts;
    struct timespec ts_h;
    tarpc_timeval   tv_h = {.tv_sec = 0, .tv_usec = 0};
    iomux_evt_fd    event;
    tarpc_timeval   timeout = {.tv_sec = 0, .tv_usec = 500000};
    te_bool         vlan = FALSE;

    int exp;
    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(onload_ext);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_IF(iut_if);

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    sndbuf = sockts_make_buf_stream(&length);
    ts_init_msghdr(TRUE, &msg, length + 300);

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    exp = iomux_init_rd_error(&event, iut_s, iomux, FALSE, NULL);
    if (iomux != IC_SELECT && iomux != IC_PSELECT)
        exp |= EVT_RD;

    TEST_STEP("Enable hardware timestamping and TX ACK timestamps.");
    ts_enable_hw_ts(pco_iut, iut_s, sock_type, TRUE, onload_ext);

    TEST_STEP("The socket read ability shutdown.");
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);

    TEST_STEP("Send a packet from IUT.");
    rpc_gettimeofday(pco_iut, &tv_h, NULL);
    rpc_send(pco_iut, iut_s, sndbuf, length, 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Retrieve and check timestamp if any timestamp is supported.");
    if (ts_any_event(TRUE, sock_type) || onload_ext)
    {
        TIMEVAL_TO_TIMESPEC(&tv_h, &ts_h);
        IOMUX_CHECK_EXP(1, exp, event,
                        iomux_call(iomux, pco_iut, &event, 1, &timeout));
        rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
        ts_check_cmsghdr(&msg, rc, length, sndbuf, TRUE, sock_type, onload_ext,
                         vlan, &ts, &ts_h);
        ts_check_deviation(&ts, &ts_h, 0, 100000);
    }
    else
    {
        exp = EVT_RD;
        IOMUX_CHECK_EXP(1, exp, event, iomux_call(iomux, pco_iut, &event, 1,
                                                  &timeout));
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
        if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            TEST_VERDICT("recvmsg() should fail with EAGAIN");
        TEST_SUCCESS;
    }

    timeout.tv_usec = 0;
    exp = EVT_RD;
    IOMUX_CHECK_EXP(1, exp, event,
                    iomux_call(iomux, pco_iut, &event, 1, &timeout));
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
