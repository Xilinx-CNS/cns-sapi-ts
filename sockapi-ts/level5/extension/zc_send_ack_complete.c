/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Onload extensions
 */

/**
 * @page extension-zc_send_ack_complete Getting completion after ACK
 *
 * @objective Check that if onload_zc_send() with user buffer is used,
 *            then completion message arrives only after ACK is received
 *            for a sent buffer.
 *
 * @param env               Network environment configuration:
 *                          - @ref arg_types_env_peer2peer_gw
 *                          - @ref arg_types_env_peer2peer_gw_ipv6
 * @param sock_type         Socket type:
 *                          - @c tcp_active
 *                          - @c tcp_passive
 *                          - @c tcp_passive_close
 *
 * @type Conformance
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/zc_send_ack_complete"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

/** Length of buffer to send */
#define BUF_LEN 1024

/**
 * Maximum time onload_zc_send() call itself may take (not
 * taking into account waiting for completion message),
 * in microseconds.
 */
#define MAX_SEND_DURATION 1000

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    int   iut_s = -1;
    int   iut_l = -1;
    int   tst_s = -1;

    sockts_socket_type          sock_type;
    struct rpc_onload_zc_mmsg   mmsg;
    struct rpc_iovec            iov;
    char                        send_buf[BUF_LEN];
    char                        recv_buf[BUF_LEN * 2];
    int64_t                     duration = -1;
    te_bool                     op_done = FALSE;
    te_bool                     test_failed = FALSE;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    SOCKTS_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Configure gateway connection between IUT and Tester.");
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, &iut_l);

    TEST_STEP("Break connectivity from Tester to gateway, so that "
              "ACK does not arrive on IUT after sending a packet.");
    tapi_route_gateway_break_tst_gw(&gateway);
    CFG_WAIT_CHANGES;

    memset(&mmsg, 0, sizeof(mmsg));
    mmsg.fd = iut_s;

    te_fill_buf(send_buf, sizeof(send_buf));
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = send_buf;
    iov.iov_len = iov.iov_rlen = sizeof(send_buf);

    mmsg.msg.msg_iov = &iov;
    mmsg.msg.msg_iovlen = 1;
    mmsg.msg.msg_riovlen = 1;

    TEST_STEP("Call onload_zc_send(), wait for a while and check that "
              "RPC wrapper still waits for completion for a sent buffer.");
    pco_iut->op = RCF_RPC_CALL;
    rpc_simple_zc_send_gen(pco_iut, &mmsg, 1, 0, -1, TRUE, RPC_NULL,
                           &duration);

    TAPI_WAIT_NETWORK;

    rc = rcf_rpc_server_is_op_done(pco_iut, &op_done);
    if (rc != 0)
    {
        rcf_rpc_server_restart(pco_iut);
        iut_s = -1;
        iut_l = -1;
        TEST_VERDICT("Failed to get status of onload_zc_send() RPC call");
    }
    else if (op_done)
    {
        ERROR_VERDICT("Completion arrived before ACK was received");
        test_failed = TRUE;
    }

    TEST_STEP("Repair connectivity from Tester to gateway, check that "
              "now RPC wrapper for onload_zc_send() terminates successfully.");

    tapi_route_gateway_repair_tst_gw(&gateway);
    CFG_WAIT_CHANGES;

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_simple_zc_send_gen(pco_iut, &mmsg, 1, 0, -1, TRUE, RPC_NULL,
                                &duration);
    if (rc < 0)
    {
        TEST_VERDICT("onload_zc_send() failed with error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }
    else if (mmsg.rc < 0)
    {
        TEST_VERDICT("onload_zc_send() returned -%r in mmsg.rc",
                     -mmsg.rc);
    }
    else if (mmsg.rc != BUF_LEN)
    {
        TEST_VERDICT("onload_zc_send() returned unexpected result");
    }

    if (duration < 0)
    {
        TEST_VERDICT("Failed to measure time it took to call "
                     "onload_zc_send()");
    }
    else if (duration > MAX_SEND_DURATION)
    {
        TEST_VERDICT("onload_zc_send() call itself took too much time");
    }

    TEST_STEP("Receive and check data on Tester.");
    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_recv(pco_tst, tst_s, recv_buf, sizeof(recv_buf), 0);
    SOCKTS_CHECK_RECV(pco_tst, send_buf, recv_buf, BUF_LEN, rc);

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
