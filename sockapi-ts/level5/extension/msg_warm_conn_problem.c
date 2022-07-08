/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Onload extensions
 */

/**
 * @page level5-extension-msg_warm_conn_problem Using MSG_WARM while there is a connection problem
 *
 * @objective Check that using @c ONLOAD_MSG_WARM flag is harmless
 *            when there is a connection problem.
 *
 * @param sock_type   Socket type:
 *                    - tcp active
 *                    - tcp passive
 * @param func        Testing send function:
 *                    - send
 *                    - sendto
 *                    - sendmsg
 *                    - onload_zc_send
 * @param status      Connection status:
 *                    - refused (RST in answer to a sent data packet)
 *                    - timeout (connection is aborted by RTO)
 *                    - delayed (ACK is not received yet)
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/msg_warm_conn_problem"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "tapi_sockets.h"

/** Value to set for tcp_retries2 to get connection timeout faster. */
#define RETRIES2_NUM 1

/**
 * For how long to wait until connection is closed due to timeout,
 * seconds.
 */
#define CLOSE_TIMEOUT 30

/**
 * For how long to wait before restoring network connection if
 * ACK should be delayed, milliseconds.
 */
#define DELAY_TIMEOUT 500

/**
 * Length of buffer to pass to send function.
 */
#define PKT_LEN 1000

/**
 * Length of buffer used for receiving data.
 */
#define RX_BUF_SIZE  (2 * PKT_LEN)

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    int   iut_s = -1;
    int   tst_s = -1;

    char      tx_buf[PKT_LEN];
    te_dbuf   rx_buf[RX_BUF_SIZE];

    int exp_errno;
    int opt_error;

    sockts_socket_type      sock_type;
    rpc_send_f              func;
    sockts_conn_problem_t   status;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_SEND_FUNC(func);
    TEST_GET_ENUM_PARAM(status, SOCKTS_CONN_PROBLEM_MAPPING_LIST);

    TEST_STEP("If @p status is @c timeout tune @c tcp_retries2.");
    if (status == SOCKTS_CONN_TIMEOUT)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES2_NUM, NULL,
                                         "net/ipv4/tcp_retries2"));
        rcf_rpc_server_restart(pco_iut);
    }

    TEST_STEP("Configure gateway connecting IUT and Tester.");
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Break channel IUT->tester using gateway if @p status is "
              "not @c refused.");
    if (status != SOCKTS_CONN_REFUSED)
    {
        tapi_route_gateway_break_gw_tst(&gateway);
        CFG_WAIT_CHANGES;
    }

    TEST_STEP("Send a data packet from IUT.");
    te_fill_buf(tx_buf, PKT_LEN);
    rpc_send(pco_iut, iut_s, tx_buf, PKT_LEN, 0);

    switch (status)
    {
        case SOCKTS_CONN_REFUSED:
            TEST_STEP("If @p status is @c refused close tester socket.");
            TAPI_WAIT_NETWORK;
            RPC_CLOSE(pco_tst, tst_s);
            TAPI_WAIT_NETWORK;
            exp_errno = RPC_ECONNRESET;
            break;

        case SOCKTS_CONN_TIMEOUT:
            TEST_STEP("If @p status is @c timeout wait until connection "
                      "is dropped.");
            sockts_wait_socket_closing(pco_iut, iut_addr, tst_addr,
                                       CLOSE_TIMEOUT);
            exp_errno = RPC_ETIMEDOUT;
            break;

        case SOCKTS_CONN_DELAYED:
            TEST_STEP("If @p status is @c delayed sleep for @c DELAY_TIMEOUT.");
            MSLEEP(DELAY_TIMEOUT);
            exp_errno = RPC_EOK;
            break;

        default:
            TEST_FAIL("Unexpected value of status parameter");
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_error);
    if (opt_error != exp_errno)
        ERROR_VERDICT("SO_ERROR unexpectedly reported %r instead of %r",
                      opt_error, exp_errno);

    TEST_STEP("Call @p func with @c ONLOAD_MSG_WARM. The call should fail "
              "if @p status is @c timeout or @c refused.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, tx_buf, PKT_LEN, RPC_MSG_WARM);
    if (status == SOCKTS_CONN_DELAYED)
    {
        if (rc < 0)
            TEST_VERDICT("Tested function with ONLOAD_MSG_WARM "
                         "unexpectedly failed with errno %r",
                         RPC_ERRNO(pco_iut));
    }
    else
    {
        if (rc >= 0)
        {
            TEST_VERDICT("Tested function with ONLOAD_MSG_WARM "
                         "unexpectedly succeeded");
        }
        else
        {
            /* See SF bug 67748 for explanation of EPIPE. */
            if (RPC_ERRNO(pco_iut) != RPC_EPIPE)
                ERROR_VERDICT("Tested function failed with unexpected "
                              "errno %r; expected errno is %r",
                              RPC_ERRNO(pco_iut), RPC_EPIPE);
        }
    }

    TEST_STEP("Repair the connection if required.");
    if (status != SOCKTS_CONN_REFUSED)
    {
        tapi_route_gateway_repair_gw_tst(&gateway);
        CFG_WAIT_CHANGES;
    }

    TEST_STEP("If @p status is @c delayed:");
    if (status == SOCKTS_CONN_DELAYED)
    {
        TEST_SUBSTEP("Read all data on tester, check it for corruption.");
        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, rx_buf, RX_BUF_SIZE, 0);

        if (rc < 0)
            TEST_VERDICT("recv() failed on Tester with errno %r",
                         RPC_ERRNO(pco_tst));
        else if (rc != PKT_LEN ||
                 memcmp(tx_buf, rx_buf, PKT_LEN) != 0)
            TEST_VERDICT("Data sent from IUT does not match data "
                         "received on Tester");

        TAPI_WAIT_NETWORK;
        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, rx_buf, RX_BUF_SIZE,
                      RPC_MSG_DONTWAIT);
        if (rc > 0)
            TEST_VERDICT("Unexpected extra data was received from IUT");
        else if (rc == 0)
            TEST_VERDICT("The last recv() on Tester returned zero");
        else if (RPC_ERRNO(pco_tst) != RPC_EAGAIN)
            TEST_VERDICT("The last recv() on Tester failed with "
                         "unexpected errno %r", RPC_ERRNO(pco_tst));

        TEST_SUBSTEP("Send some data in both directions, read and check it.");
        sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
