/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page tcp-connect_impossible Not satisfied connect()
 *
 * @objective Check behaviour of @b connect() on socket of
 *            @c SOCK_STREAM type in case if server can not satisfy
 *            request or unreachable.
 *
 * @type Conformance, compatibility
 *
 *
 * @param pco_iut       PCO on IUT
 * @param check         EHOSTUNREACH or ETIMEDOUT or ECONNREFUSED
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut of @c SOCK_STREAM type;
 * -# Bind @p iut_s and @p tst_s to local address;
 * -# Get unoccupied @p gw_fake_addr from @p net;
 * -# Prepare needed test conditions according to @p check;
 * -# Assign @p conn_addr variable to @p tst_addr in case @p check is
 *    @c ECONNREFUSED and to @p gw_fake_addr in other cases;
 * -# Call @b connect() to connect @p iut_s to the @p conn_addr socket address;
 * -# Check that @b connect returns -1 and errno set according to
 *    @p check;
 * -# Try to send/receive on @p iut_s socket, check errors.
 * -# Close created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/connect_impossible"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"

#include "tcp_test_macros.h"

/* SYN retransmits number. */
#define SYN_RETRIES_NUM 3

/* Timeout waiting for connection drop by SYN retransmits, dependent on
 * @p SYN_RETRIES_NUM . */
#define TST_CONNECT_TIMEOUT 20000

#define DATA_BULK       1024  /**< Size of data to be sent */
static uint8_t data_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    const struct sockaddr      *gw_fake_addr = NULL;
    const char                 *check;

    const struct sockaddr   *conn_addr;

    int iut_s = -1;
    int err_code;

    /* Preambule */
    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ADDR(pco_tst, gw_fake_addr);
    TEST_GET_STRING_PARAM(check);

    /* Tune SYN retransmits number to decrease waiting time. */
    if (strcmp(check, "ETIMEDOUT") == 0)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, SYN_RETRIES_NUM, NULL,
                                         "net/ipv4/tcp_syn_retries"));
        rcf_rpc_server_restart(pco_iut);
    }

    TAPI_INIT_ROUTE_GATEWAY(gw);
    CHECK_RC(tapi_route_gateway_configure(&gw));

    /* Create socket */
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);

    /* Prerare test conditions */
    TCP_TEST_RESOLVE_ERROR(check, err_code, conn_addr);

    pco_iut->timeout = TST_CONNECT_TIMEOUT;
    RPC_AWAIT_IUT_ERROR(pco_iut);

    /* Try to connect */
    rc = rpc_connect(pco_iut, iut_s, conn_addr);
    if (rc != -1)
        TEST_FAIL("connect() returns %d instead of -1 when "
                  "server can not satisfy connection request", rc);

    CHECK_RPC_ERRNO(pco_iut, err_code,
                    "connect() returns -1, but");

    /* Try to send/receive */
    TAPI_CALL_CHECK_RC(pco_iut, send, -1, RPC_EPIPE,
                       iut_s, data_buf, DATA_BULK, 0);

    TAPI_CALL_CHECK_RC(pco_iut, recv, -1, RPC_ENOTCONN,
                       iut_s, data_buf, DATA_BULK, 0);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (strcmp(check, "ETIMEDOUT") == 0)
        update_arp(pco_tst, tst_if, pco_gw, gw_tst_if, gw_tst_addr, NULL,
                   FALSE);

    TEST_END;
}

