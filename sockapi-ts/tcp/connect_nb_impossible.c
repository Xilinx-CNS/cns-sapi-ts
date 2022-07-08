/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page tcp-connect_nb_impossible Functions behaviour after unsatisfied connect()
 *
 * @objective Check behaviour of various functions after unsatisfied
 *            @b connect().
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       tester PCO
 * @param func          Function to check after unsatisfied connect:
 *                      - @b connect
 *                      - @b send
 *                      - @b recv
 *                      - @b select
 *                      - @b getsockopt(@c SO_ERROR)
 *                      - @b poll
 *                      - @b onload_zc_send
 *                      - @b onload_zc_send_user_buf
 *                      - @b template_send
 *                      - @b od_send
 *                      - @b od_send_raw
 * @param error         @c EHOSTUNREACH or @c ETIMEDOUT or @c ECONNREFUSED
 *
 * @par Scenario
 * -# Create socket @p iut_s of type @c SOCK_STREAM on @p pco_iut.
 * -# Bind @p iut_s to local address.
 * -# Call @b ioctl(@c FIONBIO) on @p iut_s socket.
 * -# Prepare needed test conditions according to @p error;
 * -# Assign @p conn_addr variable to @p tst_addr in case @p error is
 *    @c ECONNREFUSED and to @p gw_fake_addr in other cases;
 * -# Try to connect from @p pco_iut to @p conn_addr and check error code.
 * -# Sleep for some time to let @b connect() fail.
 * -# Call @p func on @p iut_s socket and check rc, if errors received,
 *    call send/receive functions and check their returned errors.
 * -# Clean up.
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/connect_nb_impossible"

#include "sockapi-test.h"
#include "tapi_cfg.h"

#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#include <linux/types.h>
#include <linux/errqueue.h>

#include "icmp_send.h"

#include "tapi_tad.h"
#include "tapi_tcp.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"
#include "ndn.h"
#include "iomux.h"

#include "tcp_test_macros.h"

#define DATA_BULK               1024  /**< Size of data to be sent */
#define POLL_TIMEOUT            2     /**< Timeout for poll() function */

/* SYN retransmits number. */
#define SYN_RETRIES_NUM 3

/* Timeout waiting for connection drop by SYN retransmits, dependent on
 * @p SYN_RETRIES_NUM . */
#define TST_CONNECT_TIMEOUT     20

/* Delay to get EHOSTUNREACH. */
#define TST_CONNECT_EHOSTUNREACH 10

static uint8_t data_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;

    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    const struct sockaddr      *gw_fake_addr = NULL;
    const char                 *error;
    const char                 *func;

    const struct sockaddr  *conn_addr;
    int req_val = TRUE;
    int err_code;
    int iut_s = -1;

    /* Preambule */
    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ADDR(pco_tst, gw_fake_addr);
    TEST_GET_STRING_PARAM(error);
    TEST_GET_STRING_PARAM(func);

    /* Tune SYN retransmits number to decrease waiting time. */
    if (strcmp(error, "ETIMEDOUT") == 0)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, SYN_RETRIES_NUM, NULL,
                                         "net/ipv4/tcp_syn_retries"));
        rcf_rpc_server_restart(pco_iut);
    }

    TAPI_INIT_ROUTE_GATEWAY(gw);

    tapi_route_gateway_configure(&gw);

    /* Create socket */
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    /* Prepare test conditions */
    TCP_TEST_RESOLVE_ERROR(error, err_code, conn_addr);

    /* Try to connect */
    TAPI_CALL_CHECK_RC(pco_iut, connect, -1, RPC_EINPROGRESS,
                       iut_s, conn_addr);

    switch (err_code)
    {
        case RPC_ETIMEDOUT:
            TAPI_CALL_CHECK_RC(pco_iut, recv, -1, RPC_EAGAIN,
                               iut_s, data_buf, DATA_BULK, 0);
            TAPI_CALL_CHECK_RC(pco_iut, send, -1, RPC_EAGAIN,
                               iut_s, data_buf, DATA_BULK, 0);
            SLEEP(TST_CONNECT_TIMEOUT);
            break;

        case RPC_EHOSTUNREACH:
            SLEEP(TST_CONNECT_EHOSTUNREACH);
            break;

        case RPC_ECONNREFUSED:
            TAPI_WAIT_NETWORK;
            break;

        default:
            TEST_FAIL("Unexpected error code %d", err_code);
    }

    /* Call function */
    TCP_TEST_CHECK_FUNCTION(func, err_code);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (strcmp(error, "ETIMEDOUT") == 0)
        update_arp(pco_tst, tst_if, pco_gw, gw_tst_if, gw_tst_addr, NULL,
                   FALSE);

    TEST_END;
}
