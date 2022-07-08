/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 *
 * $Id$
 */

/** @page tcp-connection_timeout_data Read data after the connection drop by retransmits
 *
 * @objective Check data located in receive buffer can be read after
 *            the connection drop by retransmits.
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TST
 * @param cache_socket      Create cached socket to be reused.
 *
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/connection_timeout_data"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_route_gw.h"
#include "tapi_sockets.h"

/* Amount of data to be sent. */
#define DATA_SIZE 50000

/* Restransmission number. */
#define RETRIES_NUM 3

/* Sleeping time in seconds to get the connection dropped by retransmits,
 * depends on @c RETRIES_NUM . */
#define RTO_TIMEOUT 10

/*
 * Time in microseconds to sleep before
 * checking TCP state the next time.
 */
#define USLEEP_ARG 1000

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    char   *sndbuf = NULL;
    char   *rcvbuf = NULL;
    int iut_s = -1;
    int tst_s = -1;

    te_bool cache_socket;

    rpc_tcp_state   tcp_state = RPC_TCP_CLOSE;
    struct timeval  tv_start;
    struct timeval  tv_current;
    long int        tv_diff;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(cache_socket);

    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                     "net/ipv4/tcp_retries2"));
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    sndbuf = te_make_buf_by_len(DATA_SIZE);
    rcvbuf = te_make_buf_by_len(DATA_SIZE);

    TEST_STEP("Configure gateway.");
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    CHECK_RC(tapi_route_gateway_configure(&gateway));
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                TRUE, cache_socket);

    TEST_STEP("Establish TCP connection between IUT and tester.");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Send a data bunch from the tester.");
    rpc_send(pco_tst, tst_s, sndbuf, DATA_SIZE, 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Break connection between IUT and tester using the gateway.");
    CHECK_RC(tapi_route_gateway_break_tst_gw(&gateway));
    CFG_WAIT_CHANGES;

    TEST_STEP("Send a data packet from IUT.");
    rpc_send(pco_iut, iut_s, sndbuf, 1, 0);

    TEST_STEP("Wait until the connection is aborted by retransmits.");

    rc = gettimeofday(&tv_start, NULL);
    if (rc < 0)
        TEST_FAIL("gettimeofday() failed with errno %r",
                  te_rc_os2te(errno));

    while (TRUE)
    {
        pco_iut->silent = TRUE;
        tcp_state = tapi_get_tcp_sock_state(pco_iut,
                                            iut_s);
        if (tcp_state == RPC_TCP_CLOSE)
            break;
        else if (tcp_state != RPC_TCP_ESTABLISHED)
            TEST_VERDICT("While waiting for connection timeout, "
                         "unexpected TCP state %s was encountered",
                         tcp_state_rpc2str(tcp_state));

        rc = gettimeofday(&tv_current, NULL);
        if (rc < 0)
            TEST_FAIL("gettimeofday() failed with errno %r",
                      te_rc_os2te(errno));

        if (TIMEVAL_SUB(tv_current, tv_start) > TE_SEC2US(RTO_TIMEOUT))
            TEST_VERDICT("TCP connection stayed open for too long");

        /*
         * Cannot use USLEEP() here - it prints log every time
         * it is called.
         */
        usleep(test_sleep_scale() * USLEEP_ARG);
    }

    tv_diff = TIMEVAL_SUB(tv_current, tv_start);
    RING("%d.%.6ld seconds passed while waiting for TCP "
         "connection timeout",
         TE_US2SEC(tv_diff), (tv_diff % 1000000L));

    TEST_STEP("Check the connection is dropped: "
              "-# send a data packet from tester twice; "
              "-# the second call should fail with @c ECONNRESET;");
    CHECK_RC(tapi_route_gateway_repair_tst_gw(&gateway));
    CFG_WAIT_CHANGES;

    rpc_send(pco_tst, tst_s, sndbuf, 100, 0);
    TAPI_WAIT_NETWORK;
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_send(pco_tst, tst_s, sndbuf, 100, 0);
    if (rc != -1 || RPC_ERRNO(pco_tst) != RPC_ECONNRESET)
        TEST_VERDICT("Connection has not been dropped");

    TEST_STEP("Read and check all data on IUT.");
    rc = rpc_recv(pco_iut, iut_s, rcvbuf, DATA_SIZE, 0);
    SOCKTS_CHECK_RECV(pco_iut, sndbuf, rcvbuf, DATA_SIZE, rc);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(sndbuf);
    free(rcvbuf);

    TEST_END;
}
