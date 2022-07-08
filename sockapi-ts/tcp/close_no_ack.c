/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page tcp-close_no_ack Connection closing with broken conncetivity
 *
 * @objective Check that connection is closed correct despite broken 
 *            connectivity.
 *
 * @type conformance
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param pco_gw           PCO on host in the tested network
 *                         that is able to forward incoming packets
 *                         (gateway)
 * @param iut_if           Network interface on @p pco_iut
 * @param tst_if           Network interface on @p pco_tst
 * @param iut_addr         Network address on @p pco_iut
 * @param tst_addr         Network address on @p pco_tst
 * @param gw_iut_addr      Gateway address on @p pco_iut
 * @param gw_tst_addr      Gateway address on @p pco_tst
 * @param alien_link_addr  Invalid ethernet address
 * @param way              How to close IUT socket
 * @param shutdown_close   Call close() function after shutdown() before
 *                         connectivity is repaired. Applicable only for
 *                         iteration @p way is @c shutdown.
 *@param linger            Linger timeout value, don't set linger if the
 *                         value is negative.
 * 
 * @par Test sequence:
 * -# There are 4 allowed values of argument @p linger, which determines
 * events order: linger timeout is expired (collum @b Linger), FIN
 * retransmissions limit (collum @b FIN_WAIT1), connection is fixed and
 * tester sends a data packet (collum @b Connection):
 *    | Linger value   | Linger      | FIN_WAIT1         | Connection      |
 *    |----------------|-------------|-------------------|-----------------|
 *    | -1             | -           | 1                 | 2               |
 *    |  0             | 1           | -                 | 2               |
 *    |  1             | 1           | 3                 | 2               |
 *    |  7             | 2           | 1                 | 3               |
 * -# Note, if @p linger value is greater then @c 1, it is expected that
 * retransmits limit is reached earlier then linger timeout is expired.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/close_no_ack"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "linger.h"

#include "onload.h"

#include "tapi_route_gw.h"

#define BUF_SIZE        1024

/* Attempts number to poll CSAP for FIN-ACK packets. */
#define MAX_ATTEMPTS    30

/* Delay between attempts of polling FIN_ACK packets. */
#define DELAY           1000

/* FIN-ACK retransmissions limit. */
#define RETRIES_NUM     3

/* Delay to make sure the connection is aborted by retransmits. */
#define THE_LAST_DELAY 5

/* Minimum call duration if linger is set. */
#define DURATION_MIN 1000000

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    rcf_rpc_server             *pco_iut_par = NULL; 
    const struct sockaddr      *tst_alien_addr = NULL;

    te_bool     shutdown_close = FALSE;
    closing_way way;
    int         linger;

    tarpc_linger            opt_val;
    unsigned long int       exp_duration = 0;
    char                    buffer[BUF_SIZE];
    csap_handle_t           csap;
    tsa_packets_counter     ctx;
    int exp_err;
    int retries;
    int iut_s = -1;
    int iut_l = -1;
    int tst_s = -1;
    int i;

    /* Preambule */
    TEST_START;

    TAPI_GET_ROUTE_GATEWAY_PARAMS;

    TEST_GET_ADDR(pco_tst, tst_alien_addr);

    TEST_GET_BOOL_PARAM(shutdown_close);
    TEST_GET_ENUM_PARAM(way, CLOSING_WAY);
    TEST_GET_INT_PARAM(linger);

    TAPI_INIT_ROUTE_GATEWAY(gw);

    retries = RETRIES_NUM;

    TEST_STEP("Increase waiting time in state @c FIN_WAIT1 in case @p linger is "
              "@c 1. It is to make sure that socket is not closed by retransmission "
              "timeout.");
    if (linger == 1)
        retries = 8;

    TEST_STEP("Set /proc/sys/net/ipv4/tcp_orphan_retries to tune waiting time "
              "in FIN_WAIT1 state. By default it is @c 8. "
              "Note! Linux can transmit 2-3 FIN-ACK messages more then the value "
              "specified in tcp_orphan_retries. Tested kernel 3.13.0-93-generic.");
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, retries, NULL,
                                     "net/ipv4/tcp_orphan_retries"));
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, retries, NULL,
                                     "net/ipv4/tcp_retries2"));
    rcf_rpc_server_restart(pco_iut);
    retries += 1;

    TEST_STEP("Create aux process if socket is closed with the process stopping.");
    ST_LINGER_CREATE_PROCESS;

    TEST_STEP("Create CSAP to account packets.");
    if (iut_addr->sa_family == AF_INET6)
        CHECK_RC(tapi_tcp_ip6_eth_csap_create(pco_tst->ta, 0, tst_if->if_name,
                                              TAD_ETH_RECV_DEF |
                                              TAD_ETH_RECV_NO_PROMISC,
                                              NULL, NULL,
                                              0, 0, -1, -1, &csap));
    else
        CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, 0, tst_if->if_name,
                                              TAD_ETH_RECV_DEF |
                                              TAD_ETH_RECV_NO_PROMISC,
                                              NULL, NULL,
                                              0, 0, -1, -1, &csap));

    CHECK_RC(tapi_route_gateway_configure(&gw));

    TEST_STEP("Establish TCP connection between IUT and tester.");
    ST_LINGER_GEN_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr);

    TEST_STEP("Set SO_LINGER socket option if @p linger is greater @c -1.");
    if (linger >= 0)
    {
        opt_val.l_onoff  = 1;
        opt_val.l_linger = linger;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);
    }

    TEST_STEP("Add incorrect ARP entry to imitate broken connection between IUT and "
              "tester.");
    CHECK_RC(tapi_route_gateway_break_tst_gw(&gw));
    CFG_WAIT_CHANGES;

    TEST_STEP("Start CSAP sniffer to track transmitted packets.");
    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Close connection by one of the ways in dependence on @p way.");
    if (way == CL_SHUTDOWN)
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);
    else
        sockts_close(pco_iut, pco_iut_par, &iut_s, way);

    TEST_STEP("Functions @b close() and @b dup2() have the same behavior: process "
              "is blocked for linger time if it is set. Otherwise any function "
              "should leave immediately.");
    if (way == CL_EXIT || way == CL_KILL || way == CL_SHUTDOWN || linger < 0)
        exp_duration = 0;
    else
        exp_duration = opt_val.l_linger  * 1000000L;

    RING("Closing function call duration is %lu", pco_iut->duration);
    /* Closing duration is evaluated in range because socket can be closed
     * by retransmits limit.*/
    CHECK_CALL_DURATION_INT_GEN(pco_iut->duration, TST_TIME_INACCURACY,
                                TST_TIME_INACCURACY_MULTIPLIER,
                                exp_duration < DURATION_MIN ?
                                exp_duration : DURATION_MIN, exp_duration,
                                ERROR, RING_VERDICT,
                                "close() call on 'iut_s' had "
                                "unexpectedly %s duration",
                                pco_iut->duration < exp_duration ?
                                "short" : "long");

    TEST_STEP("Sleep @p linger time in case process was not blocked in closing "
              "operation.");
    if (linger > 0 && (way == CL_EXIT || way == CL_KILL ||
                       (way == CL_SHUTDOWN && !shutdown_close)))
        SLEEP(linger);

    TEST_STEP("Wait until connection is interrupted because of FIN-ACK "
              "retransmissions limit. Skip this step if @p linger is @c 0 or @c 1. "
              "If @p linger is @c 0 - RST-ACK packet is sent immediately. Iteration "
              "with @p linger @c 1 is designed to test the case when socket is not "
              "closed by retransmission timeout, but @p linger time run out,");
    if (linger != 0 && linger != 1 && !shutdown_close)
    {
        for (i = 0; i < MAX_ATTEMPTS; i++)
        {
            rcf_ta_trrecv_get(pco_tst->ta, 0, csap, tsa_packet_handler, &ctx,
                              NULL);
            usleep(DELAY * 1000);

            if (ctx.fin_ack >= retries || ctx.rst_ack > 0 || ctx.rst > 0)
                break;
        }
        if (i == MAX_ATTEMPTS)
            TEST_FAIL("Not enough FIN-ACK segments were caught");

        /* Wait while the socket retransmits FIN-ACK, the connection must be
         * aborted by retransmits limit during the delay. */
        SLEEP(THE_LAST_DELAY);
    }
    else
        /* Wait to make sure that RST is delivered. */
        TAPI_WAIT_NETWORK;

    TEST_STEP("Counting finalizing packets.");
    rcf_ta_trrecv_get(pco_tst->ta, 0, csap, tsa_packet_handler, &ctx, NULL);
    tsa_print_packet_stats(&ctx);
    if (linger != 0 || way == CL_SHUTDOWN)
    {
        if (way != CL_SHUTDOWN && linger != 1 &&
            (ctx.fin_ack < retries || ctx.fin_ack > retries + 1))
            RING_VERDICT("Unexpected number of FIN-ACK packets were caught:"
                         " %d instead of %d", ctx.fin_ack, retries);
        else if (ctx.fin_ack == 0)
            RING_VERDICT("No FIN-ACK packets were caught");

        if (ctx.rst_ack != 0 || ctx.rst != 0)
            RING_VERDICT("Unexpected RST packet was caught");
    }
    else if (ctx.rst_ack == 0)
        RING_VERDICT("RST-ACK packet was not caught");

    TEST_STEP("If socket closing way @p way is @c CL_SHUTDOWN and @p shutdown_close "
              "is @c TRUE then call function @c close() and check its duration.");
    if (way == CL_SHUTDOWN && shutdown_close)
    {
        memset(&ctx, 0, sizeof(ctx));
        RPC_CLOSE(pco_iut, iut_s);

        if (linger < 0)
            exp_duration = 0;
        else
            exp_duration = opt_val.l_linger  * 1000000L;

        CHECK_CALL_DURATION_INT(pco_iut->duration, TST_TIME_INACCURACY,
                                TST_TIME_INACCURACY_MULTIPLIER,
                                exp_duration < DURATION_MIN ?
                                exp_duration : DURATION_MIN, exp_duration);
        RING("Closing function call duration is %lu", pco_iut->duration);

        if (linger < 0)
        {
            /* Wait while the socket retransmits FIN-ACK, the connection
             * must be aborted by retransmits limit during the delay. */
            SLEEP(THE_LAST_DELAY);
        }
        else if (linger == 0)
        {
            /* Wait to make sure RST is delivered. */
            TAPI_WAIT_NETWORK;
        }

        rcf_ta_trrecv_get(pco_tst->ta, 0, csap, tsa_packet_handler, &ctx,
                          NULL);
        tsa_print_packet_stats(&ctx);
        if (linger == 0)
        {
            if (ctx.rst_ack == 0)
                RING_VERDICT("RST-ACK packet was not caught");
        }
        else
        {
            if (ctx.fin_ack == 0)
                RING_VERDICT("FIN-ACK was not caught");
            if (ctx.rst_ack != 0 || ctx.rst != 0 || ctx.push_fin_ack != 0)
                RING_VERDICT("Unexpected finalizing packet was caught");
        }
    }

    TEST_STEP("Delete static ARP entry to fix connection between hosts.");
    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(tapi_route_gateway_repair_tst_gw(&gw));
    CFG_WAIT_CHANGES;

    TEST_STEP("Send a data packet from tester: IUT should send RST in the answer.");
    if (linger == 0 && !(way == CL_SHUTDOWN && !shutdown_close))
        RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_send(pco_tst, tst_s, buffer, sizeof(buffer), 0);

    TEST_STEP("If @p linger value is @c 0 then RST packet was sent just after "
              "socket closing, so tester call @b send() should fail with errno "
              "@c ECONNRESET.");
    if (linger == 0 && !(way == CL_SHUTDOWN && !shutdown_close))
    {
        if (rc != -1)
            TEST_FAIL("send() called on 'tst_s' socket second time "
                      "returns %d instead of -1", rc);

        if (way == CL_SHUTDOWN)
            exp_err = RPC_EPIPE;
        else
            exp_err = RPC_ECONNRESET;
        CHECK_RPC_ERRNO(pco_tst, exp_err, "send() called on 'tst_s' "
                        "socket second time returns -1, but");
    }
    else if (rc != sizeof(buffer))
        TEST_FAIL("send() called on 'tst_s' socket first time returns %d "
                  "instead of number of bytes sent %d",
                  rc, sizeof(buffer));

    TEST_STEP("Delay to make sure that the RST packet is delivered to tester.");
    TAPI_WAIT_NETWORK;

    if (linger != 0)
    {
        TEST_STEP("Now tester socket has received RST from IUT so the next "
                  "@b send() operation should fails with @c EPIPE errno.");
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_send(pco_tst, tst_s, buffer, sizeof(buffer), 0);
        if (rc != -1)
            TEST_FAIL("send() called on 'tst_s' socket second time returns %d "
                      "instead of -1", rc);

        CHECK_RPC_ERRNO(pco_tst, RPC_EPIPE, "send() called on 'tst_s' socket "
                        "second time returns -1, but");
    }

    TEST_STEP("Counting finalizing packets again.");
    rcf_ta_trrecv_get(pco_tst->ta, 0, csap, tsa_packet_handler, &ctx, NULL);
    tsa_print_packet_stats(&ctx);
    if (linger == 0 && !(way == CL_SHUTDOWN && !shutdown_close))
        ST_LINGER_NO_FIN_PACKETS;
    else if (ctx.rst == 0)
        RING_VERDICT("RST was not caught");

    ST_LINGER_CLOSE_LISTENER;
    if (is_addr_inuse(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                      RPC_SOCK_STREAM, iut_addr))
        TEST_VERDICT("Address is still in use");

    if (way == CL_SHUTDOWN && !shutdown_close)
    {
        memset(&ctx, 0, sizeof(ctx));

        RPC_CLOSE(pco_iut, iut_s);
        CHECK_CALL_DURATION_INT(pco_iut->duration, TST_TIME_INACCURACY,
                                TST_TIME_INACCURACY_MULTIPLIER, 0, 0);
        RING("close() call duration is %lu", pco_iut->duration);

        rcf_ta_trrecv_get(pco_tst->ta, 0, csap, tsa_packet_handler, &ctx, NULL);
        tsa_print_packet_stats(&ctx);
        if (ctx.rst_ack != 0 || ctx.rst != 0 || ctx.fin_ack != 0 ||
            ctx.push_fin_ack != 0)
            RING_VERDICT("Unexpected finalizing packet was caught");
    }

    rcf_ta_trrecv_stop(pco_tst->ta, 0, csap, tsa_packet_handler, &ctx, NULL);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);

    if (pco_iut_par != NULL)
        rcf_rpc_server_destroy(pco_iut);
    tapi_tad_csap_destroy(pco_tst->ta, 0, csap);

    /* Restart pco after test because tcp_retries2 and tcp_orphan_retries
       changed. */
    tapi_no_reuse_pco_disable_once();

    TEST_END;
}
