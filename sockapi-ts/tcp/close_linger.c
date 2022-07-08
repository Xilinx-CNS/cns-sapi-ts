/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 */

/** @page tcp-close_linger Closing TCP socket with set-on linger option
 *
 * @objective Check that tcp socket will be closed according to @c
 *            SO_LINGER socket option.
 *
 * @type conformance
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer_gw
 *                        - @ref arg_types_env_peer2peer_gw_ipv6
 * @param tcp_state       TCP state to be tested
 *                        - @c TCP_SYN_SENT
 *                        - @c TCP_SYN_RECV
 *                        - @c TCP_ESTABLISHED
 *                        - @c TCP_FIN_WAIT2
 *                        - @c TCP_TIME_WAIT
 *                        - @c TCP_FIN_WAIT1
 *                        - @c TCP_CLOSING
 *                        - @c TCP_LAST_ACK
 * @param opening         How to open connection from IUT:
 *                        - @c active
 *                        - @c passive_end (listener is closed at the
 *                        end of the test)
 *                        - @c passive_open (listener is closed after
 *                        connection establishment)
 * @param way             How to close IUT socket:
 *                        - @b close()
 *                        - @b exit()
 *                        - @b kill()
 *                        - @b dup2()
 * @param zero_linger     Whether we test zero value of @p l_linger or
 *                        non-zero.
 * @param ack_after_close When test should send ack after @b close()
 *                        on IUT:
 *                        - @c instant - instantly send ACK from Tester
 *                        - @c delayed - send ACK after some delay
 *                        - @c none - do not send ACK
 * @param single_sock     Whether we test a single socket file descriptor
 *                        or two file descriptors of the same socket
 * @param set_before      Whether to set @c SO_LINGER option before or after
 *                        socket file descriptor duplication (the parameter
 *                        makes sense if only we duplicate file descriptor
 *                        at all)
 * @param use_fork        Whether to use @b fork() or @b dup() to duplicate
 *                        socket file descriptor (if we duplicate it)
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/close_linger"

#include "sockapi-test.h"
#include "tapi_proc.h"
#include "tapi_route_gw.h"
#include "onload.h"
#include "tcp_test_macros.h"
#include "linger.h"
#include "tapi_sniffer.h"

/* Remove this when ST-2364 is fixed */
#define DEBUG_TSA_CSAP

/**
 * When the test should send ACK from tester after @b close() on IUT.
 */
typedef enum {
    ACK_INSTANT = 0, /**< Instantly send ACK from Tester */
    ACK_DELAYED,     /**< Send ACK after some delay */
    ACK_NONE         /**< Do not send ACK */
} ack_after_close_t;

#define ACK_AFTER_CLOSE \
    { "instant", ACK_INSTANT },    \
    { "delayed", ACK_DELAYED },  \
    { "none", ACK_NONE }

static te_bool       is_failed = FALSE;
static te_bool       found = FALSE;

/* Sleep before unblocking close in case of SQ_DURING send queue state */
#define DURING_SLEEP_TIME 2

#define PACKET_SIZE 500

unsigned char   buf[PACKET_SIZE];

/**
 * Check presence or absence of the specified packet and add verdict
 * according to @p cond value.
 *
 * @param num           Number of received packets
 * @param exp_got       Test expects presence of the packet in case of
 *                      @p TRUE and absence of the packet in case of
 *                      @c FALSE
 * @param cond          Print verdict only if this value is @c TRUE
 * @param packet_name   Name of packet to be printed in verdict
 * @param str           Additional information string to be added to
 *                      verdict
 */
#define CHECK_FINAL_PACKET(num, exp_got, cond, packet_name, str) \
    do {                                                               \
        if (!exp_got && num != 0 && (cond))                            \
            RING_VERDICT("%sunexpected %s was caught after "           \
                         "IUT socket closing", str, packet_name);      \
        if (exp_got && num == 0 && (cond))                             \
            RING_VERDICT("%s%s was not sent after IUT socket closing", \
                         str, packet_name);                            \
    } while(0)

static void
close_check_linger(char *str, rcf_rpc_server *pco_iut,
                   rcf_rpc_server *pco_iut_par, rcf_rpc_server *pco_tst,
                   int *iut_s, tapi_tcp_handler_t csap_tst_s,
                   const struct sockaddr *iut_addr,
                   const struct sockaddr *tst_addr, int linger_time,
                   te_bool should_linger, int ack_after_close,
                   te_bool unacked_data, rpc_tcp_state tcp_state,
                   closing_way way, csap_handle_t csap)
{
    unsigned long int      exp_duration = 0;
    unsigned long int      add_duration = 0;
    tsa_packets_counter    ctx;
    int                    tmp_s = -1;
    rpc_tcp_state          exp_state;
    rpc_tcp_state          got_tcp_state;
    rpc_tcp_state          new_got_tcp_state;
    te_bool                rst_got;
    te_bool                exp_found = TRUE;
    te_bool                acked = FALSE;

    memset(&ctx, 0, sizeof(ctx));
    /* Start CSAP sniffer to track transmitted packets. */
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    /* Perform socket closing according to way */
    pco_iut->timeout = TE_SEC2MS(linger_time) + pco_iut->def_timeout;
    if (way == CL_CLOSE)
    {
        pco_iut->op = RCF_RPC_CALL;
        sockts_close(pco_iut, pco_iut_par, iut_s, way);
    }
    else if (way == CL_DUP2)
    {
        tmp_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);
        pco_iut->op = RCF_RPC_CALL;
        rpc_dup2(pco_iut, tmp_s, *iut_s);
    }
    else
    {
        sockts_close(pco_iut, pco_iut_par, iut_s, way);
    }

    /* Do not send ACK immediately in case of ack_after_close is
     * ACK_DELAYED
     */
    if (ack_after_close == ACK_DELAYED)
        SLEEP(DURING_SLEEP_TIME);

    /* Make send queue empty when it is needed. */
    if (ack_after_close != ACK_NONE && linger_time != 0 &&
        tcp_state != RPC_TCP_TIME_WAIT &&
        tcp_state != RPC_TCP_FIN_WAIT2 &&
        tcp_state != RPC_TCP_SYN_SENT &&
        tcp_state != RPC_TCP_SYN_RECV &&
        should_linger)
    {
        acked = TRUE;
        /* Sleep for a while to get FIN. Further tapi_tcp_wait_packet() can
         * return before FIN in case we get retransmitted packets if
         * @p unacked_data is @c TRUE.
         */
        MSLEEP(100);
        if (way == CL_CLOSE || way == CL_DUP2)
            add_duration = TE_MS2US(100);
        CHECK_RC(tapi_tcp_wait_packet(csap_tst_s, 1000));
        CHECK_RC(tapi_tcp_ack_all(csap_tst_s));
    }

    if (way == CL_CLOSE)
    {
        pco_iut->op = RCF_RPC_WAIT;
        sockts_close(pco_iut, pco_iut_par, iut_s, way);
    }
    else if (way == CL_DUP2)
    {
        uint64_t        duration;

        pco_iut->op = RCF_RPC_WAIT;
        rpc_dup2(pco_iut, tmp_s, *iut_s);

        duration = pco_iut->duration;
        RPC_CLOSE(pco_iut, tmp_s);
        RPC_CLOSE(pco_iut, *iut_s);
        pco_iut->duration = duration;
    }

    /* Check closing duration. */
    if (way == CL_EXIT || way == CL_KILL ||
        ack_after_close == ACK_INSTANT ||
        tcp_state == RPC_TCP_TIME_WAIT ||
        tcp_state == RPC_TCP_FIN_WAIT2 ||
        tcp_state == RPC_TCP_SYN_SENT ||
        tcp_state == RPC_TCP_SYN_RECV)
        exp_duration = 0;
    else if (ack_after_close == ACK_DELAYED)
        exp_duration = should_linger ? TE_SEC2US(DURING_SLEEP_TIME) : 0;
    else
        exp_duration = should_linger ? linger_time * 1000000L : 0;
    exp_duration += add_duration;

    /* Close may take longer than normal calls, especially with AQF_XDP.
     * This is why we use TST_TIME_INACCURACY * 2.  See ST-2532. */
    CHECK_CALL_DURATION_INT_GEN(pco_iut->duration,
                                TST_TIME_INACCURACY * 2,
                                TST_TIME_INACCURACY_MULTIPLIER,
                                exp_duration, exp_duration,
                                ERROR, RING_VERDICT,
                                "%sclose() call on 'iut_s' had "
                                "unexpectedly %s duration", str,
                                pco_iut->duration < exp_duration ?
                                "short" : "long");
    TAPI_WAIT_NETWORK;

    /* Stop CSAP sniffer and check the transmitted packets. */
    CHECK_RC(rcf_ta_trrecv_stop(pco_tst->ta, 0, csap, tsa_packet_handler,
                                &ctx, NULL));

    /* Check received packets on peer host. */
    tsa_print_packet_stats(&ctx);
    CHECK_FINAL_PACKET(ctx.ack, FALSE, TRUE, "ACK", str);
    CHECK_FINAL_PACKET(ctx.rst, FALSE, TRUE, "RST", str);
    CHECK_FINAL_PACKET(ctx.push_fin_ack, FALSE,
                       (tcp_state != RPC_TCP_FIN_WAIT1 &&
                        tcp_state != RPC_TCP_CLOSING &&
                        tcp_state != RPC_TCP_LAST_ACK &&
                        ack_after_close == ACK_INSTANT) ||
                        !unacked_data,
                       "PSH-FIN-ACK", str);
    CHECK_FINAL_PACKET(ctx.push_ack, FALSE, !unacked_data, "PSH-ACK", str);

    /* Check RST-ACK packet presence */
    switch (tcp_state)
    {
        case RPC_TCP_SYN_SENT:
        case RPC_TCP_SYN_RECV:
        case TCP_TIME_WAIT:
        case RPC_TCP_LAST_ACK:
        case RPC_TCP_CLOSING:
            CHECK_FINAL_PACKET(ctx.rst_ack, FALSE, TRUE, "RST-ACK", str);
        break;

        default:
            if (should_linger)
            {
                CHECK_FINAL_PACKET(ctx.rst_ack, TRUE, (linger_time == 0),
                                   "RST-ACK", str);
                CHECK_FINAL_PACKET(ctx.rst_ack, FALSE, linger_time > 0,
                                   "RST-ACK", str);
            }
            else
            {
                CHECK_FINAL_PACKET(ctx.rst_ack, FALSE, TRUE, "RST-ACK",
                                   str);
            }
    }
    if (ctx.rst + ctx.rst_ack > 1)
        RING_VERDICT("%smore than one RST was sent", str);

    /* Check FIN-ACK packet presence */
    switch (tcp_state)
    {
        case RPC_TCP_SYN_SENT:
        case RPC_TCP_SYN_RECV:
        case TCP_TIME_WAIT:
            CHECK_FINAL_PACKET(ctx.fin_ack, FALSE, TRUE, "FIN-ACK", str);
        break;

        /* In LAST_ACK, FIN_WAIT1 and CLOSING states iut_s resends FIN-ACK
         * packet, so test can catch it if close actions take too much time.
         */
        case RPC_TCP_LAST_ACK:
        case RPC_TCP_CLOSING:
        case RPC_TCP_FIN_WAIT1:
        break;

        case RPC_TCP_FIN_WAIT2:
            CHECK_FINAL_PACKET(ctx.fin_ack, FALSE, TRUE,
                               "FIN-ACK", str);
        break;

        /* Remaining states are ESTABLISHED and CLOSE_WAIT */
        default:
            if (should_linger)
            {
                CHECK_FINAL_PACKET(ctx.fin_ack, TRUE, linger_time > 0,
                                   "FIN-ACK", str);
                CHECK_FINAL_PACKET(ctx.fin_ack, FALSE, linger_time == 0,
                                   "FIN-ACK", str);
            }
            else
            {
                CHECK_FINAL_PACKET(ctx.fin_ack, FALSE, TRUE, "FIN-ACK",
                                   str);
            }
    }
    rst_got = ctx.rst + ctx.rst_ack;

    if (!should_linger)
    {
        exp_state = tcp_state;
    }
    else if (linger_time == 0)
    {
        if (tcp_state == RPC_TCP_TIME_WAIT)
            exp_state = tcp_state;
        else
            exp_found = FALSE;
    }
    else if (acked)
    {
        if (tcp_state == RPC_TCP_CLOSING)
            exp_state = RPC_TCP_TIME_WAIT;
        else if (tcp_state == RPC_TCP_FIN_WAIT1 ||
            tcp_state == RPC_TCP_ESTABLISHED)
            exp_state = RPC_TCP_FIN_WAIT2;
        else
            exp_found = FALSE;
    }
    else /* Linger timeout */
    {
        if (tcp_state == RPC_TCP_SYN_SENT)
            exp_found = FALSE;
        else if (tcp_state == RPC_TCP_ESTABLISHED)
            exp_state = RPC_TCP_FIN_WAIT1;
        else if (tcp_state == RPC_TCP_CLOSE_WAIT)
            exp_state = RPC_TCP_LAST_ACK;
        else
            exp_state = tcp_state;
    }

    rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr,
                             &got_tcp_state, &found);

    if (exp_found && !found)
    {
        ERROR_VERDICT("Socket disappeared unexpectedly after closing");
    }
    else if (!exp_found && found)
    {
        ERROR_VERDICT("Socket should disappear after closing, but it is "
                      "instead in %s state", tcp_state_rpc2str(got_tcp_state));
    }
    else if (found && got_tcp_state != exp_state)
    {
        ERROR_VERDICT("Socket is in %s instead of %s after closing",
                      tcp_state_rpc2str(got_tcp_state),
                      tcp_state_rpc2str(exp_state));
    }

    /* Send some data from tester to get RST packet from IUT if it was not
     * received before.
     */
    if (should_linger && !rst_got && found)
    {
        CHECK_RC(tapi_tcp_send_msg(csap_tst_s, buf, PACKET_SIZE,
                                   TAPI_TCP_AUTO, 0, TAPI_TCP_AUTO, 0,
                                   NULL, 0));
        /* Wait a little for RST from IUT */
        MSLEEP(100);
        CHECK_RC(tapi_tcp_wait_packet(csap_tst_s, 1000));
        if (tapi_tcp_get_packets(csap_tst_s) < 0)
            TEST_FAIL("tapi_tcp_get_packets() failed");
        rst_got = tapi_tcp_rst_got(csap_tst_s);
        if (rst_got)
        {
            if (got_tcp_state == RPC_TCP_TIME_WAIT ||
                got_tcp_state == RPC_TCP_CLOSING ||
                got_tcp_state == RPC_TCP_LAST_ACK)
                ERROR_VERDICT("Unexpected RST packet was sent after "
                              "sending packet from peer.");
        }
        else
        {
            if (got_tcp_state != RPC_TCP_TIME_WAIT &&
                got_tcp_state != RPC_TCP_CLOSING &&
                got_tcp_state != RPC_TCP_LAST_ACK)
                ERROR_VERDICT("RST packet was not sent after sending "
                              "packet from peer.");
        }

        rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr,
                                 &new_got_tcp_state, &found);
        if (rst_got)
        {
            if (found)
            {
                ERROR_VERDICT("Socket did not disappear after sending RST "
                              "but hangs in %s state",
                              tcp_state_rpc2str(got_tcp_state));
            }
       }
       else
       {
            if (!found)
            {
                ERROR_VERDICT("Socket disappeared in response to data "
                              "packet without sending RST");
            }
            else if (new_got_tcp_state != got_tcp_state)
            {
                ERROR_VERDICT("Socket moved from %s to %s after getting "
                              "data packet",
                              tcp_state_rpc2str(got_tcp_state),
                              tcp_state_rpc2str(new_got_tcp_state));
            }
       }
    }
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    const struct sockaddr *tst_fake_addr = NULL;
    rcf_rpc_server        *pco_iut_par = NULL;
    rcf_rpc_server        *pco_dup = NULL;

    tsa_session ss = TSA_SESSION_INITIALIZER;

    tsa_packets_counter ctx;
    csap_handle_t       csap = CSAP_INVALID_HANDLE;

    rpc_tcp_state   tcp_state;
    te_bool         zero_linger = FALSE;
    int             linger_time;
    te_bool         single_sock = FALSE;
    te_bool         set_before  = TRUE;
    te_bool         use_fork    = FALSE;
    te_bool         unacked_data = FALSE;

    int                 sid = 0;
    tarpc_linger        opt_val = {.l_onoff = 1};
    closing_way         way;
    int                 opening;
    int                 iut_s = -1;
    int                 dup_s = -1;

    te_bool             exp_free_addr;

    ack_after_close_t ack_after_close;

#ifdef DEBUG_TSA_CSAP
    tapi_sniffer_id *sniff_gw_iut = NULL;
    tapi_sniffer_id *sniff_gw_tst = NULL;
#endif

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ADDR(pco_tst, tst_fake_addr);

    TEST_GET_TCP_STATE(tcp_state);
    TEST_GET_ENUM_PARAM(opening, OPENING_LISTENER);
    TEST_GET_ENUM_PARAM(way, CLOSING_WAY);
    TEST_GET_BOOL_PARAM(zero_linger);
    TEST_GET_ENUM_PARAM(ack_after_close, ACK_AFTER_CLOSE);
    TEST_GET_BOOL_PARAM(single_sock);
    TEST_GET_BOOL_PARAM(set_before);
    TEST_GET_BOOL_PARAM(use_fork);
    TEST_GET_BOOL_PARAM(unacked_data);

#ifdef DEBUG_TSA_CSAP
    /* Configure sniffers on gateway to debug ST-2364 */
    CHECK_NOT_NULL(sniff_gw_iut = tapi_sniffer_add(
                                      pco_gw->ta, gw_iut_if->if_name,
                                      NULL, NULL, TRUE));
    CHECK_NOT_NULL(sniff_gw_tst = tapi_sniffer_add(
                                      pco_gw->ta, gw_tst_if->if_name,
                                      NULL, NULL, TRUE));
#endif

    ST_LINGER_CREATE_PROCESS;

    TEST_STEP("Create a CSAP on Tester to capture packets sent from IUT.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, sid, tst_if->if_name,
        TAD_ETH_RECV_DEF,
        NULL, NULL, tst_fake_addr->sa_family,
        TAD_SA2ARGS(tst_fake_addr, iut_addr),
        &csap));

    if (tsa_state_init(&ss, TSA_TST_GW_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_fake_addr, NULL));
    tsa_gw_preconf(&ss, TRUE);
    CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
                        gw_iut_if, gw_tst_if,
                        alien_link_addr->sa_data));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a TCP socket on IUT and CSAP socket emulation on "
              "Tester.");
    CHECK_RC(tsa_create_session(&ss, 0));

    iut_s = tsa_iut_sock(&ss);

    if (ack_after_close == ACK_DELAYED)
    {
        linger_time = rand_range(DURING_SLEEP_TIME + 1,
                                 DURING_SLEEP_TIME + 3);
    }
    else
    {
        linger_time = zero_linger ? 0 : rand_range(1, 3);
    }

    opt_val.l_linger = linger_time;
    TEST_STEP("If @p set_before is @c TRUE, enable @c SO_LINGER on "
              "the IUT socket, setting @c l_linger according to "
              "@p zero_linger value.");
    if (set_before)
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);

    /* Start CSAP sniffer to track transmitted packets. */
    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("If unacked_data is @c TRUE move @p iut_s socket to "
              "@c TCP_ESTABLISHED state and then send some data from "
              "@p iut_s. ");
    if (unacked_data)
    {
        tcp_move_to_state(&ss, RPC_TCP_ESTABLISHED, opening, FALSE);
        iut_s = tsa_iut_sock(&ss);
        rpc_send(pco_iut, iut_s, buf, PACKET_SIZE, 0);
    }

    TEST_STEP("Move IUT socket to the requested state, opening connection "
              "passively or actively on IUT according to @p opening or "
              "move @p iut_s socket from @c TCP_ESTABLISHED state to "
              "@p tcp_state if @p unacked_data is @c TRUE.");
    if (tcp_state == RPC_TCP_TIME_WAIT)
    {
        /*
         * tcp_move_to_state() cannot handle TCP_TIME_WAIT.
         */
        tcp_move_to_state(&ss, RPC_TCP_CLOSING, opening, FALSE);
        CHECK_RC(tapi_tcp_send_ack(ss.state.csap.csap_tst_s,
                             tapi_tcp_next_ackn(ss.state.csap.csap_tst_s)));
        TAPI_WAIT_NETWORK;
    }
    else if (tcp_state != RPC_TCP_ESTABLISHED || !unacked_data)
    {
        if (unacked_data)
        {
            tcp_move_to_state(&ss, tcp_state, OL_ACTIVE, FALSE);
        }
        else
        {
            tcp_move_to_state(&ss, tcp_state, opening, FALSE);
        }
    }

    iut_s = tsa_iut_sock(&ss);

    TEST_STEP("If @p single_sock is @c FALSE, duplicate the IUT socket "
              "either with help of @b fork() (if @p use_fork is @c TRUE) "
              "or with help of @b dup() (if @p use_fork is @c FALSE).");
    if (!single_sock)
    {
        if (use_fork)
        {
            rcf_rpc_server_fork(pco_iut, "pco_iut_aux",
                                &pco_dup);
            dup_s = iut_s;
        }
        else
        {
            pco_dup = pco_iut;
            dup_s = rpc_dup(pco_iut, iut_s);
        }
    }

    TEST_STEP("If @p set_before is @c FALSE, enable @c SO_LINGER on "
              "the IUT socket, setting @c l_linger according to "
              "@p zero_linger value.");
    if (!set_before)
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);

    TEST_STEP("Check that @c SO_LINGER has expected value on tested IUT "
              "socket. Note that this socket can be different from the one "
              "on which we set this option if we had to @b accept() "
              "connection from listener.");
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);
    if (opt_val.l_onoff != 1 || opt_val.l_linger != linger_time)
    {
        TEST_VERDICT("SO_LINGER option has unexpected value on IUT "
                     "socket");
    }

    CHECK_RC(rcf_ta_trrecv_stop(pco_tst->ta, sid, csap, tsa_packet_handler,
                                &ctx, NULL));
    tsa_print_packet_stats(&ctx);

    /*
     * TSA library uses socket in nonblocking mode, here it is
     * better to turn it off.
     */
    rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, 0);

    if (!single_sock)
    {
        TEST_STEP("If @p single_sock is @c FALSE, close the original "
                  "IUT socket according to @p way and check that no RST "
                  "was sent.");
        close_check_linger("[the first socket] ", pco_iut, pco_iut_par,
                           pco_tst, &iut_s, ss.state.csap.csap_tst_s,
                           iut_addr, tst_fake_addr, linger_time, FALSE,
                           ack_after_close, unacked_data, tcp_state, way,
                           csap);
    }

    TEST_STEP("Close (remaining) IUT socket according to @p way."
              "Check whether socket disappears or changes its "
              "TCP state as a result, and whether closing function "
              "hangs for a while before returning. Examine which "
              "packets are sent to the peer. If IUT socket does "
              "not disappear and does not send an @c RST, check "
              "that it sends @c RST in response to a packet.");
    if (single_sock)
    {
        close_check_linger("[single socket] ", pco_iut, pco_iut_par,
                           pco_tst, &iut_s, ss.state.csap.csap_tst_s,
                           iut_addr, tst_fake_addr, linger_time, TRUE,
                           ack_after_close, unacked_data, tcp_state, way,
                           csap);
    }
    else
    {
        close_check_linger("[the second socket] ", pco_dup, pco_iut_par,
                           pco_tst, &dup_s, ss.state.csap.csap_tst_s,
                           iut_addr, tst_fake_addr, linger_time, TRUE,
                           ack_after_close, unacked_data, tcp_state, way,
                           csap);
    }

    TEST_STEP("Close listening socket in case of @c passive_end to "
              "make address free.");
    if (opening == OL_PASSIVE_END && tcp_state != RPC_TCP_SYN_RECV &&
        (way == CL_CLOSE || way == CL_DUP2))
    {
        rpc_close(pco_iut, ss.state.iut_s_aux);
        if (use_fork)
            rpc_close(pco_dup, ss.state.iut_s_aux);
        ss.state.iut_s_aux = -1;
    }

    TEST_STEP("Check that @p iut_addr is still in use only if "
              "closed socket still hangs in some TCP state. "
              "Otherwise it should be free (so that "
              "a new TCP socket can be bound to it).");
    if (found)
    {
        exp_free_addr = FALSE;
    }
    else
    {
        exp_free_addr = TRUE;
    }

    rc = is_addr_inuse(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, iut_addr);
    if (rc < 0)
    {
        ERROR_VERDICT("Unexpected error when checking whether address is "
                      "in use");
        is_failed = TRUE;
    }
    else
    {
        if (exp_free_addr && rc)
        {
            TEST_VERDICT("IUT address is in use when it should "
                         "be free");
            is_failed = TRUE;
        }
        else if (!exp_free_addr && !rc)
        {
            TEST_VERDICT("IUT address is free when it should be in "
                         "use");
            is_failed = TRUE;
        }
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

#ifdef DEBUG_TSA_CSAP
    /* Temporary code to debug ST-2364 */
    rpc_system(pco_gw, "ip neigh show");
    rpc_system(pco_gw, "ip -6 neigh show");
    CLEANUP_CHECK_RC(tapi_sniffer_del(sniff_gw_iut));
    CLEANUP_CHECK_RC(tapi_sniffer_del(sniff_gw_tst));
#endif

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, sid, csap));
    ss.state.iut_s = -1;
    if (way == CL_EXIT || way == CL_KILL)
        ss.state.iut_s_aux = -1;
    CLEANUP_CHECK_RC(tsa_destroy_session(&ss));

    if (pco_iut_par != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut));

    TEST_END;
}
