/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * TCP
 * 
 * $Id$
 */

/** @page tcp-tcp_close_timeout  Connection closing timeouts without UL
 *
 * @objective  Check that TCP connection is closed properly by timeouts if
 *             not attached to UL.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param tcp_state     TCP state to be tested
 * @param opening       Determines passive or active socket should be and
 *                      listener behavior
 * @param kill          Stop IUT process instead of socket closing
 * @param linger        Enable and set non-zero linger on IUT socket
 * @param cache_socket  Create cached socket to be reused
 * 
 * @par Scenario:
 *
 * @note The following options can be used to change waiting timeouts:
 * ### FIN_WAIT1, CLOSING
 * Tune retransmits number:
 * - /proc/sys/net/ipv4/tcp_orphan_retries --- for closing without linger
 * - /proc/sys/net/ipv4/tcp_retries2 --- for closing with non-zero linger
 * ### FIN_WAIT2
 * Waiting time limit can be tuned with /proc/sys/net/ipv4/tcp_fin_timeout
 * 
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_close_timeout"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_tcp.h"
#include "onload.h"
#include "tapi_sniffer.h"

/** Maxmim waiting time in seconds */
#define TIME_LIMIT 120

/** Accuracy to compare closing duration with tcp_fin_timeout value. */
#define FIN_TIMEOUT_ACCEPTABLE_MS_MIN(t) TE_SEC2MS(t - 1)
#define FIN_TIMEOUT_ACCEPTABLE_MS_MAX(t) TE_SEC2MS(t + 1)

/**
 * Check that socket closing time is about tcp_fin_timeout value.
 *
 * @param duration          How long it took to destroy TCP socket
 * @param tcp_fin_timeout   tcp_fin_timeout value
 *
 * @return @c TRUE if closing time is about tcp_fin_timeout.
 */
static inline te_bool
check_fin_timeout(int duration, int tcp_fin_timeout)
{
    if (duration > FIN_TIMEOUT_ACCEPTABLE_MS_MIN(tcp_fin_timeout) &&
        duration < FIN_TIMEOUT_ACCEPTABLE_MS_MAX(tcp_fin_timeout))
        return TRUE;

    return FALSE;
}

/**
 * Compare sent and expected FIN-ACK packets, print verdicts if needed
 *
 * @param sent_fin_ack      Factual amount of sent FIN-ACK packets
 * @param expected_fin_ack  Amount of FIN-ACK packets have to be sent within the
 *                          test iteration intention
 * @param extra_retries     Extra FIN packets that can be sent while IUT socket
 *                          is waiting for reply from the CSAP
 *
 */
static void
check_fin_acks(int sent_fin_ack, int expected_fin_ack,
               int extra_retries)
{
    int delta_retries = sent_fin_ack - expected_fin_ack;

    if (delta_retries < 0)
    {
        if (abs(delta_retries) == 1)
        {
            RING_VERDICT("Amount of sent FIN-ACK packets are lower than "
                         "amount of expected ones by ONE packet");
        }
        else
        {
            RING_VERDICT("Amount of sent FIN-ACK packets are lower than "
                         "amount of expected ones by MORE THAN ONE packet");
        }

        WARN("Wrong FIN-ACK packets number have been sent: %d instead of %d",
             sent_fin_ack, expected_fin_ack);
    }

    if (delta_retries > extra_retries)
    {
        if (abs(delta_retries - extra_retries) == 1)
        {
            RING_VERDICT("Amount of sent FIN-ACK packets are more than "
                         "sum of expected ones and allowable extra retries "
                         "by ONE packet");
        }
        else
        {
            RING_VERDICT("Amount of sent FIN-ACK packets are more than "
                         "sum of expected ones and allowable extra retries "
                         "by MORE THAN ONE packet");
        }

        WARN("Wrong FIN-ACK packets number have been sent: %d instead of %d + "
             "extra retries (%d)",
                sent_fin_ack, expected_fin_ack, extra_retries);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_iut2 = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    rcf_rpc_server             *pco_gw = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *gw_iut_addr = NULL;
    const struct sockaddr      *gw_tst_addr = NULL;
    const struct sockaddr      *alien_link_addr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *gw_tst_if = NULL;
    const struct if_nameindex  *gw_iut_if = NULL;
    const char     *tcp_state;
    te_bool         kill;
    int             linger;
    int             retries;
    int             tcp_fin_timeout;
    int             tcp_fin_timeout_linger;
    rpc_tcp_state   last_state;
    int             last_state_time;
    int             close_time;

    tsa_session     ss = TSA_SESSION_INITIALIZER;
    int             iut_s = -1;

    tsa_packets_counter ctx;
    csap_handle_t      csap = CSAP_INVALID_HANDLE;
    te_bool            onload_run = tapi_onload_run();
    tapi_tcp_handler_t csap_tst_s;
    rpc_tcp_state      state;
    te_bool            cache_socket;
    int                opening;
    int                sid = 1;

    tapi_sniffer_id *sniff = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_gw);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_gw, gw_iut_addr);
    TEST_GET_ADDR(pco_gw, gw_tst_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(gw_iut_if);
    TEST_GET_IF(gw_tst_if);
    TEST_GET_STRING_PARAM(tcp_state);
    TEST_GET_BOOL_PARAM(kill);
    TEST_GET_INT_PARAM(linger);
    TEST_GET_INT_PARAM(retries);
    TEST_GET_INT_PARAM(tcp_fin_timeout);
    TEST_GET_BOOL_PARAM(cache_socket);
    TEST_GET_ENUM_PARAM(opening, OPENING_LISTENER);

    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut2", &pco_iut2));

    /** Enable sniffer to get all traffic. Note! It enables promiscuous mode
     * on the interface. */
    sniff = tapi_sniffer_add(pco_tst->ta, tst_if->if_name, NULL, NULL, TRUE);

    state = tcp_state_str2rpc(tcp_state);

    switch (state)
    {
        case RPC_TCP_FIN_WAIT1:
        case RPC_TCP_CLOSING:
        case RPC_TCP_LAST_ACK:
            TEST_STEP("Set /proc/sys/net/ipv4/tcp_orphan_retries to tune waiting "
                      "time in FIN_WAIT1 and CLOSING states. There is special case "
                      "if linger time is big enought to get socket destroyed by "
                      "FIN-ACK retransmits limit during this period. In this case "
                      "parameter /proc/sys/net/ipv4/tcp_retries2 manages retransmits "
                      "number. Tested linux kernels: 3.10.0-229.1.2.el7.x86_64.");
            if ((linger == 15 || (linger == 8 && retries == 3)) && !kill)
                CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, retries, NULL,
                                                 "net/ipv4/tcp_retries2"));
            else
                CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, retries, NULL,
                                              "net/ipv4/tcp_orphan_retries"));
            break;



        case RPC_TCP_FIN_WAIT2:
            TEST_STEP("Keepalive timeouts should not influence to socket "
                      "closing, i.e. TCP probes should not be sent.");
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, retries, NULL,
                                            "net/ipv4/tcp_keepalive_probes"));
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 1, NULL,
                                             "net/ipv4/tcp_keepalive_intvl"));
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 1, NULL,
                                             "net/ipv4/tcp_keepalive_time"));
            break;

        default:
            TEST_FAIL("Unexpected socket state is requested");
    }

    TEST_STEP("Set /proc/sys/net/ipv4/tcp_fin_timeout value. This should not affect "
              "delays in states TCP_FIN_WAIT1 and TCP_CLOSING. But socket should "
              "be closed by this timeout if it hangs in state TCP_FIN_WAIT2.");
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, tcp_fin_timeout, NULL,
                                     "net/ipv4/tcp_fin_timeout"));
    rcf_rpc_server_restart(pco_iut);

    TEST_STEP("Create aux CSAP to account packets.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, sid, tst_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC, NULL,
        NULL, tst_addr->sa_family, NULL, NULL, -1, -1, &csap));

    if (tsa_state_init(&ss, TSA_TST_GW_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL));
    CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
                        gw_iut_if, gw_tst_if,
             ((struct sockaddr *)alien_link_addr)->sa_data));
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p cache_socket is @c TRUE and @p opening is @c OL_ACTIVE - create "
              "cached socket.");
    if (opening == OL_ACTIVE)
    {
        sockts_create_cached_socket(pco_iut, pco_gw, iut_addr, gw_iut_addr, -1,
                                    TRUE, cache_socket);
    }

    TEST_STEP("Create a tcp socket on IUT and CSAP on tester.");
    tsa_create_session(&ss, 0);
    TAPI_WAIT_NETWORK;

    iut_s = tsa_iut_sock(&ss);

    TEST_STEP("Check that socket is not closed by ACK probes in TCP_FIN_WAIT2.");
    if (state == RPC_TCP_FIN_WAIT2)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_KEEPALIVE, 1);

    TEST_STEP("Move IUT socket and the CSAP to ESTABLISHED TCP state.");
    tcp_move_to_state(&ss, RPC_TCP_ESTABLISHED, opening,
                      opening == OL_ACTIVE ? FALSE : cache_socket);

    iut_s = tsa_iut_sock(&ss);
    csap_tst_s = tsa_tst_sock(&ss);

    TEST_STEP("Set non-zero linger on IUT socket.");
    if (linger >= 0)
    {
        tarpc_linger opt_val = {.l_onoff = 1, .l_linger = linger};
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);
    }

    TEST_STEP("Start CSAP sniffer to track transmitted packets.");
    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Note the time staying in TCP_FIN_WAIT2 state.");
    pco_iut2->op = RCF_RPC_CALL;
    pco_iut2->timeout = TE_SEC2MS(TIME_LIMIT);
    rpc_wait_tcp_socket_termination(pco_iut2, iut_addr, tst_addr,
                                    &last_state, &last_state_time,
                                    &close_time);

    if (state == RPC_TCP_LAST_ACK)
        CHECK_RC(tapi_tcp_send_fin(csap_tst_s, 1000));

    TEST_STEP("Close IUT socket by function @b close() or by stopping process in "
              "dependence on argument @p kill.");
    if (kill)
    {
        CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }
    else
    {
        pco_iut->timeout = 30000;
        pco_iut->op = RCF_RPC_CALL;
        rpc_close(pco_iut, iut_s);
    }

    switch (state)
    {
        case RPC_TCP_FIN_WAIT1:
        case RPC_TCP_LAST_ACK:
            break;

        TEST_STEP("Reply ACK packet from tester to move IUT socket in "
                  "TCP_FIN_WAIT2 state.");
        case RPC_TCP_FIN_WAIT2:
            CHECK_RC(tapi_tcp_wait_packet(ss.state.csap.csap_tst_s, 1000));
            CHECK_RC(tapi_tcp_send_ack(csap_tst_s,
                                       tapi_tcp_next_ackn(csap_tst_s)));
            break;

        TEST_STEP("Reply FIN-ACK packet from tester to move IUT socket in "
                  "TCP_CLOSING state.");
        case RPC_TCP_CLOSING:
            CHECK_RC(tapi_tcp_wait_packet(ss.state.csap.csap_tst_s, 1000));
            CHECK_RC(tapi_tcp_send_fin(csap_tst_s, 1000));
            break;

        default:
            TEST_FAIL("Unexpected socket state is requested");
    }

    if (!kill)
    {
        int high = linger * 1000;
        int low = high;

        TEST_STEP("Check closing call duration if socket was closed with function "
                  "@b close().");
        RPC_CLOSE(pco_iut, iut_s);

        if (linger < 0 || state == RPC_TCP_FIN_WAIT2)
            low = high = 0;
        /** It is not correct comparison in general since arguments
         * linger and retries determine different metrics. But in this
         * particular case test arguments are choosen in special way. So
         * this inequality has sense that linger timeout is expired
         * later then retransmits limit is reached. */
        else if (linger >= retries)
        {
            low = 500;
            high -= 500;
        }

        rcf_ta_trrecv_get(pco_tst->ta, sid, csap, tsa_packet_handler, &ctx,
                          NULL);
        tsa_print_packet_stats(&ctx);
        CHECK_CALL_DURATION_INT(pco_iut->duration / 1000, 500,
                                TST_TIME_INACCURACY_MULTIPLIER, low, high);

        if (ss.state.iut_s_aux != -1 && opening != OL_PASSIVE_OPEN)
            RPC_CLOSE(pco_iut, ss.state.iut_s_aux);
    }

    rpc_wait_tcp_socket_termination(pco_iut2, iut_addr, tst_addr,
                                    &last_state, &last_state_time,
                                    &close_time);

    if (last_state != state)
        TEST_VERDICT("TCP socket was lastly observed in %s instead of %s",
                     tcp_state_rpc2str(last_state),
                     tcp_state_rpc2str(state));

    if (!kill && ss.state.iut_s_aux != -1)
        RPC_CLOSE(pco_iut, ss.state.iut_s_aux);

    TEST_STEP("Open a new TCP socket on IUT.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ss.state.iut_s = iut_s;
    TEST_STEP("Try to bind the new socket to the same address:port couple to "
              "make sure that previous socket is closed.");
    rpc_bind(pco_iut, iut_s, iut_addr);

    RING("Close duration %d, time in last state %d, "
         "tcp_fin_timeout %d, linger %d",
         close_time, last_state_time, TE_SEC2MS(tcp_fin_timeout), linger);

    rcf_ta_trrecv_stop(pco_tst->ta, sid, csap, tsa_packet_handler, &ctx,
                       NULL);
    tsa_print_packet_stats(&ctx);

    /* tcp_fin_timeout value plus linger time. */
    tcp_fin_timeout_linger = tcp_fin_timeout;
    if (linger > 0 && !kill)
        tcp_fin_timeout_linger += linger;

    /**
     * Onload feature, see bug 53749 for details: any orphaned socket is
     * closed in tcp_fin_timeout time.
     */
    if (onload_run &&
        ((state == RPC_TCP_FIN_WAIT2 ? last_state_time : close_time) >
         (FIN_TIMEOUT_ACCEPTABLE_MS_MAX(tcp_fin_timeout_linger))))
        TEST_VERDICT("Socket closing time overheads tcp_fin_timeout value");

    TEST_STEP("Counting finalizing packets.");
    switch (state)
    {
        case RPC_TCP_FIN_WAIT1:
        case RPC_TCP_CLOSING:
        case RPC_TCP_LAST_ACK:
        {
            int expected_fin_ack = retries + 1;
            int extra_retries = 1;

            /** Extra FIN packets can be sent while IUT socket is waiting
             * for reply from the CSAP. Especially in case if IUT process
             * is killed. */
            if (state == RPC_TCP_CLOSING || state == RPC_TCP_LAST_ACK)
                extra_retries = 2;

            /**
            * Onload feature, see bug 53749 for details: any orphaned
            * socket is closed in tcp_fin_timeout time.
            */
            if (onload_run && retries > 0 &&
                check_fin_timeout(close_time, tcp_fin_timeout_linger))
                break;

            check_fin_acks(ctx.fin_ack, expected_fin_ack, extra_retries);
            break;
        }

        case RPC_TCP_FIN_WAIT2:
            CHECK_CALL_DURATION_INT(last_state_time, 2000,
                                    TST_TIME_INACCURACY_MULTIPLIER,
                                    tcp_fin_timeout * 1000,
                                    tcp_fin_timeout * 1000 * 3);
            break;

        default:
            TEST_FAIL("Unexpected socket state is requested");
    }

    if (ctx.rst_ack != 0 || ctx.rst != 0 || ctx.push_fin_ack != 0)
        RING_VERDICT("Unexpected finalizing packet was caught");

    if (ctx.syn != 0 || ctx.syn_ack != 0)
        RING_VERDICT("Unexpected SYN packet was caught");

    TEST_SUCCESS;

cleanup:
    tapi_tad_csap_destroy(pco_tst->ta, sid, csap);
    tsa_destroy_session(&ss);

    tapi_sniffer_del(sniff);
    TEST_END;
}
