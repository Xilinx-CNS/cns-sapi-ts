/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 *
 * $Id$
 */

/** @page tcp-tcp_timeout TCP socket handling retries timeout
 *
 * @objective Check that the socket will be eventually dropped to
 *            TCP_CLOSED because of retransmit timeout if it does not
 *            receive replies.
 *            Check the behaviour of @b tcp_info struct fields:
 *            @b tcpi_probes.
 *
 * @type conformance, robustness
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param tcp_state     TCP state to be tested
 * @param mode          Test mode (peer_unreachable or peer_rebooted)
 * @param cache_socket  Create cached socket to be reused
 *
 * @par Test sequence:
 *
 * -# Set small TCP retries number on IUT to decrease TCP retransmission
 *    timeout.
 * -# Create socket on IUT and CSAP on TST.
 * -# Move the IUT socket to the given state @p tcp_state using
      tcp_state lib.
 * -# If @p tcp_state is @c TCP_SYN_RECV track @c tcp_n_in_listenq state
 *    using Onload stackdump.
 * -# If @p tcp_state is @c ESTABLISHED send a data packet from IUT.
 * -# If @p mode is @c peer_unreachable than don't reply to any IUT packets
 *    from TST. Wait while IUT socket will not be closed.
 * -# If @p mode is @c peer_rebooted than modify ARP table on IUT to pass
 *    packets to TST with actual ethernet address. Then IUT packet will
 *    reach TST linux, which will send RST packet to IUT.
 * -# If @b test_change_mac fuction is called check that @b tcpi_probes
 *    field is increased by @c 1 or @c 2.
 * -# Check the IUT socket state during a time, it should be eventually
 *    dropped to @c TCP_CLOSED state.
 * -# If @b tcp_test_wait_for_tcp_close fuction is called check that
 *    @b tcpi_probes field is increased by @c RETRIES_NUM.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 * @author Oleg Sadakov <osadakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_timeout"

#include "sockapi-test.h"
#include "onload.h"
#include "tcp_test_macros.h"
#include "tapi_sniffer.h"

#define TST_BUF_LEN 100

/* Restransmission number. */
#define RETRIES_NUM 4

/* FIN_WAIT2 timeout. */
#define FIN_WAIT2_TIMEOUT 5

/* Attempts number to poll CSAP for SYN-ACK packets. */
#define MAX_ATTEMPTS 30

/* Delay between attempts of polling SYN-ACK packets. */
#define DELAY 1000

enum {
    PEER_UNREACHABLE = 0,
    PEER_REBOOTED
};

static rcf_rpc_server *pco_iut2 = NULL;

/* See description in tcp_test_macros.h */
static void
check_caching(tsa_session *ss, te_bool active)
{
    int cached = 0;

    if (!tapi_onload_lib_exists(ss->config.pco_iut->ta))
        return;

    if (tapi_sh_env_get_int(ss->config.pco_iut, "EF_SOCKET_CACHE_MAX",
                            &cached) != 0 || cached == 0)
        return;

    if (tapi_onload_socket_is_cached(ss->config.pco_iut, tsa_iut_sock(ss)))
        RING_VERDICT("Socket was cached");

    if (ss->state.iut_s_aux == -1)
        return;

    CHECK_RC(tsa_repair_iut_tst_conn(ss));
    TAPI_WAIT_NETWORK;

    sockts_create_cached_socket(ss->config.pco_iut, ss->config.pco_tst,
                                ss->config.iut_addr, ss->config.tst_addr,
                                ss->state.iut_s_aux, active, TRUE);
    sockts_tcp_check_cache_reuse(ss->config.pco_iut, pco_iut2, ss->config.pco_tst,
                                 ss->config.iut_addr, ss->config.tst_addr,
                                 ss->state.iut_s_aux, -1, active);
    CHECK_RC(tsa_break_iut_tst_conn(ss));
    TAPI_WAIT_NETWORK;
}

#define CHECK_TCP_NO_RST \
do {                                                                    \
    if (ctx->rst_ack != 0 || ctx->rst != 0 || ctx->push_fin_ack != 0)   \
        RING_VERDICT("Unexpected finalizing packet was caught");        \
} while (0)

/**
 * Check packets number.
 * 
 * @param state_to      Tested socket state
 * @param ctx           Packets counter context
 * @param data_packet   If data packet is sent
 */
static void
check_packets_num(rpc_tcp_state state_to, tsa_packets_counter *ctx,
                  te_bool data_packet)
{
    switch (state_to)
    {
        case RPC_TCP_SYN_RECV:
            if (ctx->syn_ack != RETRIES_NUM + 1)
                TEST_VERDICT("Wrong amount of SYN-ACK packets was caught: "
                             "%d/%d", ctx->syn_ack, RETRIES_NUM);
            CHECK_TCP_NO_RST;
            break;

        case RPC_TCP_SYN_SENT:
            if (ctx->syn != RETRIES_NUM + 1)
                TEST_VERDICT("Wrong amount of SYN packets was caught: %d/%d",
                             ctx->syn, RETRIES_NUM);
            CHECK_TCP_NO_RST;
            break;

        case RPC_TCP_CLOSE_WAIT:
        case RPC_TCP_ESTABLISHED:
        case RPC_TCP_FIN_WAIT2:
            if (state_to == RPC_TCP_ESTABLISHED && data_packet)
            {
                if (ctx->push_ack < RETRIES_NUM + 1 ||
                    ctx->push_ack > RETRIES_NUM + 2)
                    RING_VERDICT("Wrong PSH-ACK packets number was caught");
                CHECK_TCP_NO_RST;
            }
            else
            {
                if (ctx->ack < RETRIES_NUM + 1 ||
                    ctx->ack > RETRIES_NUM + 2)
                if (ctx->rst_ack != 1)
                    RING_VERDICT("RST-ACK packet was not caught");
                if (ctx->rst != 0 || ctx->push_fin_ack != 0)
                    RING_VERDICT("Unexpected finalizing packet was caught");
            }
            break;

        case TCP_LAST_ACK:
        case RPC_TCP_FIN_WAIT1:
        case RPC_TCP_CLOSING:
            if (ctx->fin_ack < RETRIES_NUM + 1 ||
                ctx->fin_ack > RETRIES_NUM + 3)
                RING_VERDICT("Wrong FIN-ACK packets number have been sent: "
                             "%d instead of %d", ctx->fin_ack,
                             RETRIES_NUM + 1);
            CHECK_TCP_NO_RST;
            break;

        default:
            TEST_FAIL("Unexpected socket state is requested");
    }
}

#undef CHECK_TCP_NO_RST

/** Contains the expected value range */
typedef struct expected_values {
    uint32_t value;   /**< Expected value */
    uint32_t more_on; /**< Admissible exceeding of value */
} expected_values;

/**
 * Check tcpi_probes field value
 *
 * @param cur      current value
 * @param exp      expected value
 * @param pos      position in relation to function call (before or after)
 * @param func     name of testable function
 * @param verdict  preferred verdict
 */
#define CHECK_VALUE(cur, exp, pos, func, verdict) \
    do {                                                    \
        if (((cur) < (exp).value) ||                        \
            ((cur) > ((exp).value + (exp).more_on)))        \
        {                                                   \
            if ((exp).more_on == 0)                         \
            {                                               \
                verdict("Wrong value tcp_info.tcpi_probes " \
                        " (%d) " pos " calling " func ", "  \
                        "expected %d",                      \
                        (cur), (exp).value);                \
            }                                               \
            else                                            \
            {                                               \
                verdict("Wrong value tcp_info.tcpi_probes " \
                        "(%d) " pos " calling " func ", "   \
                        "expected [%d, %d]",                \
                        (cur), (exp).value,                 \
                        (exp).value + (exp).more_on);       \
            }                                               \
        }                                                   \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_gw = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *gw_iut_addr = NULL;
    const struct sockaddr *gw_tst_addr = NULL;

    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *gw_iut_if = NULL;
    const struct if_nameindex *gw_tst_if = NULL;
    const struct sockaddr     *alien_link_addr = NULL;

    uint8_t *buf = NULL;

    tsa_session ss = TSA_SESSION_INITIALIZER;

    tsa_packets_counter ctx;
    csap_handle_t      csap = CSAP_INVALID_HANDLE;
    const char     *tcp_state;
    int             mode;
    te_bool         cache_socket;
    te_bool         data_packet;
    rpc_tcp_state   state_to;
    int             sid = 1;

    int iut_s       = -1;
    int opt_val     = 0;
    int exp_err     = 0;
    int opening     = 0;

    expected_values     tcpi_probes_before;
    expected_values     tcpi_probes_after;
    struct rpc_tcp_info info;

    tapi_sniffer_id *sniff = NULL;

    /* Preambule */
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
    TEST_GET_ENUM_PARAM(mode,
                        {"peer_unreachable", PEER_UNREACHABLE},
                        {"peer_rebooted", PEER_REBOOTED});
    TEST_GET_ENUM_PARAM(opening, OPENING_LISTENER);
    TEST_GET_BOOL_PARAM(cache_socket);
    TEST_GET_BOOL_PARAM(data_packet);

    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut2", &pco_iut2));

    /** Enable sniffer to get all traffic. Note! It enables promiscuous mode
     * on the interface. */
    sniff = tapi_sniffer_add(pco_tst->ta, tst_if->if_name, NULL, NULL, TRUE);

    state_to = tcp_state_str2rpc(tcp_state);

    switch(state_to)
    {
        case RPC_TCP_SYN_RECV:
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                             "net/ipv4/tcp_synack_retries"));
            break;

        case RPC_TCP_SYN_SENT:
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                             "net/ipv4/tcp_syn_retries"));
            break;

        case TCP_LAST_ACK:
        case RPC_TCP_FIN_WAIT1:
        case RPC_TCP_CLOSING:
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                             "net/ipv4/tcp_retries2"));
            /** CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                                 "net/ipv4/tcp_orphan_retries")); */
            break;

        case RPC_TCP_FIN_WAIT2:
        case RPC_TCP_CLOSE_WAIT:
        case RPC_TCP_ESTABLISHED:
            if (state_to == RPC_TCP_ESTABLISHED && data_packet)
            {
                CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                                 "net/ipv4/tcp_retries2"));
                break;
            }

            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                            "net/ipv4/tcp_keepalive_probes"));
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 1, NULL,
                                             "net/ipv4/tcp_keepalive_intvl"));
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 1, NULL,
                                             "net/ipv4/tcp_keepalive_time"));
            break;

        default:
            TEST_FAIL("Unexpected socket state value %d", state_to);
    }
    rcf_rpc_server_restart(pco_iut);

    /* Create aux CSAP to account packets. */
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_gw->ta, sid,
        gw_iut_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL, gw_iut_addr->sa_family,
        NULL, NULL, -1, -1, &csap));

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

    tsa_create_session(&ss, 0);
    TAPI_WAIT_NETWORK;

    iut_s = tsa_iut_sock(&ss);

    /** Set socket option SO_KEEPALIVE for @p tcp_state values
     * @c ESTABLISHED and @c CLOSE_WAIT. */
    if (state_to == RPC_TCP_CLOSE_WAIT || state_to == RPC_TCP_ESTABLISHED ||
        state_to == RPC_TCP_FIN_WAIT2)
    {
        opt_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &opt_val);
    }

    /* Start CSAP sniffer to track transmitted packets. */
    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    tcp_move_to_state(&ss, state_to, opening,
                      opening == OL_ACTIVE ? FALSE : cache_socket);

    if (opening != OL_ACTIVE)
        iut_s = tsa_iut_sock(&ss);

    if ((state_to != RPC_TCP_SYN_RECV && state_to != tsa_state_cur(&ss)) ||
        (state_to == RPC_TCP_SYN_RECV && tsa_state_cur(&ss) != RPC_TCP_LISTEN))
        TEST_VERDICT("%s was not achieved", tcp_state_rpc2str(tsa_state_to(&ss)));

    if (data_packet)
    {
        buf = te_make_buf_by_len(TST_BUF_LEN);
        rpc_send(pco_iut, iut_s, buf, TST_BUF_LEN, 0);
    }

    if (mode == PEER_REBOOTED)
    {
        tcpi_probes_before.value = 0;
        tcpi_probes_before.more_on = 0;
        rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);
        CHECK_VALUE(info.tcpi_probes, tcpi_probes_before,
                    "before", "forwarding repair", TEST_VERDICT);

        CHECK_RC(tsa_repair_iut_tst_conn(&ss));

        /*
         * Wait for keep-alive probes to be sent; CFG_WAIT_CHANGES
         * is not used here as it may result in no delay.
         */
        SLEEP(2);

        if ((!data_packet) &&
            ((state_to == RPC_TCP_ESTABLISHED) ||
             (state_to == RPC_TCP_CLOSE_WAIT) ||
             (state_to == RPC_TCP_FIN_WAIT2)))
        {
            /*
             * Tests may fail in some virtualised environments. For this
             * case the tcpi_probes must be equal 0.
             */
            tcpi_probes_after.value = 1;
            tcpi_probes_after.more_on = 1;
        }
        else
        {
            tcpi_probes_after.value = 0;
            tcpi_probes_after.more_on = 0;
        }
        rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);
        CHECK_VALUE(info.tcpi_probes, tcpi_probes_after,
                    "after", "forwarding repair", RING_VERDICT);
    }
    TAPI_WAIT_NETWORK;

    if (state_to == RPC_TCP_SYN_RECV)
        sockts_wait_cleaned_listenq(pco_iut2, iut_addr);
    else
    {
        tcpi_probes_before.value = 0;
        tcpi_probes_before.more_on = 0;
        tcpi_probes_after.value = 0;
        tcpi_probes_after.more_on = 0;
        if (!data_packet && (
            (state_to == RPC_TCP_ESTABLISHED) ||
            (state_to == RPC_TCP_CLOSE_WAIT) ||
            (state_to == RPC_TCP_FIN_WAIT2)
           ))
        {
            switch (mode)
            {
            case PEER_UNREACHABLE:
                tcpi_probes_after.value = RETRIES_NUM;
                break;

            case PEER_REBOOTED:
                /*
                 * Tests may fail in some virtualised environments. For this
                 * case the tcpi_probes must be equal 0.
                 */
                tcpi_probes_before.value = 1;
                tcpi_probes_before.more_on = 1;
                tcpi_probes_after.value = 1;
                tcpi_probes_after.more_on = 1;
                break;
            }
        }

        rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);
        CHECK_VALUE(info.tcpi_probes, tcpi_probes_before,
            "before", "tcp_test_wait_for_tcp_close", RING_VERDICT);

        tcp_test_wait_for_tcp_close(&ss, MSEC_BEFORE_NEXT_ATTEMPT,
                                    TCP_MAX_ATTEMPTS);

        rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);
        CHECK_VALUE(info.tcpi_probes, tcpi_probes_after,
            "after", "tcp_test_wait_for_tcp_close", TEST_VERDICT);
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (mode == PEER_UNREACHABLE && state_to != RPC_TCP_SYN_RECV)
        exp_err = RPC_ETIMEDOUT;
    else
    {
        switch (state_to)
        {
            case RPC_TCP_SYN_SENT:
                exp_err = RPC_ECONNREFUSED;
                break;

            case RPC_TCP_CLOSE_WAIT:
                exp_err = RPC_EPIPE;
                break;

            case RPC_TCP_SYN_RECV:
                exp_err = RPC_EOK;
                break;

            default:
                exp_err = RPC_ECONNRESET;
        }
    }
    if (opt_val != exp_err)
        TEST_VERDICT("IUT socket has unexpected error %s after closing "
                     "connection, it must be %s",
                     errno_rpc2str(opt_val), errno_rpc2str(exp_err));

    rcf_ta_trrecv_stop(pco_gw->ta, sid, csap, tsa_packet_handler, &ctx,
                       NULL);
    tsa_print_packet_stats(&ctx);

    if (!cache_socket && mode == PEER_UNREACHABLE)
        check_packets_num(state_to, &ctx, data_packet);

    check_caching(&ss, opening == OL_ACTIVE);

    TEST_SUCCESS;

cleanup:
    tapi_tad_csap_destroy(pco_gw->ta, sid, csap);

    if (tsa_destroy_session(&ss) != 0)
        CLEANUP_TEST_FAIL("Closing working session with TSA failed");

    free(buf);

    tapi_sniffer_del(sniff);
    TEST_END;
}
