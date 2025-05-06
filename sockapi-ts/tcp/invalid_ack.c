/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 *
 * This test package contains tests for special cases of TCP protocol,
 * such as ICMP and routing table handling, small and zero window,
 * fragmentation of TCP packets, etc.
 */

/**
 * @page tcp-invalid_ack Invalid ACK processing
 *
 * @objective Check that invalid ACK is processed correctly and
 *            the connection can continue work without deviations.
 *
 * @param tcp_state      TCP state to be tested:
 *                       - TCP_SYN_SENT
 *                       - TCP_SYN_RECV
 *                       - TCP_ESTABLISHED (ACK to sent data)
 *                       - TCP_CLOSE_WAIT (ACK to sent data)
 *                       - TCP_FIN_WAIT1
 *                       - TCP_TIME_WAIT
 *                       - TCP_CLOSING
 *                       - TCP_LAST_ACK
 * @param bad_seqn       Switch to use bad seqn or bad ackn
 * @param value          Determines how to compute SEQN or ACKN of
 *                       incorrect packet sent from Tester:
 *                       - prev (The number of previous packet.)
 *                       - exp-1 (<expected value> - 1)
 *                       - exp-2^31+1 (<expected value> - (2^31-1))
 *                       - exp-random (<expected value> - rand[1, 2^31-1])
 * @param opening        Connection establishment way (iterate when possible):
 *                       - active
 *                       - passive close
 * @param cache_socket   If @c TRUE, create cached socket to be reused.
 * @param timestamp      Type of TCP timestamp in invalid ACK:
 *                       - @c disabled: TCP timestamps are disabled;
 *                       - @c normal: use expected timestamp in invalid
 *                                    ACK;
 *                       - @c too_big: use timestamp which is significantly
 *                                     bigger than expected value in
 *                                     invalid ACK.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/invalid_ack"

#include "sockapi-test.h"
#include "tapi_proc.h"
#include "tcp_test_macros.h"
#include "tapi_route_gw.h"
#include "te_dbuf.h"
#include "tapi_sniffer.h"

/* Remove this when ST-2364 is fixed */
#define DEBUG_TSA_CSAP

/** Number of bytes to send to check connection. */
#define SEND_LEN      1000

/** Length of buffer with data. */
#define BUF_LEN       (SEND_LEN * 2)

/** Time to wait for new TCP packet on CSAP, in milliseconds. */
#define MSG_TIMEOUT   500

/* Maximum offset of the incorrect sequence number. */
#define MAX_OFFT ((((uint32_t)1) << 31) - 1)

/**
 * Available options to choose which sequence number should be used in the
 * invalid ACK message.
 */
typedef enum {
    TEST_ACK_SEQN_PREV = 0, /**< Sequence number of the previous packet,
                                 (imitate zero window) */
    TEST_ACK_SEQN_1,        /**< exp-1 */
    TEST_ACK_SEQN_M,        /**< exp-2^31+1 */
    TEST_ACK_SEQN_RAND,     /**< exp-random */
} test_value_num;

/**
 * List of possible values of "value" test parameter,
 * to be passed to TEST_GET_ENUM_PARAM().
 */
#define TEST_ACK_SEQN   \
    { "prev",         TEST_ACK_SEQN_PREV },   \
    { "exp-1",        TEST_ACK_SEQN_1 },      \
    { "exp-2^31+1",   TEST_ACK_SEQN_M },      \
    { "exp-random",   TEST_ACK_SEQN_RAND }

/** Maximum initial timestamp on Tester */
#define MAX_INIT_TS 0xffffff

/**
 * Value to add to current timestamp to get "too big"
 * timestamp.
 */
#define BIG_TS_INCREMENT 60000

/**
 * Possible values for timestamp parameter.
 */
typedef enum {
    TEST_TS_DISABLED,   /**< Disabled TCP timestamps */
    TEST_TS_NORMAL,     /**< Use current timestamp in invalid ACK */
    TEST_TS_TOO_BIG,    /**< Use too big timestamp in invalid ACK */
} test_timestamp;

/**
 * List of possible values of "timestamp" test parameter,
 * to be passed to TEST_GET_ENUM_PARAM().
 */
#define TEST_TS_VALUES   \
    { "disabled",     TEST_TS_DISABLED },     \
    { "normal",       TEST_TS_NORMAL },       \
    { "too_big",      TEST_TS_TOO_BIG }

/**
 * Get next TCP state which can be achieved from
 * a given one.
 *
 * @param tcp_state     TCP state.
 *
 * @return Next TCP state.
 */
static rpc_tcp_state
get_next_tcp_state(rpc_tcp_state tcp_state)
{
    switch (tcp_state)
    {
        case RPC_TCP_SYN_SENT:
        case RPC_TCP_SYN_RECV:
            return RPC_TCP_ESTABLISHED;

        case RPC_TCP_ESTABLISHED:
            return RPC_TCP_FIN_WAIT1;

        case RPC_TCP_CLOSE_WAIT:
            return RPC_TCP_LAST_ACK;

        case RPC_TCP_FIN_WAIT1:
            return RPC_TCP_FIN_WAIT2;

        case RPC_TCP_FIN_WAIT2:
            return RPC_TCP_TIME_WAIT;

        case RPC_TCP_TIME_WAIT:
            return RPC_TCP_CLOSE;

        case RPC_TCP_CLOSING:
            return RPC_TCP_TIME_WAIT;

        case RPC_TCP_LAST_ACK:
            return RPC_TCP_CLOSE;

        default:
            return RPC_TCP_UNKNOWN;
    }

    return RPC_TCP_UNKNOWN;
}

/**
 * Structure storing auxiliary data and results related to
 * parsing packets sent from IUT.
 */
typedef struct handler_data {
    te_bool       failed;         /**< Will be set to @c TRUE if
                                       processing packets failed. */
    uint32_t      big_ts;         /**< Big timestamp set in checked ACK
                                       packet. */
    te_bool       big_ts_echo;    /**< Will be set to @c TRUE if
                                       big timestamp was echoed. */
    te_bool       decreased_ts;   /**< Will be set to @c TRUE if
                                       after echoing too big timestamp
                                       a packet with smaller timestamp
                                       was encountered. */
    unsigned int  pkts_num;       /**< Total number of captured packets. */
} handler_data;

/**
 * Process IUT packet captured by CSAP.
 *
 * @param pkt         TCP packet in ASN.
 * @param user_data   Pointer to handler_data structure.
 */
static void
process_iut_packet(asn_value *pkt, void *user_data)
{
    handler_data *data = (handler_data *)user_data;
    uint32_t      ts_echo;
    uint32_t      flags = 0;
    int           rc;

    data->pkts_num++;

    if (data->failed)
        goto cleanup;

    rc = asn_read_uint32(pkt, &flags, "pdus.0.#tcp.flags");
    if (rc != 0)
    {
        ERROR("asn_read_uint32() returned %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    rc = tapi_tcp_get_ts_opt(pkt, NULL, &ts_echo);
    if (rc == TE_ENOENT && (flags & TCP_RST_FLAG))
        goto cleanup;
    if (rc != 0)
    {
        ERROR("tapi_tcp_get_ts_opt() returned %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    if (ts_echo == data->big_ts)
    {
        ERROR("Big timestamp was echoed");
        data->big_ts_echo = TRUE;
    }

    if (ts_echo < data->big_ts && data->big_ts_echo)
        data->decreased_ts = TRUE;

cleanup:

    asn_free_value(pkt);
}

/**
 * Check that IUT does not echo wrong (too big) timestamp after
 * receiving it in invalid ACK packet.
 *
 * @param ta          TA where CSAP listens for IUT packets.
 * @param csap_recv   CSAP handle.
 * @param cb_data     Callback data structure to pass to
 *                    @b tapi_tad_trrecv_stop().
 * @param tcp_state   TCP state in which invalid ACK is received.
 */
static void
check_iut_ts_echo_after_big_ts(const char *ta, csap_handle_t csap_recv,
                               tapi_tad_trrecv_cb_data *cb_data,
                               rpc_tcp_state tcp_state,
                               te_bool expect_big_ts)
{
    handler_data *data = (handler_data *)cb_data->user_data;

    CHECK_RC(tapi_tad_trrecv_stop(ta, 0, csap_recv,
                                  cb_data, NULL));
    if (data->failed)
    {
        TEST_FAIL("Failed to parse TCP packets");
    }
    else if (data->pkts_num == 0 &&
             tcp_state != RPC_TCP_TIME_WAIT)
    {
        TEST_VERDICT("No TCP packets from IUT was captured "
                     "after sending invalid ACK");
    }

    if (expect_big_ts)
    {
        if (data->big_ts_echo)
        {
            if (data->decreased_ts)
                TEST_VERDICT("Decreasing echoed timestamp was observed");
        }
        else if (data->pkts_num > 0)
        {
            TEST_VERDICT("Echoed timestamp was not updated from ACK");
        }
    }
    else
    {
        if (data->big_ts_echo)
            TEST_VERDICT("Invalid timestamp was echoed by IUT");
    }
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    const struct sockaddr *tst_fake_addr = NULL;

    rpc_tcp_state     tcp_state;
    te_bool           bad_seqn;
    test_value_num    value;
    opening_listener  opening;
    te_bool           cache_socket;
    test_timestamp    timestamp;

    tsa_session         ss = TSA_SESSION_INITIALIZER;
    tapi_tcp_handler_t  csap_tst_s;

    int                 value_num;
    int                 ackn;
    int                 seqn;
    rpc_tcp_state       next_state;
    te_bool             exp_rst = FALSE;
    te_bool             got_rst = FALSE;

    char    send_buf[BUF_LEN];
    te_dbuf recv_dbuf = TE_DBUF_INIT(0);

    te_bool zf_shim_run = FALSE;
    te_bool test_failed = FALSE;

    asn_value          *pkt_tmpl = NULL;
    te_bool             iut_ts_enabled = FALSE;
    uint32_t            ts_to_echo;
    csap_handle_t       csap_recv = CSAP_INVALID_HANDLE;

    handler_data              pkts_data;
    tapi_tad_trrecv_cb_data   cb_data;
    uint32_t                  invalid_ack_ts = 0;
    te_bool                   exp_big_ts = FALSE;

#ifdef DEBUG_TSA_CSAP
    tapi_sniffer_id *sniff_gw_iut = NULL;
    tapi_sniffer_id *sniff_gw_tst = NULL;
#endif

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_TCP_STATE(tcp_state);
    TEST_GET_BOOL_PARAM(bad_seqn);
    TEST_GET_ENUM_PARAM(value, TEST_ACK_SEQN);
    TEST_GET_ENUM_PARAM(opening, OPENING_LISTENER);
    TEST_GET_BOOL_PARAM(cache_socket);
    TEST_GET_ENUM_PARAM(timestamp, TEST_TS_VALUES);

    zf_shim_run = sockts_zf_shim_run();

    TEST_STEP("Use GW CSAP to control traffic from Tester side.");

    if (tsa_state_init(&ss, TSA_TST_GW_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    tsa_iut_set(&ss, pco_iut, iut_if, iut_addr);
    tsa_tst_set(&ss, pco_tst, tst_if, tst_fake_addr, NULL);
    tsa_gw_preconf(&ss, TRUE);
    tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
               gw_iut_if, gw_tst_if,
               alien_link_addr->sa_data);

    TEST_STEP("If @p cache_socket is @c TRUE and @p opening is @c OL_ACTIVE - create "
              "cached socket.");
    if (opening == OL_ACTIVE)
    {
        sockts_create_cached_socket(pco_iut, pco_gw, iut_addr, gw_iut_addr, -1,
                                    TRUE, cache_socket);
    }

#ifdef DEBUG_TSA_CSAP
    /* Configure sniffers on gateway to debug ST-2364 */
    CHECK_NOT_NULL(sniff_gw_iut = tapi_sniffer_add(
                                      pco_gw->ta, gw_iut_if->if_name,
                                      NULL, NULL, TRUE));
    CHECK_NOT_NULL(sniff_gw_tst = tapi_sniffer_add(
                                      pco_gw->ta, gw_tst_if->if_name,
                                      NULL, NULL, TRUE));
#endif

    tsa_create_session(&ss, 0);
    /*
     * Enabling promiscuous mode can take some time on virtual hosts,
     * see ST-2675.
     */
    VSLEEP(1, "Wait for promiscuous mode to turn on");

    TEST_STEP("If @p timestamp is @c 'too_big', create a CSAP on @p pco_gw "
              "which will capture packets sent from IUT and check whether "
              "invalid timestamp is echoed.");
    if (timestamp == TEST_TS_TOO_BIG)
    {
        CHECK_RC(tapi_tcp_ip_eth_csap_create(
                            pco_gw->ta, 0, gw_iut_if->if_name,
                            TAD_ETH_RECV_DEF |
                            TAD_ETH_RECV_NO_PROMISC,
                            NULL, NULL, iut_addr->sa_family,
                            TAD_SA2ARGS(tst_fake_addr, iut_addr),
                            &csap_recv));
        memset(&pkts_data, 0, sizeof(pkts_data));

        cb_data.callback = &process_iut_packet;
        cb_data.user_data = &pkts_data;
    }

    TEST_STEP("If @p timestamp is not @c 'disabled', enable TCP timestamps "
              "for Tester CSAP socket emulation.");
    csap_tst_s = tsa_tst_sock(&ss);
    if (timestamp != TEST_TS_DISABLED)
    {
        CHECK_RC(tapi_tcp_conn_enable_ts(csap_tst_s, TRUE,
                                         rand_range(0, MAX_INIT_TS)));
    }

    TEST_STEP("Move IUT socket to state @p tcp_state, taking into "
              "account @p opening.");

    tcp_move_to_state(&ss, tcp_state, opening,
                      (opening != OL_ACTIVE) ? cache_socket : FALSE);

    TEST_STEP("If @p tcp_state is @c TCP_ESTABLISHED or @c TCP_CLOSE_WAIT, send "
              "some data from IUT and allow CSAP socket emulation to receive "
              "packets, so that its expected next ACKN will be updated.");
    if (tcp_state == RPC_TCP_ESTABLISHED ||
        tcp_state == RPC_TCP_CLOSE_WAIT)
    {
        te_fill_buf(send_buf, SEND_LEN);
        rc = rpc_send(pco_iut, tsa_iut_sock(&ss), send_buf, SEND_LEN, 0);
        if (rc != SEND_LEN)
            TEST_FAIL("send() returned unexpected result");

        tapi_tcp_recv_data(csap_tst_s, MSG_TIMEOUT,
                           TAPI_TCP_QUIET, &recv_dbuf);
    }
    else
    {
        /* Some TCP states involve sending a packet to peer
         * and expecting some response - let CSAP socket
         * process that packet before computing ACKN and SEQN
         * of incorrect packet. This is essential in case
         * of TCP_SYN_RECV since it is the first packet
         * we receive, and we cannot compute expected ACKN
         * without it. */
        tapi_tcp_wait_msg(csap_tst_s, MSG_TIMEOUT);
    }

    TEST_STEP("Send ACK packet from tester using CSAP; set incorrect sequence "
              "or ack number according to @b bad_seqn and @p value. Set timestamp "
              "according to @p timestamp if required.");

    if (value == TEST_ACK_SEQN_1 || value == TEST_ACK_SEQN_M)
    {
        if (bad_seqn)
            value_num = tapi_tcp_next_seqn(csap_tst_s);
        else
            value_num = tapi_tcp_next_ackn(csap_tst_s);
    }

    switch (value)
    {
        case TEST_ACK_SEQN_1:
            value_num--;
            break;

        case TEST_ACK_SEQN_M:
            value_num -= MAX_OFFT;
            break;

        case TEST_ACK_SEQN_PREV:
            if (bad_seqn)
                value_num = tapi_tcp_last_seqn_sent(csap_tst_s);
            else
                value_num = tapi_tcp_last_ackn_sent(csap_tst_s);

            break;

        case TEST_ACK_SEQN_RAND:
            /*
             * Make sure that random number cannot be confused
             * with values which may be considered valid (like
             * retransmitting ACK for an old packet).
             */

            if (bad_seqn)
                value_num = tapi_tcp_first_seqn_sent(csap_tst_s);
            else
                value_num = tapi_tcp_first_seqn_got(csap_tst_s);

            value_num -= rand_range(2, MAX_OFFT);

            break;

        default:
            TEST_FAIL("Invalid test parameter 'value'");
    }

    if (bad_seqn)
    {
        ackn = tapi_tcp_next_ackn(csap_tst_s);
        seqn = value_num;
    }
    else
    {
        ackn = value_num;
        seqn = tapi_tcp_next_seqn(csap_tst_s);
    }

    CHECK_RC(tapi_tcp_conn_template(csap_tst_s, NULL, 0,
                                    &pkt_tmpl));

    CHECK_RC(asn_write_uint32(pkt_tmpl, TCP_ACK_FLAG,
                              "pdus.0.#tcp.flags.#plain"));
    CHECK_RC(asn_write_uint32(pkt_tmpl, ackn,
                              "pdus.0.#tcp.ackn.#plain"));
    CHECK_RC(asn_write_uint32(pkt_tmpl, seqn,
                              "pdus.0.#tcp.seqn.#plain"));

    if (timestamp != TEST_TS_DISABLED)
    {
        CHECK_RC(tapi_tcp_conn_get_ts(csap_tst_s, NULL, &iut_ts_enabled,
                                      &invalid_ack_ts, NULL, NULL,
                                      &ts_to_echo, NULL, NULL));

        if (!iut_ts_enabled)
            TEST_FAIL("TCP timestamp option is not set by IUT socket");

        if (timestamp == TEST_TS_TOO_BIG)
        {
            invalid_ack_ts += BIG_TS_INCREMENT;
            pkts_data.big_ts = invalid_ack_ts;
        }

        CHECK_RC(tapi_tcp_set_ts_opt(pkt_tmpl, invalid_ack_ts,
                                     ts_to_echo));
    }

    if (timestamp == TEST_TS_TOO_BIG)
    {
        CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap_recv, NULL,
                                       TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_PACKETS));
    }

    CHECK_RC(tapi_tcp_send_template(csap_tst_s, pkt_tmpl,
                                    RCF_MODE_BLOCKING));

    if (timestamp == TEST_TS_TOO_BIG)
    {
        if (!bad_seqn &&
            ((value == TEST_ACK_SEQN_1 && tcp_state != RPC_TCP_SYN_RECV) ||
             value == TEST_ACK_SEQN_PREV))
        {
            /*
             * Linux accepts timestamp from "not too invalid" ACK,
             * so avoid failures due to timestamp mismatch here.
             * I have no idea why @c "exp-1" is not OK for @c SYN_RECV but
             * is OK for @c SYN_SENT.
             */
            CHECK_RC(tapi_tcp_conn_enable_ts(csap_tst_s, TRUE,
                                             invalid_ack_ts));
            exp_big_ts = TRUE;
        }
    }

    TEST_STEP("Check that RST is sent in response to incorrect packet "
              "if TCP state is @c TCP_SYN_SENT or @c TCP_SYN_RECV, "
              "and TCP ACKN was incorrect (not TCP SEQN).");

    tapi_tcp_wait_msg(csap_tst_s, MSG_TIMEOUT);

    got_rst = tapi_tcp_rst_got(csap_tst_s);
    RING("RST was %sreceived", (got_rst ? "" : "not "));

    if ((tcp_state == RPC_TCP_SYN_SENT || tcp_state == RPC_TCP_SYN_RECV) &&
        value != TEST_ACK_SEQN_PREV && !bad_seqn)
        exp_rst = TRUE;

    TEST_STEP("If @p tcp_state is @c TCP_ESTABLISHED or @c TCP_CLOSE_WAIT, check "
              "that data sent from IUT before incorrect packet is received "
              "correctly.");
    if (tcp_state == RPC_TCP_ESTABLISHED ||
        tcp_state == RPC_TCP_CLOSE_WAIT)
    {
        tapi_tcp_recv_data(csap_tst_s, MSG_TIMEOUT,
                           TAPI_TCP_AUTO, &recv_dbuf);

        RING("%d bytes received after sending %d bytes of data and "
             "incorrect packet", SEND_LEN, (int)recv_dbuf.len);

        if (recv_dbuf.len != SEND_LEN ||
            memcmp(send_buf, recv_dbuf.ptr, SEND_LEN) != 0)
        {
            ERROR_VERDICT("Received data does not match data sent "
                          "from IUT before incorrect packet");
            test_failed = TRUE;
        }

        /* Send ACK to all read data. */
        CHECK_RC(tapi_tcp_ack_all(csap_tst_s));
    }

    if (got_rst)
    {
        if (!exp_rst)
            TEST_VERDICT("RST was unexpectedly received from IUT");
    }
    else
    {
        if (exp_rst)
        {
            ERROR_VERDICT("Expected RST was not received from IUT");
            test_failed = TRUE;
        }
    }

    TEST_STEP("If @p tcp_state is @c TCP_ESTABLISHED, check that "
              "data can be sent in both directions via the TCP connection.");
    if (tcp_state == RPC_TCP_ESTABLISHED)
    {
        if (sockts_check_tcp_conn_csap(pco_iut, tsa_iut_sock(&ss),
                                       csap_tst_s) != 0)
        {
            if (timestamp == TEST_TS_TOO_BIG)
            {
                check_iut_ts_echo_after_big_ts(pco_gw->ta, csap_recv,
                                               &cb_data, tcp_state,
                                               exp_big_ts);
            }
            TEST_STOP;
        }
    }

    TEST_STEP("Move IUT socket to the next state, check it is successfully "
              "moved there.");

    next_state = get_next_tcp_state(tcp_state);

    rc = tsa_do_tcp_move(&ss, tcp_state, next_state, 0);
    if (rc != 0)
    {
        test_failed = TRUE;
        ERROR_VERDICT("Failed to move from %s to %s",
                      tcp_state_rpc2str(tcp_state),
                      tcp_state_rpc2str(next_state));
    }

    TEST_STEP("If next state is @c TCP_ESTABLISHED, check that "
              "data can be sent in both directions via the TCP connection.");
    if (next_state == RPC_TCP_ESTABLISHED && !test_failed)
    {
        if (sockts_check_tcp_conn_csap(pco_iut, tsa_iut_sock(&ss),
                                       csap_tst_s) != 0)
        {
            test_failed = TRUE;
        }
    }

    TEST_STEP("If @p timestamp is @c 'too_big', check that timestamp from "
              "invalid ACK packet is echoed from IUT if ACK had correct "
              "SEQN and its ACKN was not lower than initial peer SEQN, "
              "and is not echoed in all other cases.");

    if (timestamp == TEST_TS_TOO_BIG)
    {
        check_iut_ts_echo_after_big_ts(pco_gw->ta, csap_recv, &cb_data,
                                       tcp_state, exp_big_ts);
    }

    if (test_failed)
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

    te_dbuf_free(&recv_dbuf);

    if (tsa_destroy_session(&ss) != 0)
       TEST_FAIL("Closing working session with TSA failed");

    asn_free_value(pkt_tmpl);

    if (timestamp == TEST_TS_TOO_BIG)
    {
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_gw->ta, 0,
                                               csap_recv));
    }

    TEST_END;
}
