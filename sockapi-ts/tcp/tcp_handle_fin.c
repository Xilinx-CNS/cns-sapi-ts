/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP protocol special cases
 */

/**
 * @page tcp-tcp_handle_fin Receiving incorrect FIN from peer
 *
 * @objective Check that incorrect FIN packet is processed correctly
 *            in various TCP states
 *
 * @reference @ref BLIND-FIN-ATTACK-PAPER
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer_gw
 *      - @ref arg_types_env_peer2peer_gw_ipv6
 * @param tcp_state TCP state to be tested (only synchronized states are
 *                  tested):
 *      - TCP_ESTABLISHED
 *      - TCP_CLOSE_WAIT
 *      - TCP_FIN_WAIT1
 *      - TCP_FIN_WAIT2
 *      - TCP_CLOSING
 *      - TCP_LAST_ACK
 *      - TCP_TIME_WAIT
 * @param active    Active/passive connection opening:
 *      - FALSE (passive opening)
 *      - TRUE (active opening)
 * @param seq_val   Value of sequence number in FIN segment sent from tester:
 *      - next-1 (seq = next - 1)
 *      - next_plus_1 (seq = next + 1)
 *      - next_plus_datalen (seq = next + length of data to be sent next)
 *      - max_offs (seq = next + 2^31)
 * @param ack_val   Value of acknowledgment number in FIN segment sent from
 *                  tester:
 *      - next_plus_1 (ack = next + 1)
 *      - max_offs (ack = next + 2^31)
 * @param close_iut Close IUT socket before FIN transmission.
 *      - FALSE
 *      - TRUE (not applicable for TCP_ESTABLISHED and TCP_CLOSE_WAIT states)
 * @param pass_data If @c TRUE, pass some data in both directions
 *                  in ESTABLISHED state.
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/tcp_handle_fin"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "tapi_tad.h"
#include "ndn_ipstack.h"

/**
 * User data to pass to CSAP callback function.
 */
typedef struct callback_data
{
    tapi_tcp_pos_t  ackn;       /**< ACK number in ACK segment got by CSAP */
    te_bool         got_ack;    /**< Set to "1" if CSAP catches ACK segment */
    te_bool         got_rst;    /**< Set to "1" if CSAP catches RST segment */
    te_bool         got_rstack; /**< Set to "1" if CSAP catches RST-ACK
                                     segment */
} callback_data;

/**
 * Available options to choose which sequence/acknowledgment number
 * should be used in the FIN segment.
 */
typedef enum {
    NEXT,               /**< SND.NEXT */
    NEXT_PLUS_1,        /**< SND.NEXT + 1 */
    NEXT_MINUS_1,       /**< SND.NEXT - 1 */
    NEXT_PLUS_DATALEN,  /**< SND.NEXT + length of data to be sent next */
    NEXT_PLUS_MAXOFFS,  /**< SND.NEXT + 2^31 */
} tcp_pos_value;

/**
 * List of possible values of "tcp_pos_value" test parameter,
 * to be passed to TEST_GET_ENUM_PARAM().
 */
#define TCP_POS_VALUE               \
    { "next", NEXT },               \
    { "next-1", NEXT_MINUS_1 },     \
    { "next_plus_1", NEXT_PLUS_1 }, \
    { "next_plus_datalen", NEXT_PLUS_DATALEN }, \
    { "max_offs", NEXT_PLUS_MAXOFFS }

/* Maximum offset of the incorrect sequence number. */
#define MAX_OFFT (((uint32_t)1) << 31)

/* Length of data to be sent to IUT after FIN. */
#define TX_BUF_LEN 100

/* Length of data to send in ESTABLISHED state if @p pass_data is TRUE. */
#define BUF_LEN 10000

/**
 * Macro for checking ACK number sent by IUT.
 *
 * @param got_ackn_     ACK number got on tester CSAP
 * @param msg_          Message to print in verdict
 */
#define CHECK_ACK_NUMBER(got_ackn_, msg_)                           \
    do {                                                            \
        RING("%slast ACK from IUT got on tester = %u",              \
             msg_, got_ackn_);                                      \
        RING("%sFIN segment SEQ number sent by tester = %u",        \
             msg_, seqn);                                           \
        if ((got_ackn_) == (seqn + 1) && seq_val != NEXT_MINUS_1)   \
        {                                                           \
            test_failed = TRUE;                                     \
            ERROR_VERDICT("%s%s: IUT ACKed invalid FIN segment",    \
                          msg_, tcp_state);                         \
        }                                                           \
    } while(0)

/* Macro for preparing acknowledgment number. */
#define ACKN_PREPARE(val, csap) \
    tcp_number_prepare(tapi_tcp_next_ackn, val, csap)

/* Macro for preparing sequence number. */
#define SEQN_PREPARE(val, csap) \
    tcp_number_prepare(tapi_tcp_next_seqn, val, csap)

/**
 * Prepare tcp ack/seq number according to @p value.
 *
 * @param pfunc_next    Pointer to a function which returns "next"
 *                      ack/seq number (can be @ref tapi_tcp_next_ackn or
 *                      @ref tapi_tcp_next_seqn).
 * @param value         Value indicating how to change "next" number.
 * @param csap          CSAP id to obtain "next" number in connection.
 *
 * @return New seq/ack number.
 */
static tapi_tcp_pos_t
tcp_number_prepare(tapi_tcp_pos_t (*pfunc_next)(tapi_tcp_handler_t),
                   tcp_pos_value value,
                   tapi_tcp_handler_t csap)
{
    tapi_tcp_pos_t tcp_pos = 0;

    switch (value)
    {
        case NEXT:
            tcp_pos = pfunc_next(csap);
            break;
        case NEXT_MINUS_1:
            tcp_pos = pfunc_next(csap) - 1;
            break;
        case NEXT_PLUS_1:
            tcp_pos = pfunc_next(csap) + 1;
            break;
        case NEXT_PLUS_DATALEN:
            tcp_pos = pfunc_next(csap) + TX_BUF_LEN;
            break;
        case NEXT_PLUS_MAXOFFS:
            tcp_pos = pfunc_next(csap) + MAX_OFFT;
            break;
    }

    return tcp_pos;
}

/**
 * TCP CSAP callback function.
 *
 * @param tcp_message   Packet described in ASN.
 * @param user_param    Pointer to user data.
 */
static void
csap_handler(asn_value *tcp_message, void *user_param)
{
    const asn_value    *tcp_pdu;
    const asn_value    *subval;
    const asn_value    *val;
    int32_t             pdu_field;
    uint8_t             flags;
    callback_data      *user_data = user_param;

    CHECK_RC(asn_get_child_value(tcp_message, &val, PRIVATE, NDN_PKT_PDUS));
    CHECK_RC(asn_get_indexed(val, (asn_value **)&subval, 0, NULL));
    CHECK_RC(asn_get_choice_value(subval, (asn_value **)&tcp_pdu, NULL, NULL));

    CHECK_RC(ndn_du_read_plain_int(tcp_pdu, NDN_TAG_TCP_FLAGS, &pdu_field));
    flags = pdu_field;
    if (flags == TCP_ACK_FLAG)
    {
        user_data->got_ack = TRUE;
        CHECK_RC(ndn_du_read_plain_int(tcp_pdu, NDN_TAG_TCP_ACKN, &pdu_field));
        user_data->ackn = pdu_field;
    }

    if ((flags & TCP_RST_FLAG) == TCP_RST_FLAG)
    {
        if ((flags & TCP_ACK_FLAG) == TCP_ACK_FLAG)
            user_data->got_rstack = TRUE;
        else
            user_data->got_rst = TRUE;
    }

    asn_free_value(tcp_message);
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    const char             *tcp_state;
    te_bool                 active;
    tcp_pos_value           seq_val;
    tcp_pos_value           ack_val;
    tsa_session             ss = TSA_SESSION_INITIALIZER;
    uint32_t                flags = 0;
    tapi_tcp_handler_t      csap_tst_s;
    asn_value              *pkt_tmpl;
    tapi_tcp_pos_t          seqn = 0;
    tapi_tcp_pos_t          ackn = 0;
    rpc_tcp_state           state_cur;
    csap_handle_t           sniff_csap;
    int                     sniff_sid;
    char                    tx_buf[TX_BUF_LEN];
    te_bool                 test_failed = FALSE;
    te_bool                 close_iut;
    te_bool                 found = FALSE;
    callback_data           cb_user_data = {0};
    te_bool                 send_data = FALSE;
    te_bool                 pass_data;
    uint8_t                *buf = NULL;
    te_dbuf                 recv_data = TE_DBUF_INIT(0);

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_STRING_PARAM(tcp_state);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_ENUM_PARAM(seq_val, TCP_POS_VALUE);
    TEST_GET_ENUM_PARAM(ack_val, TCP_POS_VALUE);
    TEST_GET_BOOL_PARAM(close_iut);
    TEST_GET_BOOL_PARAM(pass_data);

    if (seq_val == NEXT_PLUS_DATALEN)
        send_data = TRUE;

    TEST_STEP("Initialize TSA session.");
    CHECK_RC(tsa_state_init(&ss, TSA_TST_GW_CSAP));
    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr,
                         ((struct sockaddr *)alien_link_addr)->sa_data));
    tsa_gw_preconf(&ss, TRUE);
    CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr, gw_iut_if,
                        gw_tst_if, alien_link_addr->sa_data));
    CFG_WAIT_CHANGES;

    TEST_STEP("Move IUT socket to @p tcp_state state. Active/passive "
              "connection establishment depends on a @p active parameter. "
              "If there is TCP_ESTABLISHED state on the way to this state "
              "from TCP_CLOSE, we stop at it to perform sending operations "
              "(if @p pass_data is @c TRUE) and then resume moving "
              "to @p tcp_state from it.");
    if (!active)
        flags |= TSA_ESTABLISH_PASSIVE | TSA_MOVE_IGNORE_START_ERR;

    CHECK_RC(tsa_create_session(&ss, flags));
    csap_tst_s = tsa_tst_sock(&ss);
    rc = tsa_do_moves_str(&ss, RPC_TCP_UNKNOWN, RPC_TCP_ESTABLISHED, flags,
                          tcp_state);
    if (rc == TSA_ESTOP)
    {
        /* We are in TCP_ESTABLISHED state */
        if (pass_data)
        {
            int     data_sent = 0;
            char    rx_buf[1024];
            int     data_chunk = sizeof(rx_buf);

            buf = te_make_buf_by_len(BUF_LEN);

            /* Send data from IUT to Tester */
            rpc_send(pco_iut, tsa_iut_sock(&ss), buf, BUF_LEN, 0);
            tapi_tcp_recv_data(tsa_tst_sock(&ss), TAPI_WAIT_NETWORK_DELAY,
                               TAPI_TCP_AUTO, &recv_data);

            /* Send data from Tester to IUT */
            while (data_sent < BUF_LEN)
            {
                if (BUF_LEN - data_sent < data_chunk)
                    data_chunk = BUF_LEN - data_sent;

                CHECK_RC(tapi_tcp_send_msg(tsa_tst_sock(&ss),
                                           buf + data_sent,
                                           data_chunk,
                                           TAPI_TCP_AUTO, 0,
                                           TAPI_TCP_AUTO, 0,
                                           NULL, 0));
                TAPI_WAIT_NETWORK;
                data_sent += rpc_recv(pco_iut, tsa_iut_sock(&ss),
                                      rx_buf, sizeof(rx_buf), 0);
            }
        }

        rc = tsa_do_moves_str(&ss, tsa_state_to(&ss), RPC_TCP_UNKNOWN,
                              flags, tsa_rem_path(&ss));
    }

    TEST_STEP("Close IUT socket if @p close_iut. In case of passive "
              "connection opening close listening socket too.");
    if (close_iut)
    {
        RPC_CLOSE(pco_iut, ss.state.iut_s);

        if (!active)
            RPC_CLOSE(pco_iut, ss.state.iut_s_aux);
    }

    TEST_STEP("Create and start CSAP on Tester.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sniff_sid));
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, sniff_sid, tst_if->if_name, TAD_ETH_RECV_DEF,
        NULL, NULL, tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &sniff_csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sniff_sid, sniff_csap,
                                   NULL, TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));

    TEST_STEP("Send FIN segment from tester with sequence/acknowledgment "
              "numbers according to @p seq_val and @p ack_val.");
    tapi_tcp_wait_msg(csap_tst_s, TAPI_WAIT_NETWORK_DELAY);
    CHECK_RC(tapi_tcp_conn_template(csap_tst_s, NULL, 0, &pkt_tmpl));
    CHECK_RC(asn_write_uint32(pkt_tmpl, TCP_FIN_FLAG | TCP_ACK_FLAG,
                              "pdus.0.#tcp.flags.#plain"));

    ackn = ACKN_PREPARE(ack_val, csap_tst_s);
    CHECK_RC(asn_write_uint32(pkt_tmpl, ackn, "pdus.0.#tcp.ackn.#plain"));
    seqn = SEQN_PREPARE(seq_val, csap_tst_s);
    CHECK_RC(asn_write_uint32(pkt_tmpl, seqn, "pdus.0.#tcp.seqn.#plain"));

    CHECK_RC(tapi_tcp_send_template(csap_tst_s, pkt_tmpl, RCF_MODE_BLOCKING));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that IUT socket does not change its state.");
    rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr, &state_cur, &found);
    if (!found)
        state_cur = RPC_TCP_CLOSE;
    if (state_cur != tcp_state_str2rpc(tcp_state))
    {
        TEST_VERDICT("%s: IUT socket unexpectedly changed its state to %s",
                     tcp_state, tcp_state_rpc2str(state_cur));
    }

    TEST_STEP("Check that challenge ACK is sent by IUT");
    CHECK_RC(tapi_tad_trrecv_get(
                    pco_tst->ta, sniff_sid, sniff_csap,
                    tapi_tad_trrecv_make_cb_data(csap_handler, &cb_user_data),
                    NULL));
    if (cb_user_data.got_ack)
    {
        TEST_SUBSTEP("If IUT sends ACK, check that it does not acknowledge "
                     "incorrect FIN");
        CHECK_ACK_NUMBER(cb_user_data.ackn, "");
    }
    else
    {
        WARN_VERDICT("IUT did not send challenge ACK%s",
                     send_data ? " before data was received" : "");
        if (cb_user_data.got_rst)
        {
            WARN_VERDICT("IUT sent RST segment%s",
                         send_data ? " before data was received" : "");
        }
        else if (cb_user_data.got_rstack)
        {
            WARN_VERDICT("IUT sent RST-ACK segment%s",
                         send_data ? " before data was received" : "");
        }
    }

    TEST_STEP("Send data to IUT, if @p seq_val is @c next_plus_datalen");
    if (send_data)
    {
        te_fill_buf(tx_buf, TX_BUF_LEN);
        CHECK_RC(tapi_tcp_send_msg(csap_tst_s, (uint8_t *)tx_buf,
                                   TX_BUF_LEN,
                                   TAPI_TCP_AUTO, 0,
                                   TAPI_TCP_AUTO, 0,
                                   NULL, 0));
        TAPI_WAIT_NETWORK;

        TEST_SUBSTEP("Stop CSAP and check that IUT sends ACK in response "
                     "to data");
        memset(&cb_user_data, 0, sizeof(cb_user_data));
        CHECK_RC(tapi_tad_trrecv_stop(
                    pco_tst->ta, sniff_sid, sniff_csap,
                    tapi_tad_trrecv_make_cb_data(csap_handler, &cb_user_data),
                    NULL));
        if (cb_user_data.got_ack)
        {
            TEST_SUBSTEP("If IUT sends ACK, check that it does not confirm "
                         "invalid FIN");
            CHECK_ACK_NUMBER(cb_user_data.ackn, "After data sending: ");
        }
        else
        {
            WARN_VERDICT("IUT did not send ACK after data was received");
            if (cb_user_data.got_rst)
            {
                WARN_VERDICT("IUT sent RST segment after data was received");
            }
            else if (cb_user_data.got_rstack)
            {
                WARN_VERDICT("IUT sent RST-ACK segment after data was "
                             "received");
            }
        }

        TEST_SUBSTEP("Check that IUT socket does not change its state after "
                     "Tester sent data to it");
        rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr, &state_cur,
                                 &found);
        if (!found)
            state_cur = RPC_TCP_CLOSE;
        if (state_cur != tcp_state_str2rpc(tcp_state))
        {
            TEST_VERDICT("%s: IUT socket unexpectedly changed its state "
                         "to %s after data was received", tcp_state,
                         tcp_state_rpc2str(state_cur));
        }
    }

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:
    te_dbuf_free(&recv_data);
    free(buf);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, sniff_sid,
                                           sniff_csap));
    CLEANUP_CHECK_RC(tsa_destroy_session(&ss));
    TEST_END;
}
