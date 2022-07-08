/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP protocol special cases
 */

/**
 * @page tcp-tcp_handle_syn TCP socket handling SYN flag received from peer
 *
 * @objective Check that socket in different TCP socket states processes packet
 *            with SYN flag from peer correctly.
 *
 * @reference @ref RFC5961
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer_gw
 *      - @ref arg_types_env_peer2peer_tst_gw
 * @param tcp_state TCP state to be tested (only synchronized states are
 *                  tested):
 *      - TCP_ESTABLISHED
 *      - TCP_FIN_WAIT1
 *      - TCP_FIN_WAIT2
 *      - TCP_CLOSE_WAIT
 *      - TCP_CLOSING
 *      - TCP_LAST_ACK
 *      - TCP_TIME_WAIT
 * @param active    Active/passive connection opening:
 *      - FALSE (Passive connection opening)
 *      - TRUE (Active connection opening)
 * @param seq_val   Value of sequence number in SYN segment sent from tester:
 *      - next (seq = next)
 *      - next-1 (seq = next - 1)
 *      - next_plus_1 (seq = next + 1)
 *      - max_offs (seq = next + 2^31)
 * @param close_iut Close IUT socket before SYN transmission
 *      - FALSE
 *      - TRUE (not applicable for TCP_ESTABLISHED and TCP_CLOSE_WAIT states)
 * @param pass_data If @c TRUE, pass some data in both directions
 *                  in ESTABLISHED state.
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/tcp_handle_syn"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

/* Maximum offset of the incorrect sequence number. */
#define MAX_OFFT (((uint32_t)1) << 31)

/* Length of data to send in ESTABLISHED state if @p pass_data is TRUE. */
#define BUF_LEN 10000

/**
 * Available options to choose which sequence number should be used in the
 * SYN segment.
 */
typedef enum {
    SEQ_NEXT,          /**< seq = next */
    SEQ_NEXT_MINUS_1,  /**< seq = next - 1 */
    SEQ_NEXT_PLUS_1,   /**< seq = next + 1 */
    SEQ_NEXT_PLUS_MAX  /**< seq = next + 2^31 */
} seq_value;

/**
 * List of possible values of "seq_val" test parameter,
 * to be passed to TEST_GET_ENUM_PARAM().
 */
#define SEQ_VALUE                               \
    { "next",   SEQ_NEXT },                     \
    { "next-1", SEQ_NEXT_MINUS_1 },             \
    { "next_plus_1", SEQ_NEXT_PLUS_1 },         \
    { "max_offs", SEQ_NEXT_PLUS_MAX }

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    const char             *tcp_state;
    te_bool                 active;
    seq_value               seq_val;
    te_bool                 close_iut;
    tsa_session             ss = TSA_SESSION_INITIALIZER;
    uint32_t                flags = 0;
    tapi_tcp_handler_t      csap_tst_s;
    asn_value              *pkt_tmpl = NULL;
    uint32_t                seqn;
    rpc_tcp_state           state_cur;
    asn_value              *sniff_pattern = NULL;
    csap_handle_t           sniff_csap;
    int                     sniff_sid;
    unsigned int            sniff_num = 0;
    tsa_packets_counter     ctx;
    te_bool                 found = FALSE;
    te_bool                 pass_data;
    uint8_t                *buf = NULL;
    te_dbuf                 recv_data = TE_DBUF_INIT(0);

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_STRING_PARAM(tcp_state);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_ENUM_PARAM(seq_val, SEQ_VALUE);
    TEST_GET_BOOL_PARAM(close_iut);
    TEST_GET_BOOL_PARAM(pass_data);

    TEST_STEP("Initialize TSA session.");
    CHECK_RC(tsa_state_init(&ss, TSA_TST_GW_CSAP));
    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL));
    tsa_gw_preconf(&ss, TRUE);
    CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr, gw_iut_if,
                        gw_tst_if, alien_link_addr->sa_data));
    CFG_WAIT_CHANGES;

    if (!active)
        flags |= TSA_ESTABLISH_PASSIVE | TSA_MOVE_IGNORE_START_ERR;

    CHECK_RC(tsa_create_session(&ss, flags));
    csap_tst_s = tsa_tst_sock(&ss);

    TEST_STEP("Create CSAP on Tester.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sniff_sid));
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, sniff_sid,
        tst_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL, tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &sniff_csap));

    TEST_STEP("Move IUT socket to @p tcp_state TCP state. Active/passive "
              "connection establishment depends on a @p active parameter. "
              "If there is TCP_ESTABLISHED state on the way to this state "
              "from TCP_CLOSE, we stop at it to perform sending operations "
              "(if @p pass_data is @c TRUE) and then resume moving "
              "to @p tcp_state from it.");
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

    if (rc != 0 || tsa_state_to(&ss) != tsa_state_cur(&ss))
    {
        /*
         * Linux reports TIME_WAIT state as CLOSE. See kernel bug 33902.
         * So, do not stop the test in this case.
         */
        if (tsa_state_to(&ss) == RPC_TCP_TIME_WAIT &&
            tsa_state_cur(&ss) == RPC_TCP_CLOSE)
        {
            RING("%s is not observable",
                 tcp_state_rpc2str(tsa_state_to(&ss)));
        }
        else
        {
            TEST_VERDICT("%s was not achieved",
                         tcp_state_rpc2str(tsa_state_to(&ss)));
        }
    }

    TEST_STEP("Close IUT socket if @p close_iut. In case of passive "
              "connection opening close listening socket too.");
    if (close_iut)
    {
        RPC_CLOSE(pco_iut, ss.state.iut_s);

        if (!active)
            RPC_CLOSE(pco_iut, ss.state.iut_s_aux);
    }

    TEST_STEP("Start Tester CSAP to catch ACK segments from IUT");
    CHECK_RC(tapi_tcp_ip_segment_pattern(iut_addr->sa_family == AF_INET6,
                                         0, tapi_tcp_next_seqn(csap_tst_s),
                                         FALSE, TRUE,
                                         FALSE, FALSE,
                                         FALSE, FALSE,
                                         &sniff_pattern));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sniff_sid, sniff_csap,
                                   sniff_pattern, TAD_TIMEOUT_INF, 1,
                                   RCF_TRRECV_PACKETS));

    TEST_STEP("Send segment with SYN flag from tester with sequence "
              "number according to @p seq_val.");
    tapi_tcp_wait_msg(csap_tst_s, TAPI_WAIT_NETWORK_DELAY);

    CHECK_RC(tapi_tcp_conn_template(csap_tst_s, NULL, 0, &pkt_tmpl));
    CHECK_RC(asn_write_uint32(pkt_tmpl, TCP_SYN_FLAG,
                              "pdus.0.#tcp.flags.#plain"));
    CHECK_RC(asn_write_uint32(pkt_tmpl, 0, "pdus.0.#tcp.ackn.#plain"));
    switch (seq_val)
    {
        case SEQ_NEXT:
            seqn = tapi_tcp_next_seqn(csap_tst_s);
            break;
        case SEQ_NEXT_PLUS_1:
            seqn = tapi_tcp_next_seqn(csap_tst_s) + 1;
            break;
        case SEQ_NEXT_MINUS_1:
            seqn = tapi_tcp_next_seqn(csap_tst_s) - 1;
            break;
        case SEQ_NEXT_PLUS_MAX:
            seqn = tapi_tcp_next_seqn(csap_tst_s) + MAX_OFFT;
            break;
    }
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

    TEST_STEP("Check that empty ACK segment is sent from IUT.");
    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(rcf_ta_trrecv_stop(pco_tst->ta, sniff_sid, sniff_csap,
                                tsa_packet_handler, &ctx, &sniff_num));
    tsa_print_packet_stats(&ctx);
    if (sniff_num == 0)
        TEST_VERDICT("%s: IUT did not send ACK segment to Tester", tcp_state);

    TEST_STEP("Send segment with RST flag from tester to close the "
              "connection.");
    rc = tsa_tst_send_rst(&ss);
    if (rc != 0)
    {
        /*
         * We cannot obtain state of a closed socket, so tsa_tst_send_rst()
         * fails with EBADF in case @p close_iut is TRUE - lets ignore it.
         */
        if (!(close_iut && rc == RPC_EBADF))
            TEST_FAIL("Sending RST failed with error %r", rc);
    }

    TEST_STEP("Check that IUT socket is in CLOSE state.");
    rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr, &state_cur, &found);
    if (found)
    {
        TEST_VERDICT("IUT socket is in %s state instead of TCP_CLOSE "
                     "after receiving RST segment",
                     tcp_state_rpc2str(state_cur));
    }

    TEST_SUCCESS;

cleanup:
    te_dbuf_free(&recv_data);
    free(buf);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, sniff_sid,
                                           sniff_csap));
    CLEANUP_CHECK_RC(tsa_destroy_session(&ss));

    TEST_END;
}
