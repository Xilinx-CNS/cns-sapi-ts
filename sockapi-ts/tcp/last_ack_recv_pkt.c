/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-last_ack_recv_pkt Receiving various packets in LAST_ACK state
 *
 * @objective Check how LAST_ACK state handles various incoming packets.
 *
 * @type conformance
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_peer2peer_gw
 * @param sock_type           IUT socket type:
 *                            - @c tcp_active
 *                            - @c tcp_passive
 *                            - @c tcp_passive_close
 * @param send_syn            If @c TRUE, send SYN to socket in LAST_ACK
 *                            state; otherwise send ACK packet with data.
 * @param seqn_mod            Relative SEQN to set in a tested packet:
 *                            - @c less: expected SEQN - @c MODIFIER_VALUE
 *                            - @c more: expected SEQN + @c MODIFIER_VALUE
 * @param enable_timestamps   If @c TRUE, enable TCP timestamps.
 * @param ts_value_mod        Relative TCP timestamp value to set in
 *                            a tested packet:
 *                            - @c less: previous timestamp
 *                              value - @c MODIFIER_VALUE
 *                            - @c more: previous timestamp
 *                              value + @c MODIFIER_VALUE
 * @param ts_echo_mod         Relative TCP timestamp echo-reply to set in
 *                            a tested packet (take into account
 *                            only if @p send_syn is @c FALSE):
 *                            - @c expected: previous timestamp echo-reply
 *                            - @c more: previous timestamp
 *                              echo-reply + @c MODIFIER_VALUE
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/last_ack_recv_pkt"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "tapi_sockets.h"
#include "tapi_tcp.h"

#define MODIFIER_VALUE 10

/**
 * Variants for using expected or changed value.
 */
typedef enum {
    SOCKTS_VALUE_LESS,      /**< Decrease value. */
    SOCKTS_VALUE_EXPECTED,  /**< Use expected value. */
    SOCKTS_VALUE_MORE,      /**< Increase value. */
} sockts_value_modifier;

/**
 * Mapping of sockts_value_modifier enum values to string constants.
 */
#define SOCKTS_VALUE_TYPES \
    { "less", SOCKTS_VALUE_LESS },          \
    { "expected", SOCKTS_VALUE_EXPECTED },  \
    { "more", SOCKTS_VALUE_MORE }

/**
 * Structure used to store results of processing
 * packets sent from Tester and captured by a CSAP.
 */
typedef struct sockts_tst_tcp_data {
    uint32_t seqn;          /**< SEQN of the last captured packet. */
    uint32_t ackn;          /**< ACKN of the last captured packet. */
    uint32_t ts_value;      /**< Timestamp value in the last packet. */
    uint32_t ts_echo;       /**< Timestamp echo-reply in the last packet. */
    te_bool timestamped;    /**< Whether the last packet had TCP timestamp
                                 option. */

    te_bool captured;       /**< Will be set to @c TRUE if some packets
                                 were captured and processed. */
    te_bool failed;         /**< Will be set to @c TRUE if some failure
                                 occured during processing. */
} sockts_tst_tcp_data;

/**
 * Structure used to store results of processing
 * packets sent from IUT and captured by a CSAP.
 */
typedef struct sockts_iut_tcp_data {
    te_bool fin_received;   /**< Will be set to @c TRUE if @c FIN packet
                                 was received. */
    uint32_t fin_seqn;      /**< SEQN in the @c FIN packet. */
    uint32_t fin_ackn;      /**< ACKN in the @c FIN packet. */
    uint32_t fin_flags;     /**< Flags in the @c FIN packet. */

    te_bool retr_check;     /**< If @c TRUE, check whether IUT still
                                 sends @c FIN retransmits after
                                 receiving modified packet and possibly
                                 responding to it. */
    te_bool fin_retr;       /**< Will be set to @c TRUE if @c FIN retransmit
                                 is detected. */
    te_bool captured;       /**< Will be set to @c TRUE if some packets
                                 were captured and processed. */
    te_bool failed;         /**< Will be set to @c TRUE if some failure
                                 occured during processing. */
} sockts_iut_tcp_data;

/**
 * Compare two TCP sequence numbers.
 *
 * @param seqn1     The first SEQN.
 * @param seqn2     The second SEQN.
 *
 * @return @c -1 if the first SEQN is smaller than the second SEQN,
 *         @c 1 if the first SEQN is greater than the second SEQN,
 *         @c 0 if they are equal.
 */
static int
compare_seqn(uint32_t seqn1, uint32_t seqn2)
{
    uint32_t diff;

    diff = seqn2 - seqn1;

    /*
     * 1 << 30 is maximum TCP window size (taking into account
     * window scale option).
     */
    if (diff == 0)
        return 0;
    else if (diff < (1 << 30))
        return -1;
    else
        return 1;
}

/**
 * Process TCP packets sent by Tester.
 *
 * @param pkt         Captured packet.
 * @param userdata    Pointer to sockts_tst_tcp_data structure.
 */
static void
tst_packets_handler(asn_value *pkt, void *userdata)
{
    sockts_tst_tcp_data *tcp_pkt = (sockts_tst_tcp_data *)userdata;

    uint32_t  seqn;
    uint32_t  ackn;
    te_errno  rc;
    uint32_t  ts_value;
    uint32_t  ts_echo;

    if (tcp_pkt->failed)
        goto cleanup;

    rc = asn_read_uint32(pkt, &seqn, "pdus.0.#tcp.seqn");
    if (rc != 0)
    {
        ERROR("Failed to read TCP SEQN");
        tcp_pkt->failed = TRUE;
        goto cleanup;
    }

    rc = asn_read_uint32(pkt, &ackn, "pdus.0.#tcp.ackn");
    if (rc != 0)
    {
        ERROR("Failed to read TCP ACKN");
        tcp_pkt->failed = TRUE;
        goto cleanup;
    }

    if (!tcp_pkt->captured ||
        compare_seqn(tcp_pkt->seqn, seqn) < 0 ||
        (compare_seqn(tcp_pkt->seqn, seqn) == 0 &&
         compare_seqn(tcp_pkt->ackn, ackn) < 0))
    {
        tcp_pkt->seqn = seqn;
        tcp_pkt->ackn = ackn;

        rc = tapi_tcp_get_ts_opt(pkt, &ts_value, &ts_echo);
        if (rc == 0)
        {
            tcp_pkt->ts_value = ts_value;
            tcp_pkt->ts_echo = ts_echo;
            tcp_pkt->timestamped = TRUE;
        }
        else
        {
            tcp_pkt->timestamped = FALSE;
        }
    }

    tcp_pkt->captured = TRUE;

cleanup:

    asn_free_value(pkt);
}

/**
 * Process TCP packets sent by IUT.
 *
 * @param pkt         Captured packet.
 * @param userdata    Pointer to sockts_iut_tcp_data structure.
 */
static void
iut_packets_handler(asn_value *pkt, void *userdata)
{
    sockts_iut_tcp_data *data = (sockts_iut_tcp_data *)userdata;

    uint32_t flags;
    uint32_t ackn;
    uint32_t seqn;

    te_errno rc;

    if (data->failed)
        goto cleanup;

    data->captured = TRUE;

    rc = asn_read_uint32(pkt, &seqn, "pdus.0.#tcp.seqn");
    if (rc != 0)
    {
        ERROR("Failed to read TCP SEQN");
        data->failed = TRUE;
        goto cleanup;
    }

    rc = asn_read_uint32(pkt, &ackn, "pdus.0.#tcp.ackn");
    if (rc != 0)
    {
        ERROR("Failed to read TCP ACKN");
        data->failed = TRUE;
        goto cleanup;
    }

    rc = asn_read_uint32(pkt, &flags, "pdus.0.#tcp.flags");
    if (rc != 0)
    {
        ERROR("Failed to get TCP flags: %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    if (!data->fin_received)
    {
        if (flags & TCP_FIN_FLAG)
        {
            data->fin_received = TRUE;
            data->fin_seqn = seqn;
            data->fin_ackn = ackn;
            data->fin_flags = flags;

            RING("FIN packet from IUT received with SEQN %u ACKN %u",
                 seqn, ackn);
        }
        else
        {
            RING_VERDICT("Unexpected packet was received from IUT "
                         "before FIN packet");
        }
    }
    else
    {
        if (flags != data->fin_flags || seqn != data->fin_seqn ||
            ackn != data->fin_ackn)
        {
            char          buf[1000];
            te_string     str = TE_STRING_BUF_INIT(buf);

            RING("IUT responded with a packet having SEQN %u ACKN %u",
                 seqn, ackn);

#define CHECK_FLAG(flag_) \
    if (flags & TCP_ ## flag_ ## _FLAG) \
        te_string_append(&str, " %s", #flag_)

            te_string_append(&str, "flags [");
            CHECK_FLAG(FIN);
            CHECK_FLAG(SYN);
            CHECK_FLAG(RST);
            CHECK_FLAG(PSH);
            CHECK_FLAG(ACK);
            CHECK_FLAG(URG);
            te_string_append(&str, " ]");

            if (seqn != data->fin_seqn)
            {
                if (seqn == data->fin_seqn + 1)
                    te_string_append(&str, " with updated SEQN");
                else
                    te_string_append(&str, " with unexpected SEQN");
            }
            if (ackn != data->fin_ackn && (flags & TCP_ACK_FLAG) &&
                (data->fin_flags & TCP_ACK_FLAG))
                te_string_append(&str, " with changed ACKN");

            if (data->retr_check)
            {
                RING_VERDICT("IUT sent a strange packet instead of "
                             "FIN retransmit having %s", str.ptr);
            }
            else
            {
                RING_VERDICT("IUT responded with TCP packet having %s",
                             str.ptr);
            }

            if (flags & TCP_FIN_FLAG)
                data->fin_retr = TRUE;
        }
        else
        {
            data->fin_retr = TRUE;
        }
    }

cleanup:

    asn_free_value(pkt);
}

/**
 * Return a given value processed according to @p modifier (decreased or
 * increased by @c MODIFIER_VALUE, or left intact).
 *
 * @param value       Original value.
 * @param modifier    How to modify the original value.
 *
 * @return Processed value.
 */
static uint32_t
modify_value(uint32_t value, sockts_value_modifier modifier)
{
    if (modifier == SOCKTS_VALUE_LESS)
        return (value - MODIFIER_VALUE);
    else if (modifier == SOCKTS_VALUE_MORE)
        return (value + MODIFIER_VALUE);

    return value;
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    const struct sockaddr *gw_iut_lladdr = NULL;
    const struct sockaddr *iut_lladdr = NULL;

    sockts_socket_type        sock_type;
    te_bool                   send_syn;
    te_bool                   enable_timestamps;
    sockts_value_modifier     seqn_mod;
    sockts_value_modifier     ts_value_mod;
    sockts_value_modifier     ts_echo_mod;
    int                       iut_ts_val;

    int                   iut_s = -1;
    int                   iut_l = -1;
    int                   tst_s = -1;

    csap_handle_t         csap_recv_tst = CSAP_INVALID_HANDLE;
    csap_handle_t         csap_recv_iut = CSAP_INVALID_HANDLE;
    csap_handle_t         csap_send = CSAP_INVALID_HANDLE;

    tapi_tad_trrecv_cb_data   tst_cb_data;
    tapi_tad_trrecv_cb_data   iut_cb_data;
    sockts_tst_tcp_data       tst_data;
    sockts_iut_tcp_data       iut_data;
    char                      send_buf[SOCKTS_MSG_STREAM_MAX];
    char                      recv_buf[SOCKTS_MSG_STREAM_MAX];
    asn_value                *pkt_tmpl = NULL;

    te_bool           syn_flag = FALSE;
    te_bool           ack_flag = FALSE;
    tapi_tcp_pos_t    pkt_seqn = 0;
    tapi_tcp_pos_t    pkt_ackn = 0;
    uint32_t          pkt_ts_value = 0;
    uint32_t          pkt_ts_echo = 0;
    char             *data = NULL;
    size_t            data_len = 0;
    rpc_tcp_state     exp_state;
    rpc_tcp_state     got_state;
    te_bool           readable = FALSE;
    te_bool           force_ip6 = FALSE;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(send_syn);
    TEST_GET_BOOL_PARAM(enable_timestamps);
    TEST_GET_ENUM_PARAM(seqn_mod, SOCKTS_VALUE_TYPES);
    TEST_GET_ENUM_PARAM(ts_value_mod, SOCKTS_VALUE_TYPES);
    TEST_GET_ENUM_PARAM(ts_echo_mod, SOCKTS_VALUE_TYPES);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(gw_iut_lladdr);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    memset(&tst_data, 0, sizeof(tst_data));
    tst_cb_data.callback = &tst_packets_handler;
    tst_cb_data.user_data = &tst_data;

    memset(&iut_data, 0, sizeof(iut_data));
    iut_cb_data.callback = &iut_packets_handler;
    iut_cb_data.user_data = &iut_data;

    if (rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET6)
        force_ip6 = TRUE;

    TEST_STEP("Configure CSAPs for receiving packets sent from IUT and Tester "
              "sockets, and a CSAP for sending a packet to IUT.");

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_gw->ta, 0,
        gw_iut_if->if_name,
        TAD_ETH_RECV_NO,
        (const uint8_t *)gw_iut_lladdr->sa_data,
        (const uint8_t *)iut_lladdr->sa_data,
        tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &csap_send));

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0,
        tst_if->if_name,
        TAD_ETH_RECV_OUT, NULL, NULL,
        tst_addr->sa_family,
        TAD_SA2ARGS(iut_addr, tst_addr), &csap_recv_tst));

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_gw->ta, 0,
        gw_iut_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL, tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &csap_recv_iut));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_recv_tst, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("If @p enable_timestamps is @c TRUE, enable TCP timestamps on IUT "
              "and Tester; otherwise disable them.");

    CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &iut_ts_val,
                                     "net/ipv4/tcp_timestamps"));
    if (enable_timestamps)
    {
        if (!iut_ts_val)
            TEST_FAIL("Timestamps on IUT should have been enabled in "
                      "timestamps_prologue");

        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_tst->ta, 1, NULL,
                                         "net/ipv4/tcp_timestamps"));
    }
    else
    {
        if (iut_ts_val)
            TEST_FAIL("Timestamps on IUT should have been disabled in "
                      "timestamps_prologue");

        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_tst->ta, 0, NULL,
                                         "net/ipv4/tcp_timestamps"));
    }

    TEST_STEP("Establish TCP connection between IUT and Tester according to "
              "@p sock_type.");

    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, &iut_l);

    TEST_STEP("Send some data in both directions over the connection.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("Close Tester socket, so that IUT socket receives @c FIN and moves to "
              "@c CLOSE_WAIT state.");

    RPC_CLOSE(pco_tst, tst_s);
    TAPI_WAIT_NETWORK;

    CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap_recv_iut, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Block network connectivity from Tester to IUT, so that ACK from "
              "Tester will not reach IUT.");

    CHECK_RC(tapi_route_gateway_break_tst_gw(&gateway));
    CFG_WAIT_CHANGES;

    TEST_STEP("Call @b shutdown(@c SHUT_WR) on IUT socket, so that it moves to "
              "@c LAST_ACK state.");

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
    TAPI_WAIT_NETWORK;

    if (tapi_get_tcp_sock_state(pco_iut, iut_s) != RPC_TCP_LAST_ACK)
        TEST_VERDICT("LAST_ACK state was not achieved");

    CHECK_RC(tapi_tad_trrecv_get(pco_gw->ta, 0, csap_recv_iut,
                                 &iut_cb_data, NULL));
    if (iut_data.failed || !iut_data.fin_received)
        TEST_FAIL("Failed to capture FIN packet from IUT");

    TEST_STEP("With help of CSAP send a packet to IUT based on the last packet "
              "sent by Tester socket but with some fields modified according to "
              "@p send_syn, @p seqn_mod, @p ts_value_mod and @p ts_echo_mod (take "
              "the latter two ones into account only if @p enable_timestamps is "
              "@c TRUE).");

    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, csap_recv_tst,
                                  &tst_cb_data, NULL));
    if (tst_data.failed)
        TEST_FAIL("Failed to parse TCP packets sent from Tester");
    if (!tst_data.captured)
        TEST_FAIL("Failed to capture any packets from Tester");

    if (send_syn)
    {
        syn_flag = TRUE;
        ack_flag = FALSE;
        pkt_ackn = 0;
        data = NULL;
        data_len = 0;
    }
    else
    {
        syn_flag = FALSE;
        ack_flag = TRUE;
        pkt_ackn = tst_data.ackn;
        data = send_buf;
        data_len = rand_range(MODIFIER_VALUE, SOCKTS_MSG_STREAM_MAX);
        te_fill_buf(data, data_len);
    }

    pkt_seqn = modify_value(tst_data.seqn, seqn_mod);

    CHECK_RC(tapi_tcp_template(force_ip6, pkt_seqn,
                               pkt_ackn, syn_flag, ack_flag,
                               (uint8_t *)data, data_len, &pkt_tmpl));

    if (enable_timestamps)
    {
        if (!tst_data.timestamped)
            TEST_FAIL("The last packet sent from Tester did not "
                      "have TCP timestamp");

        pkt_ts_value = modify_value(tst_data.ts_value, ts_value_mod);

        if (send_syn)
            pkt_ts_echo = 0;
        else
            pkt_ts_echo = modify_value(tst_data.ts_echo, ts_echo_mod);

        CHECK_RC(tapi_tcp_set_ts_opt(pkt_tmpl, pkt_ts_value,
                                     pkt_ts_echo));
    }

    CHECK_RC(tapi_tad_trsend_start(pco_gw->ta, 0, csap_send, pkt_tmpl,
                                   RCF_MODE_BLOCKING));

    TAPI_WAIT_NETWORK;

    TEST_STEP("Check and report what IUT socket sends in response.");

    CHECK_RC(tapi_tad_trrecv_get(pco_gw->ta, 0, csap_recv_iut,
                                 &iut_cb_data, NULL));
    if (iut_data.failed)
        TEST_FAIL("Failed to parse TCP packets sent from IUT");

    TEST_STEP("Check that socket remains in @c LAST_ACK state if @c SYN "
              "was sent to it, or moved to @c CLOSE state otherwise.");

    if (send_syn)
        exp_state = RPC_TCP_LAST_ACK;
    else
        exp_state = RPC_TCP_CLOSE;

    got_state = tapi_get_tcp_sock_state(pco_iut, iut_s);
    if (got_state != exp_state)
        RING_VERDICT("At the end socket state is %s instead of %s",
                     tcp_state_rpc2str(got_state),
                     tcp_state_rpc2str(exp_state));

    TEST_STEP("Check whether IUT socket continues to send @c FIN retransmits.");

    VSLEEP(3, "waiting for FIN retransmits");

    iut_data.retr_check = TRUE;
    iut_data.fin_retr = FALSE;
    CHECK_RC(tapi_tad_trrecv_stop(pco_gw->ta, 0, csap_recv_iut,
                                  &iut_cb_data, NULL));
    if (iut_data.failed)
        TEST_FAIL("Failed to parse last TCP packets sent from IUT");

    if (got_state == RPC_TCP_LAST_ACK)
    {
        if (!iut_data.fin_retr)
            RING_VERDICT("IUT socket stopped FIN retransmitting while "
                         "socket is still in LAST_ACK state");
    }
    else
    {
        if (iut_data.fin_retr)
            RING_VERDICT("IUT socket continues FIN retransmitting after "
                         "socket moved to %s state",
                         tcp_state_rpc2str(got_state));
    }

    TEST_STEP("Check that no data can be read from IUT socket.");

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 0);
    if (readable)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_recv(pco_iut, iut_s, recv_buf, sizeof(recv_buf),
                      RPC_MSG_DONTWAIT);
        if (rc > 0)
            TEST_VERDICT("Some data was read from IUT socket at the end");
    }
    else
    {
        ERROR_VERDICT("IUT socket is not readable after sending FIN to it");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    asn_free_value(pkt_tmpl);

    TEST_END;
}
