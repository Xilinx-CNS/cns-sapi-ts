/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 *
 */

/** @page tcp-rtt_calc Check that TCP connection correctly calculates RTT
 *
 * @objective  Compare the difference between the calculated RTO and
 *             the RTO obtained during the retransmit process.
 *
 * @param passive_open            Connection establishment way:
 *      - active
 *      - passive_open
 * @param send_aux_data           Send data to update RTO
 * @param iut_timestamps_enable   Enable or disable timestamps on IUT
 * @param tst_timestamps_enable   Enable or disable timestamps on TST
 *
 * @par Scenario:
 *
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/rtt_calc"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_tcp.h"
#include "tapi_route_gw.h"

#include "ndn_ipstack.h"

/**
 * Allowed relative difference for measured RTO
 * if it is less than expected one. This number
 * cannot be 0.5 or more, since RTO expectation
 * is multiplied by 2 after each retransmit,
 * and x * 2 * 0.5 = x.
 */
#define RTO_PRECISION_LESS 0.3

/**
 * Allowed relative difference for measured RTO
 * if it is more than expected one.
 */
#define RTO_PRECISION_MORE 0.6

/** How long to wait for initial packet, in milliseconds */
#define INITIAL_TIMEOUT 500

/** How long to wait for retransmits, in milliseconds */
#define RTO_TIMEOUT 10000

/** RTT delay, in milliseconds */
#define RTT_DELAY 300

/** Data size to transmit */
#define DATA_SIZE 500

/** Constants for RTT computation defined in RFC 2988. */
#define RTT_ALPHA (1.0 / 8.0)
#define RTT_BETA (1.0 / 4.0)
#define RTT_K 4.0
#define RTO_DEFAULT 3000

#define SET_TIMESTAMPS(pco_, timestamps_enable_, init_val_, is_changed_) \
    do {                                                                     \
        CHECK_RC(tapi_cfg_sys_ns_get_int(pco_->ta, &timestamps_val,          \
                                         "net/ipv4/tcp_timestamps"));        \
                                                                             \
        if (timestamps_val != (timestamps_enable_ ? 1 : 0))                  \
        {                                                                    \
            RING("Set timestamps on %s to %d", #pco_, timestamps_enable_);   \
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_->ta,                       \
                                             timestamps_enable_ ? 1 : 0,     \
                                             &init_val_,                     \
                                             "net/ipv4/tcp_timestamps"));    \
            is_changed_ = TRUE;                                              \
        }                                                                    \
    } while(0)

/** Structure describing TCP packet. */
typedef struct tcp_packet {
    TAILQ_ENTRY(tcp_packet)    links;   /**< Queue links. */

    uint32_t    flags;                  /**< TCP flags. */
    uint32_t    seqn;                   /**< SEQN. */
    uint32_t    ackn;                   /**< ACKN. */
    uint32_t    exp_ackn;               /**< Expected ACKN from peer. */
    uint32_t    got_ackn;               /**< Got ACKN from peer. */
    uint32_t    ts_sent;                /**< TCP timestamp. */
    int64_t     first_sent_ts;          /**< Timestamp of the first sending
                                             of this packet (ms). */
    int64_t     ack_ts;                 /**< Timestamp of ACK arrival for
                                             this packet (ms). */
    int         retransmits;            /**< Number of retransmits. */
    te_bool     ts_echo;                /**< Whether ACK for this packet
                                             had filled echo-reply field
                                             in TCP timestamp. */
    int         rtt;                    /**< RTT value. */
    int         rttvar;                 /**< RTTVAR value. */
    int         rto;                    /**< RTO value. */

    /*
     * These variables mimic behavior of hidden variables
     * Linux uses to compute RTO. See tcp_rtt_estimator() in
     * net/ipv4/tcp_input.c
     */
    int         rttvar_max;
    int         rttvar_us;
} tcp_packet;

/**< Type of the TCP packets queue head. */
typedef TAILQ_HEAD(tcp_packets, tcp_packet) tcp_packets;

/** Data passed to estimation_handler() callback. */
typedef struct handler_data {
    const struct sockaddr   *iut_addr;  /**< IUT IP address. */
    const struct sockaddr   *tst_addr;  /**< Tester IP address. */

    tcp_packets              packets;   /**< Queue of captured TCP
                                             packets from IUT. */
    te_bool                  failed;    /**< Will be set to TRUE if
                                             packets processing failed. */

    te_bool     collect_retransmits;    /**< If TRUE, a separate
                                             packet will be added to queue
                                             for every retransmit. Such
                                             queue cannot be used for RTO
                                             computation. */

    te_bool                  ip6;       /**< If TRUE, IPv6 is used. */
} handler_data;

/**
 * Release memory occupied by elements of tcp_packets queue,
 * remove them from the queue.
 *
 * @param packets       Pointer to the queue's head.
 */
static void
free_tcp_packets(tcp_packets *packets)
{
    tcp_packet *p;
    tcp_packet *q;

    TAILQ_FOREACH_SAFE(p, packets, links, q)
    {
        TAILQ_REMOVE(packets, p, links);
        free(p);
    }
}

/**
 * Get timestamp (in milliseconds) from a packet captured by CSAP.
 *
 * @param pkt       Packet captured by CSAP.
 *
 * @return Timestamp (or @c -1 in case of failure).
 */
static int64_t
get_timestamp(asn_value *pkt)
{
    struct timeval tv;
    int            rc = 0;

    rc = sockts_get_csap_pkt_ts(pkt, &tv);
    if (rc != 0)
        return -1;

    return tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
}

/**
 * Process packet sent from IUT.
 *
 * @param pkt     Packet captured by CSAP.
 * @param data    Packet handler data.
 */
static void
process_iut_packet(asn_value *pkt, handler_data *data)
{
    int32_t      cur_seqn = 0;
    int32_t      cur_ackn = 0;
    int32_t      next_ackn = 0;
    uint32_t     ts_sent = 0;
    int32_t      flags = 0;
    int          rc = 0;
    int64_t      ts = 0;

    tcp_packet  *tpacket = NULL;

    ts = get_timestamp(pkt);
    if (ts < 0)
    {
        RING("Failed to get timestamp");
        data->failed = TRUE;
        return;
    }

    rc = asn_read_int32(pkt, &cur_seqn,
                        "pdus.0.#tcp.seqn");
    if (rc != 0)
    {
        ERROR("Failed to get SEQN: %r", rc);
        data->failed = TRUE;
        return;
    }

    rc = sockts_tcp_payload_len(pkt);
    if (rc < 0)
    {
        ERROR("Failed to get payload length: %r", rc);
        data->failed = TRUE;
        return;
    }
    next_ackn = cur_seqn + rc;

    rc = asn_read_int32(pkt, &flags, "pdus.0.#tcp.flags");
    if (rc < 0)
    {
        ERROR("Failed to get TCP flags: %r", rc);
        data->failed = TRUE;
        return;
    }
    if (flags & (TCP_SYN_FLAG | TCP_FIN_FLAG))
        next_ackn++;

    rc = tapi_tcp_get_ts_opt(pkt, &ts_sent, NULL);
    if (rc != 0 && rc != TE_ENOENT)
    {
        ERROR("tapi_tcp_get_ts_opt() returned %r", rc);
        data->failed = TRUE;
        return;
    }

    rc = asn_read_int32(pkt, &cur_ackn,
                        "pdus.0.tcp.ackn");
    if (rc != 0)
    {
        ERROR("Failed to get ACKN: %r", rc);
        data->failed = TRUE;
        return;
    }

    if (data->collect_retransmits)
    {
        tpacket = TE_ALLOC(sizeof(*tpacket));
        if (tpacket == NULL)
        {
            data->failed = TRUE;
            return;
        }
        tpacket->seqn = cur_seqn;
        tpacket->ackn = cur_ackn;
        tpacket->exp_ackn = next_ackn;
        tpacket->first_sent_ts = ts;
        tpacket->ts_sent = ts_sent;
        tpacket->flags = flags;

        TAILQ_INSERT_TAIL(&data->packets, tpacket, links);
    }
    else
    {
        TAILQ_FOREACH(tpacket, &data->packets, links)
        {
            if (tpacket->seqn == (uint32_t)cur_seqn &&
                tpacket->exp_ackn == (uint32_t)next_ackn)
                break;
        }

        if (tpacket == NULL)
        {
            if (cur_seqn != next_ackn)
            {
                tpacket = TE_ALLOC(sizeof(*tpacket));
                if (tpacket == NULL)
                {
                    data->failed = TRUE;
                    return;
                }
                tpacket->seqn = cur_seqn;
                tpacket->ackn = cur_ackn;
                tpacket->exp_ackn = next_ackn;
                tpacket->first_sent_ts = ts;
                tpacket->ts_sent = ts_sent;
                tpacket->flags = flags;

                TAILQ_INSERT_TAIL(&data->packets, tpacket, links);
            }
        }
        else
        {
            tpacket->retransmits++;
        }
    }
}

/**
 * Process packet sent from Tester.
 *
 * @param pkt     Packet captured by CSAP.
 * @param data    Packet handler data.
 */
static void
process_tst_packet(asn_value *pkt, handler_data *data)
{
    int32_t      cur_ackn = 0;
    int          rc = 0;
    int64_t      ts = 0;
    uint32_t     ts_echo;

    tcp_packet  *tpacket = NULL;

    ts = get_timestamp(pkt);
    if (ts < 0)
    {
        RING("Failed to get timestamp");
        data->failed = TRUE;
        return;
    }

    rc = tapi_tcp_get_ts_opt(pkt, NULL, &ts_echo);
    if (rc != 0 && rc != TE_ENOENT)
    {
        ERROR("tapi_tcp_get_ts_opt() returned %r", rc);
        data->failed = TRUE;
        return;
    }

    rc = asn_read_int32(pkt, &cur_ackn,
                        "pdus.0.tcp.ackn");
    if (rc != 0)
    {
        ERROR("Failed to get ACKN: %r", rc);
        data->failed = TRUE;
        return;
    }

    TAILQ_FOREACH(tpacket, &data->packets, links)
    {
        if (tpacket->ack_ts == 0 &&
            (int)(tpacket->exp_ackn - cur_ackn) >= 0)
        {
            tpacket->ack_ts = ts;
            if (ts_echo > 0)
                tpacket->ts_echo = TRUE;
        }
    }
}

/**
 * CSAP callback used to capture packets sent via tested
 * TCP connection.
 *
 * @param pkt         Packet captured by CSAP.
 * @param userdata    Pointer to handler_data structure.
 */
static void
estimation_handler(asn_value *pkt, void *userdata)
{
    handler_data     *data = (handler_data *)userdata;
    int               rc = 0;

    sockts_addrs_direction dir;

    if (data->failed)
        return;

    rc = sockts_tcp_asn_addrs_match(pkt, data->iut_addr, data->tst_addr,
                                    &dir);
    if (rc != 0)
    {
        data->failed = TRUE;
        goto cleanup;
    }

    if (dir == SOCKTS_ADDRS_FORWARD)
    {
        process_iut_packet(pkt, data);
    }
    else if (dir == SOCKTS_ADDRS_BACKWARD)
    {
        process_tst_packet(pkt, data);
    }

cleanup:

    asn_free_value(pkt);
}

/**
 * Send TCP packet with CSAP.
 *
 * @param force_ip6   TRUE for IPv6 PDU,
 *                    FALSE for IPv4 PDU.
 * @param ta          Test Agent name.
 * @param csap        CSAP handle.
 * @param seqn        SEQN.
 * @param ackn        ACKN,
 * @param syn_flag    Whether to set SYN flag.
 * @param ack_flag    Whether to set ACK flag.
 * @param insert_ts   Whether to insert TCP timestamp (if
 *                    a peer uses it too).
 * @param tv_start    A moment of time from which we compute
 *                    our TCP timestamp.
 * @param echo_ts     Value for "echo-reply" field of TCP timestamp.
 */
static void
csap_send_tcp_packet(te_bool force_ip6, const char *ta, csap_handle_t csap,
                     uint32_t seqn, uint32_t ackn,
                     te_bool syn_flag, te_bool ack_flag,
                     te_bool insert_ts, struct timeval *tv_start,
                     int32_t echo_ts)
{
    asn_value       *pkt_templ = NULL;
    struct timeval  tv_cur;

    CHECK_RC(tapi_tcp_template(force_ip6, seqn, ackn, syn_flag, ack_flag,
                               NULL, 0, &pkt_templ));
    if (insert_ts && (echo_ts != 0 || (syn_flag && ackn == 0)))
    {
        if (gettimeofday(&tv_cur, NULL) < 0)
            TEST_FAIL("gettimeofday() failed");

        CHECK_RC(tapi_tcp_set_ts_opt(pkt_templ,
                                     TIMEVAL_SUB(tv_cur, *tv_start),
                                     echo_ts));
    }

    CHECK_RC(tapi_tad_trsend_start(ta, 0, csap, pkt_templ,
                                   RCF_MODE_BLOCKING));
    asn_free_value(pkt_templ);
}

/**
 * Send ACKs to all received TCP packets which are not acked yet.
 *
 * @param force_ip6   TRUE for IPv6 PDU,
 *                    FALSE for IPv4 PDU.
 * @param ta          Test Agent name,
 * @param csap        CSAP handler.
 * @param seqn        SEQN.
 * @param insert_ts   Whether to insert TCP timestamp.
 * @param tv_start    A moment from which we compute our timestamp.
 * @param packets     Queue of TCP packets sent from IUT.
 */
static void
csap_send_tcp_acks(te_bool force_ip6, const char *ta, csap_handle_t csap,
                   uint32_t *seqn,
                   te_bool insert_ts, struct timeval *tv_start,
                   tcp_packets *packets)
{
    tcp_packet *packet = NULL;
    te_bool     syn_flag = FALSE;

    TAILQ_FOREACH(packet, packets, links)
    {
        if (packet->ack_ts == 0)
        {
            if ((packet->flags & TCP_SYN_FLAG) &&
                packet->ackn == 0)
                syn_flag = TRUE;
            else
                syn_flag = FALSE;

            csap_send_tcp_packet(force_ip6, ta, csap, *seqn, packet->exp_ackn,
                                 syn_flag, TRUE, insert_ts, tv_start,
                                 packet->ts_sent);

            if (syn_flag)
                (*seqn)++;
        }
    }
}

/**
 * Compute TCP RTO.
 *
 * @param packets     Queue of TCP packets sent from IUT.
 *
 * @return RTO value.
 */
static int
compute_rto(tcp_packets *packets)
{
    tcp_packet *packet = NULL;
    tcp_packet *prev_packet = NULL;

    int diff_ts;
    int rto = 0;

    TAILQ_FOREACH(packet, packets, links)
    {
        if ((packet->retransmits > 0 && !packet->ts_echo) ||
            packet->ack_ts == 0)
        {
            if (prev_packet != NULL)
            {
                packet->rtt = prev_packet->rtt;
                packet->rttvar = prev_packet->rttvar;
                packet->rto = prev_packet->rto;
            }
            else
            {
                packet->rtt = 0;
                packet->rttvar = RTO_DEFAULT / 4;
                packet->rto = RTO_DEFAULT;
            }
        }
        else
        {
            diff_ts = packet->ack_ts - packet->first_sent_ts;

            if (prev_packet != NULL && prev_packet->rtt != 0)
            {
                packet->rttvar =
                      (1.0 - RTT_BETA) * (double)prev_packet->rttvar +
                      RTT_BETA * (double)abs(prev_packet->rtt - diff_ts);
                packet->rtt = (1.0 - RTT_ALPHA) * (double)prev_packet->rtt +
                              RTT_ALPHA * (double)diff_ts;

                /*
                 * See comment about hidden Linux variables below
                 * made for RTO computation.
                 */

                if (packet->rttvar > prev_packet->rttvar_max)
                    packet->rttvar_max = packet->rttvar;
                else
                    packet->rttvar_max = prev_packet->rttvar_max;

                if (packet->rttvar_max > prev_packet->rttvar_us)
                    packet->rttvar_us = packet->rttvar_max;
                else
                    packet->rttvar_us =
                        prev_packet->rttvar_us -
                        (prev_packet->rttvar_us - packet->rttvar_max) / 4.0;

                packet->rttvar_max = 0;
            }
            else
            {
                packet->rtt = diff_ts;
                packet->rttvar = packet->rtt / 2;

                packet->rttvar_max = packet->rttvar;
                packet->rttvar_us = packet->rttvar;
            }

#if 0
            /*
             * This is how Linux computes RTO. Instead of rttvar it
             * reports in TCP_INFO it uses hidded rttvar_us,
             * see tcp_rtt_estimator() in net/ipv4/tcp_input.c
             *
             * It seems Onload does not follow Linux here.
             */
            packet->rto = packet->rtt + RTT_K * packet->rttvar_us;
#else
            packet->rto = packet->rtt + RTT_K * packet->rttvar;
#endif
        }

        rto = packet->rto;
        prev_packet = packet;
    }

    return rto;
}

/**
 * Print table of TCP packets sent from IUT, together with
 * computed RTT/RTTVAR/RTO values.
 *
 * @param packets       Queue of TCP packets.
 */
static void
print_tcp_packets_rtt(tcp_packets *packets)
{
    tcp_packet   *packet = NULL;
    te_string     str = TE_STRING_INIT;

    te_string_append(&str, "%20s%20s%20s%15s%10s%8s"
                     "%8s%10s%8s\n",
                     "SEQN", "SENT TS",
                     "ACK TS", "RETRANSMITS",
                     "TS ECHO", "RTT", "RTTVAR", "RTTVAR_US", "RTO");

    TAILQ_FOREACH(packet, packets, links)
    {
        te_string_append(&str, "%20u%20u%20u%15u%10s%8u"
                         "%8u%10u%8u\n",
                         packet->seqn, packet->first_sent_ts,
                         packet->ack_ts, packet->retransmits,
                         (packet->ts_echo ? "true" : "false"),
                         packet->rtt, packet->rttvar,
                         packet->rttvar_us, packet->rto);
    }

    RING("%s", str.ptr);
    te_string_free(&str);
}

/**
 * Print table of TCP packets sent from IUT.
 *
 * @param packets       Queue of TCP packets.
 */
static void
print_tcp_packets(tcp_packets *packets)
{
    tcp_packet   *packet = NULL;
    te_string     str = TE_STRING_INIT;

    te_string_append(&str, "%20s%20s%20s%20s\n",
                     "SEQN", "EXP ACKN", "SENT TS",
                     "ACK TS");

    TAILQ_FOREACH(packet, packets, links)
    {
        te_string_append(&str, "%20u%20u%20u%20u\n",
                         packet->seqn, packet->exp_ackn,
                         packet->first_sent_ts, packet->ack_ts);
    }

    RING("%s", str.ptr);
    te_string_free(&str);
}

/**
 * Process packets captured by CSAP, stop testing
 * if something went wrong.
 *
 * @param ta        Test Agent name.
 * @param csap      CSAP handle.
 * @param cb_data   Callback data.
 */
static void
csap_process_packets(const char *ta, csap_handle_t csap,
                     tapi_tad_trrecv_cb_data *cb_data)
{
    handler_data *data = (handler_data *)cb_data->user_data;

    CHECK_RC(tapi_tad_trrecv_get(ta, 0, csap,
                                 cb_data, NULL));
    if (data->failed)
        TEST_FAIL("Failed to process captured packets");
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    const struct sockaddr *gw_tst_lladdr;

    tsa_session        ss = TSA_SESSION_INITIALIZER;
    te_bool            passive_open;

    int                iut_s = -1;
    int                iut_s_listener = -1;

    int                init_iut_timestamps_val;
    int                timestamps_val;
    te_bool            send_aux_data;
    te_bool            iut_timestamps_enable;
    te_bool            tst_timestamps_enable;
    te_bool            iut_timestamps_changed = FALSE;

    char              *sndbuf    = NULL;

    unsigned long      rto_init;
    unsigned long      rto_act;
    unsigned long      rto_exp;
    double             rto_diff;

    csap_handle_t             csap_recv = CSAP_INVALID_HANDLE;
    csap_handle_t             csap_send = CSAP_INVALID_HANDLE;
    tapi_tad_trrecv_cb_data   cb_data;
    handler_data              data;
    uint32_t                  next_seqn = 0;

    struct timeval       tv_start;
    struct rpc_tcp_info  tcp_info;
    tcp_packet          *tcp_pkt = NULL;
    tcp_packet          *tcp_pkt_prev = NULL;
    te_bool              test_failed = FALSE;
    te_bool              free_packets = FALSE;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_LINK_ADDR(gw_tst_lladdr);
    TEST_GET_BOOL_PARAM(iut_timestamps_enable);
    TEST_GET_BOOL_PARAM(tst_timestamps_enable);
    TEST_GET_BOOL_PARAM(send_aux_data);
    TEST_GET_BOOL_PARAM(passive_open);

    TEST_STEP("Enable/disable TCP timestamps according to @p iut_timestamps_enable "
              "on IUT.");
    SET_TIMESTAMPS(pco_iut, iut_timestamps_enable, init_iut_timestamps_val,
                   iut_timestamps_changed);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    tapi_route_gateway_break_gw_tst(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a CSAP @b csap_recv on gateway to capture TCP packets from the "
              "tested TCP connection.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_gw->ta, 0, gw_iut_if->if_name,
        TAD_ETH_RECV_OUT | TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL, gw_iut_addr->sa_family, NULL, NULL, -1, -1,
        &csap_recv));

    TEST_STEP("Create a CSAP @b csap_send on Tester to simulate TCP socket "
              "there.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        (uint8_t *)alien_link_addr->sa_data,
        (uint8_t *)gw_tst_lladdr->sa_data,
        tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &csap_send));

    TEST_STEP("Start capturing packets with @b csap_recv.");
    CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap_recv, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));

    memset(&data, 0, sizeof(data));
    TAILQ_INIT(&data.packets);
    free_packets = TRUE;
    data.iut_addr = iut_addr;
    data.tst_addr = tst_addr;
    data.ip6 = rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET6 ?
               TRUE : FALSE;

    cb_data.callback = &estimation_handler;
    cb_data.user_data = &data;

    if (tst_timestamps_enable)
    {
        if (gettimeofday(&tv_start, NULL) < 0)
            TEST_FAIL("gettimeofday() failed");
    }

    next_seqn = rand_range(1, INT_MAX);

    TEST_STEP("Create connected TCP socket on IUT, establishing connection "
              "according to @p passive_open. Wait for @c RTT_DELAY before "
              "sending ACKs from Tester.");

    if (passive_open)
    {
        iut_s_listener = rpc_socket(pco_iut,
                                    rpc_socket_domain_by_addr(iut_addr),
                                    RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s_listener, iut_addr);
        rpc_listen(pco_iut, iut_s_listener, SOCKTS_BACKLOG_DEF);

        csap_send_tcp_packet(data.ip6, pco_tst->ta, csap_send,
                             next_seqn, 0, TRUE, FALSE,
                             tst_timestamps_enable, &tv_start, 0);

        next_seqn++;

        MSLEEP(RTT_DELAY);
        csap_process_packets(pco_gw->ta, csap_recv, &cb_data);

        csap_send_tcp_acks(data.ip6, pco_tst->ta, csap_send, &next_seqn,
                           tst_timestamps_enable, &tv_start,
                           &data.packets);

        iut_s = rpc_accept(pco_iut, iut_s_listener, NULL, NULL);
    }
    else
    {
        iut_s = rpc_socket(pco_iut,
                           rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s, iut_addr);

        pco_iut->op = RCF_RPC_CALL;
        rpc_connect(pco_iut, iut_s, tst_addr);

        MSLEEP(RTT_DELAY);
        csap_process_packets(pco_gw->ta, csap_recv, &cb_data);

        csap_send_tcp_acks(data.ip6, pco_tst->ta, csap_send, &next_seqn,
                           tst_timestamps_enable, &tv_start,
                           &data.packets);

        rpc_connect(pco_iut, iut_s, tst_addr);
    }

    TEST_STEP("If @p send_aux_data is @c TRUE, send a packet from IUT "
              "and acknowledge it from Tester after @c RTT_DELAY.");

    sndbuf = te_make_buf_by_len(DATA_SIZE);

    if (send_aux_data)
    {
        rpc_send(pco_iut, iut_s, sndbuf, DATA_SIZE, 0);

        MSLEEP(RTT_DELAY);
        csap_process_packets(pco_gw->ta, csap_recv, &cb_data);

        csap_send_tcp_acks(data.ip6, pco_tst->ta, csap_send, &next_seqn,
                           tst_timestamps_enable, &tv_start,
                           &data.packets);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Process TCP packets captured by @b csap_recv. Compute "
              "TCP RTO from them.");

    csap_process_packets(pco_gw->ta, csap_recv, &cb_data);

    rto_init = compute_rto(&data.packets);
    print_tcp_packets_rtt(&data.packets);

    TEST_STEP("Obtain RTO value from TCP_INFO option, check that it "
              "does not differ too much from our estimation. If RTO from "
              "TCP_INFO structure is zero, assume it is not supported.");

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &tcp_info);
    if (tcp_info.tcpi_rto != 0)
    {
        rto_diff =
          ((double)TE_US2MS(tcp_info.tcpi_rto) - (double)rto_init) /
          (double)rto_init;
        if (rto_diff > RTO_PRECISION_MORE ||
            (rto_diff < 0 && (-rto_diff) > RTO_PRECISION_LESS))
        {
            RING("Estimated RTO %lu, RTO from TCP_INFO %u, rto_diff=%f",
                 rto_init, (unsigned long)TE_US2MS(tcp_info.tcpi_rto),
                 rto_diff);
            ERROR_VERDICT("RTO value reported by TCP_INFO option "
                          "is significantly %s than our estimation",
                          (TE_US2MS(tcp_info.tcpi_rto) > rto_init ?
                               "more" : "less"));
        }
        rto_init = TE_US2MS(tcp_info.tcpi_rto);
    }
    else
    {
        RING_VERDICT("RTO value in TCP_INFO structure is zero");
    }

    TEST_STEP("Send some data from IUT but don't send ACK back.");
    pco_iut->op = RCF_RPC_CALL;
    rpc_send(pco_iut, iut_s, sndbuf, DATA_SIZE, 0);

    TEST_STEP("Wait for @c RTO_TIMEOUT. After that check that "
              "@b csap_recv captured retransmitted packets and "
              "their timing matches our expectation.");
    MSLEEP(RTO_TIMEOUT);

    free_tcp_packets(&data.packets);
    data.collect_retransmits = TRUE;
    csap_process_packets(pco_gw->ta, csap_recv, &cb_data);
    print_tcp_packets(&data.packets);

    rto_act = 0;
    rto_exp = rto_init;
    TAILQ_FOREACH(tcp_pkt, &data.packets, links)
    {
        if (tcp_pkt_prev != NULL)
        {
            rto_act = tcp_pkt->first_sent_ts - tcp_pkt_prev->first_sent_ts;

            RING("Actual retransmit time: %lu, estimated expected time: %lu",
                  rto_act, rto_exp);

            if (rto_act > rto_exp * (1 + RTO_PRECISION_MORE) ||
                rto_act < rto_exp * (1 - RTO_PRECISION_LESS))
            {
                /** Finish sending in case of test fail */
                ERROR_VERDICT("Retransmit time differ too much");
                test_failed = TRUE;
                break;
            }

            rto_exp = rto_act * 2;
        }
        tcp_pkt_prev = tcp_pkt;
    }

    if (rto_act == 0)
    {
        ERROR_VERDICT("Failed to capture any retransmits");
        test_failed = TRUE;
    }

    if (tcp_pkt_prev != NULL)
    {
        /* Send ACK. */
        csap_send_tcp_packet(data.ip6, pco_tst->ta, csap_send, next_seqn,
                             tcp_pkt_prev->exp_ackn,
                             FALSE, TRUE,
                             tst_timestamps_enable,
                             &tv_start, tcp_pkt_prev->ts_sent);
    }

    TEST_STEP("Finish send operation.");
    rpc_send(pco_iut, ss.state.iut_s, sndbuf, DATA_SIZE, 0);

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (free_packets)
        free_tcp_packets(&data.packets);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_gw->ta, 0,
                                           csap_recv));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                           csap_send));

    if (iut_timestamps_changed)
        CLEANUP_CHECK_RC(
            tapi_cfg_sys_ns_set_int(pco_iut->ta, init_iut_timestamps_val,
                                    NULL, "net/ipv4/tcp_timestamps"));

    free(sndbuf);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listener);

    TEST_END;
}
