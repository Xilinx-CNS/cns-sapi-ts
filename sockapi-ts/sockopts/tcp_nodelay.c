/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-tcp_nodelay Usage of TCP_NODELAY socket option
 *
 * @objective Check that Nagle algorithm is disabled when @c TCP_NODELAY
 *            socket option is switched on, and enabled otherwise.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.10
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_peer2peer_gw
 *                    - @ref arg_types_env_peer2peer_gw_ipv6
 *
 * @par Test sequence:
 *
 * @note
 *    From @ref STEVENS, section 7.9:\n
 *    The Nagle algorithm states that if a given connection has outstanding
 *    data (that is, data that our TCP has sent, and for which it is
 *    currently awaiting an acknowledgement), then no small packets will be
 *    sent on the connection until the existing data is acknowledged.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_nodelay"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"
#include "te_time.h"
#include "tapi_tcp.h"

/**
 * Convert struct timeval to microseconds since epoch.
 *
 * @param _tv       struct timeval to convert.
 */
#define TV2US(_tv) ((_tv).tv_sec * 1000000LL + (_tv).tv_usec)

/**
 * If TCP_NODELAY is enabled, less than this time (in us) should
 * pass between sending two packets.
 */
#define NODELAY_TIMEOUT 50000

/** Auxiliary structure to communicate with CSAP callback */
typedef struct csap_data {
    int64_t                last_seqn;   /**< SEQN of the last captured
                                             packet */
    unsigned int           pkts;        /**< Incremented every time a packet
                                             with bigger SEQN is captured */
    long long unsigned int ts;          /**< Timestamp of the first packet
                                             with the current SEQN */
    te_bool                failed;      /**< Is set to TRUE if some failure
                                             occurred when processing
                                             packets */
} csap_data;

/**
 * Process a packet captured by CSAP.
 *
 * @param pkt         Packet captured by CSAP.
 * @param user_data   Pointer to csap_data structure.
 */
static void
csap_cb(asn_value *pkt, void *user_data)
{
    csap_data *data = (csap_data *)user_data;
    struct timeval tv;
    te_errno rc;
    uint32_t seqn;

    if (data->failed)
        goto cleanup;

    rc = asn_read_uint32(pkt, &seqn, "pdus.0.#tcp.seqn");
    if (rc != 0)
    {
        ERROR("Failed to get TCP SEQN, rc=%r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    if (data->last_seqn >= 0 &&
        tapi_tcp_compare_seqn(seqn, data->last_seqn) <= 0)
        goto cleanup;

    data->pkts++;
    data->last_seqn = seqn;

    rc = sockts_get_csap_pkt_ts(pkt, &tv);
    if (rc != 0)
    {
        data->failed = TRUE;
        goto cleanup;
    }

    data->ts = TV2US(tv);

cleanup:

    asn_free_value(pkt);
}

/**
 * Process packets captured by CSAP to get timestamp
 * of the last packet (not taking into account its
 * retransmits).
 *
 * @param ta            TA on which CSAP is created.
 * @param csap          CSAP handle.
 * @param user_data     Pointer to csap_data.
 * @param msg           Message to print in verdicts.
 */
static void
process_csap_pkts(const char *ta, csap_handle_t csap,
                  csap_data *user_data, const char *msg)
{
    tapi_tad_trrecv_cb_data cb_data;
    unsigned int num;

    memset(&cb_data, 0, sizeof(cb_data));
    cb_data.callback = &csap_cb;
    cb_data.user_data = user_data;

    user_data->pkts = 0;
    CHECK_RC(tapi_tad_trrecv_get(ta, 0, csap, &cb_data, &num));
    if (num == 0)
    {
        TEST_VERDICT("%s: CSAP did not capture a packet", msg);
    }
    else if (user_data->pkts > 1)
    {
        TEST_VERDICT("%s: CSAP captured more than a single packet", msg);
    }
    else if (user_data->failed)
    {
        TEST_VERDICT("%s: failed to process captured packet", msg);
    }
}

/**
 * Send a packet from IUT, capture it with CSAP, receive it on Tester.
 *
 * @param pco_iut         RPC server on IUT.
 * @param iut_s           TCP socket on IUT.
 * @param tcp_conn        CSAP TCP socket emulation on Tester.
 * @param sent_data       Data to send.
 * @param sent_len        Length of data to send.
 * @param msg             Message to print in verdicts.
 */
static void
send_recv_pkt(rcf_rpc_server *pco_iut, int iut_s,
              tapi_tcp_handler_t tcp_conn,
              char *sent_data, size_t sent_len,
              const char *msg)
{
    int rc;
    te_dbuf recv_data = TE_DBUF_INIT(0);

    RPC_SEND(rc, pco_iut, iut_s, sent_data, sent_len, 0);

    rc = tapi_tcp_wait_msg(tcp_conn, TAPI_WAIT_NETWORK_DELAY);
    if (rc != 0)
    {
        if (rc == TE_RC(TE_TAPI, TE_ETIMEDOUT))
        {
            CHECK_RC(tapi_tcp_send_ack(tcp_conn,
                                       tapi_tcp_next_ackn(tcp_conn)));

            rc = tapi_tcp_wait_msg(tcp_conn, TAPI_WAIT_NETWORK_DELAY);
        }

        if (rc != 0)
        {
            TEST_VERDICT("%s: failed to wait for the packet, rc=%r",
                         msg, rc);
        }
    }

    CHECK_RC(tapi_tcp_recv_data(tcp_conn, 0, TAPI_TCP_QUIET, &recv_data));

    RING("Received %d bytes from peer", (int)(recv_data.len));
    if (recv_data.len != sent_len ||
        memcmp(sent_data, recv_data.ptr, sent_len) != 0)
    {
        te_dbuf_free(&recv_data);
        TEST_VERDICT("%s: received data does not match sent data", msg);
    }
    te_dbuf_free(&recv_data);
}

/**
 * Check how TCP_NODELAY option works.
 *
 * @param pco_iut         RPC server on IUT.
 * @param iut_s           TCP socket on IUT.
 * @param tcp_conn        CSAP TCP socket emulation on Tester.
 * @param nodelay_set     Whether TCP_NODELAY option is enabled.
 * @param csap            CSAP to capture packets sent from IUT.
 * @param csap_ta         TA on which CSAP was created.
 * @param msg             Message to print in verdicts.
 */
static void
check_nodelay(rcf_rpc_server *pco_iut, int iut_s,
              tapi_tcp_handler_t tcp_conn,
              te_bool nodelay_set,
              csap_handle_t csap, const char *csap_ta,
              const char *msg)
{
    char tx_buf[2];
    csap_data user_data;
    long long unsigned int ts1;
    long long unsigned int ts2;
    long long unsigned int ts_diff;

    te_string str = TE_STRING_INIT_STATIC(1024);

    memset(&user_data, 0, sizeof(user_data));
    user_data.last_seqn = -1;

    te_fill_buf(tx_buf, sizeof(tx_buf));

    CHECK_RC(te_string_append(&str, "%s, sending the first packet", msg));
    send_recv_pkt(pco_iut, iut_s, tcp_conn, &tx_buf[0], 1, str.ptr);
    process_csap_pkts(csap_ta, csap, &user_data, str.ptr);
    ts1 = user_data.ts;

    te_string_reset(&str);
    CHECK_RC(te_string_append(&str, "%s, sending the second packet", msg));
    send_recv_pkt(pco_iut, iut_s, tcp_conn, &tx_buf[1], 1, str.ptr);
    process_csap_pkts(csap_ta, csap, &user_data, str.ptr);
    ts2 = user_data.ts;

    CHECK_RC(tapi_tcp_send_ack(tcp_conn,
                               tapi_tcp_next_ackn(tcp_conn)));
    TAPI_WAIT_NETWORK;

    ts_diff = ts2 - ts1;
    RING("Timestamp of packet 1: %llu us\n"
         "Timestamp of packet 2: %llu us\n"
         "Difference=%llu us", ts1, ts2, ts_diff);

    if (nodelay_set && ts_diff >= NODELAY_TIMEOUT)
    {
        TEST_VERDICT("%s: too much time passed between sending two "
                     "packets", msg);
    }
    else if (!nodelay_set && ts_diff < NODELAY_TIMEOUT)
    {
        TEST_VERDICT("%s: too little time passed between sending two "
                     "packets", msg);
    }
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gw;

    const struct sockaddr *gw_tst_lladdr = NULL;

    int iut_l = -1;
    int iut_s = -1;
    int tst_s = -1;

    int opt_val;

    csap_handle_t csap = CSAP_INVALID_HANDLE;
    tapi_tcp_handler_t tcp_conn = 0;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_LINK_ADDR(gw_tst_lladdr);

    TEST_STEP("Configure routing between IUT and Tester via a "
              "gateway host.");
    TAPI_INIT_ROUTE_GATEWAY(gw);
    CHECK_RC(tapi_route_gateway_configure(&gw));

    TEST_STEP("Add neighbor entry with an alien MAC address for "
              "@p tst_addr on the gateway, so that only CSAP "
              "captures packets from IUT while Linux ignores them "
              "on Tester.");
    CHECK_RC(tapi_route_gateway_break_gw_tst(&gw));
    CFG_WAIT_CHANGES;

    TEST_STEP("Establish connection between TCP socket on IUT and "
              "CSAP TCP socket emulation on Tester.");

    iut_l = rpc_stream_server(pco_iut, RPC_PROTO_DEF, FALSE, iut_addr);

    CHECK_RC(tapi_tcp_create_conn(
                              pco_tst->ta, tst_addr, iut_addr,
                              tst_if->if_name,
                              CVT_HW_ADDR(alien_link_addr),
                              CVT_HW_ADDR(gw_tst_lladdr),
                              TAPI_TCP_DEF_WINDOW, &tcp_conn));

    CHECK_RC(tapi_tcp_start_conn(tcp_conn, TAPI_TCP_CLIENT));
    CHECK_RC(tapi_tcp_wait_open(tcp_conn, TAPI_WAIT_NETWORK_DELAY));

    iut_s = rpc_accept(pco_iut, iut_l, NULL, NULL);

    TEST_STEP("Create a CSAP on the gateway host to capture packets "
              "sent from IUT.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_gw->ta, 0, gw_iut_if->if_name,
        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL, iut_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr),
        &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap,
                                   NULL, TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));
    SLEEP(1);

    TEST_STEP("Check whether @c TCP_NODELAY option is disabled by "
              "default on the IUT socket.");

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &opt_val);
    if (opt_val != 0)
        ERROR_VERDICT("TCP_NODELAY is enabled by default");

    TEST_STEP("Send two packets from IUT, receive them on Tester. "
              "Check that the second packet is not sent immediately "
              "after the first one (unless @c TCP_NODELAY is enabled "
              "by default).");
    check_nodelay(pco_iut, iut_s, tcp_conn, opt_val, csap, pco_gw->ta,
                  "Default TCP_NODELAY value");

    TEST_STEP("Enable @c TCP_NODELAY option on the IUT socket.");

    rpc_setsockopt_int(pco_iut, iut_s, RPC_TCP_NODELAY, 1);

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &opt_val);
    if (opt_val != 1)
        TEST_VERDICT("Cannot enable TCP_NODELAY option");

    TEST_STEP("Send two packets from the IUT socket, receive them on "
              "Tester. Check that the second packet is sent after the "
              "first one without a significant delay.");
    check_nodelay(pco_iut, iut_s, tcp_conn, TRUE, csap, pco_gw->ta,
                  "TCP_NODELAY is enabled");

    TEST_STEP("Disable @c TCP_NODELAY option on the IUT socket.");

    rpc_setsockopt_int(pco_iut, iut_s, RPC_TCP_NODELAY, 0);

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &opt_val);
    if (opt_val != 0)
        TEST_VERDICT("Cannot disable TCP_NODELAY option");

    TEST_STEP("Send two packets from the IUT socket, receive them on "
              "Tester. Check that the second packet is not sent "
              "immediately after the first one.");
    check_nodelay(pco_iut, iut_s, tcp_conn, FALSE, csap, pco_gw->ta,
                  "TCP_NODELAY is disabled");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_gw->ta, 0, csap));
    CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));

    TEST_END;
}
