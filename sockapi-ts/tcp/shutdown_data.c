/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page tcp-shutdown_data Incoming data packet after calling shutdown
 *
 * @objective  Check data packet coming after calling shutdown is handled
 *             proerly.
 *
 * @type conformance
 *
 * @param pco_iut        PCO on IUT
 * @param pco_tst        PCO on TESTER
 * @param shut           Shutdown type
 * @param no_ack         Do not send ACK from TST
 * @param active         Passive or active open
 * @param cache_socket   If @c TRUE, create cached socket to be reused.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/shutdown_data"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "tcp_test_macros.h"

#include "ndn_ipstack.h"

#include "onload.h"

#define BUF_SIZE 1024

/* FIN-ACK retransmissions limit. */
#define RETRIES_NUM 10

/** Data passed to counter_handler() callback. */
typedef struct handler_data {
    tsa_packets_counter    packets_counter;    /**< Context to count packets */
    uint32_t               last_flags;         /**< Flags of the last received
                                                    TCP packet. */
    te_bool                failed;             /**< Will be set to TRUE if
                                                    packets processing failed. */
} handler_data;

/**
 * CSAP callback used to capture packets sent via tested
 * TCP connection.
 *
 * @param pkt         Packet captured by CSAP.
 * @param userdata    Pointer to handler_data structure.
 */
static void
counter_handler(asn_value *pkt, void *userdata)
{
    tsa_packets_counter   *ctx;
    handler_data          *data;
    uint32_t               flags;
    int                    rc = 0;

    data = (handler_data *)userdata;
    ctx = &(data->packets_counter);

    if (data->failed)
        return;

    rc = asn_read_uint32(pkt, &flags, "pdus.0.#tcp.flags.#plain");
    if (rc != 0)
    {
        ERROR("Failed to get TCP flags: %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    switch (flags)
    {
        case TCP_ACK_FLAG:
            ctx->ack++;
            VERB("ACK %d", ctx->ack);
            break;

        case TCP_SYN_FLAG:
            ctx->syn++;
            VERB("SYN %d", ctx->syn);
            break;

        case TCP_ACK_FLAG | TCP_SYN_FLAG:
            ctx->syn_ack++;
            VERB("SYN-ACK %d", ctx->syn_ack);
            break;

        case TCP_ACK_FLAG | TCP_PSH_FLAG:
            ctx->push_ack++;
            VERB("PSH-ACK %d", ctx->push_ack);
            break;

        case TCP_ACK_FLAG | TCP_FIN_FLAG:
            ctx->fin_ack++;
            VERB("FIN-ACK %d", ctx->fin_ack);
            break;

        case TCP_ACK_FLAG | TCP_FIN_FLAG | TCP_PSH_FLAG:
            ctx->push_fin_ack++;
            VERB("PSH-FIN-ACK %d", ctx->push_fin_ack);
            break;

        case TCP_ACK_FLAG | TCP_RST_FLAG:
            ctx->rst_ack++;
            VERB("RST-ACK %d", ctx->rst_ack);
            break;

        case TCP_RST_FLAG:
            ctx->rst++;
            VERB("RST %d", ctx->rst);
            break;

        default:
            ctx->other++;
    }

    data->last_flags = flags;

cleanup:

    asn_free_value(pkt);
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
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    rcf_rpc_server             *pco_gw = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *gw_iut_addr = NULL;
    const struct sockaddr      *gw_tst_addr = NULL;
    const struct sockaddr      *alien_link_addr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *gw_iut_if = NULL;
    const struct if_nameindex  *gw_tst_if = NULL;

    rpc_shut_how                shut;
    te_bool                     no_ack;
    te_bool                     active;
    te_bool                     cache_socket;

    tapi_tad_trrecv_cb_data   cb_data;
    handler_data              data;

    tsa_session          ss = TSA_SESSION_INITIALIZER;
    tapi_tcp_handler_t   csap_tst_s = 0;
    tsa_packets_counter *ctx;
    uint8_t              buf[BUF_SIZE];
    csap_handle_t        csap;
    int                  iut_s = -1;

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
    TEST_GET_ENUM_PARAM(shut, RPC_SHUTDOWN_HOW);
    TEST_GET_BOOL_PARAM(no_ack);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_BOOL_PARAM(cache_socket);

    TEST_STEP("Set /proc/sys/net/ipv4/{tcp_orphan_retries,tcp_retries2} to tune "
              "waiting time in FIN_WAIT1 state.");
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                     "net/ipv4/tcp_orphan_retries"));
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                     "net/ipv4/tcp_retries2"));
    rcf_rpc_server_restart(pco_iut);

    TEST_STEP("Create CSAP to account packets.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL, tst_addr->sa_family, NULL, NULL, -1, -1, &csap));

    if (tsa_state_init(&ss, TSA_TST_GW_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    tsa_iut_set(&ss, pco_iut, iut_if, iut_addr);
    tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL);
    tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
               gw_iut_if, gw_tst_if,
               alien_link_addr->sa_data);
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p cache_socket is @c TRUE and @p opening is @c OL_ACTIVE - create "
              "cached socket.");
    if (active)
    {
        sockts_create_cached_socket(pco_iut, pco_gw, iut_addr, gw_iut_addr, -1,
                                    TRUE, cache_socket);
    }

    TEST_STEP("Create a tcp socket on IUT and CSAP on tester.");
    tsa_create_session(&ss, 0);
    /*
     * Enabling promiscuous mode can take some time on virtual hosts,
     * see ST-2675.
     */
    VSLEEP(1, "Wait for promiscuous mode to turn on");

    TEST_STEP("Move the socket and the CSAP to the ESTABLISHED TCP state.");
    tcp_move_to_state(&ss, RPC_TCP_ESTABLISHED,
                      active ? OL_ACTIVE : OL_PASSIVE_OPEN,
                      active ? cache_socket : FALSE);

    csap_tst_s = tsa_tst_sock(&ss);
    iut_s = tsa_iut_sock(&ss);

    TEST_STEP("Start CSAP sniffer to track transmitted packets.");
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Call @b shutdown.");
    rpc_shutdown(pco_iut, iut_s, shut);
    TAPI_WAIT_NETWORK;

    if (!no_ack && shut != RPC_SHUT_RD)
    {
        CHECK_RC(tapi_tcp_wait_packet(ss.state.csap.csap_tst_s, 1000));
        CHECK_RC(tapi_tcp_send_ack(csap_tst_s,
                                   tapi_tcp_next_ackn(csap_tst_s)));
    }

    cb_data.callback = &counter_handler;
    cb_data.user_data = &data;
    ctx = &data.packets_counter;

    TEST_STEP("Counting packets.");
    memset(&data, 0, sizeof(data));
    csap_process_packets(pco_tst->ta, csap, &cb_data);

    tsa_print_packet_stats(ctx);

    switch (shut)
    {
        case RPC_SHUT_RDWR:
        case RPC_SHUT_WR:
            if (no_ack)
            {
                if (ctx->fin_ack < 2)
                    RING_VERDICT("FIN-ACK retransmits were not sent");
            }
            else if (ctx->fin_ack < 1)
            {
                RING_VERDICT("FIN-ACK packet was not sent");
            }
            if (ctx->rst_ack != 0 || ctx->rst != 0 ||
                ctx->push_fin_ack != 0)
            {
                RING_VERDICT("Unexpected finalizing packet was sent");
            }
            break;

        case RPC_SHUT_RD:
            if (ctx->rst_ack != 0 || ctx->rst != 0 ||
                ctx->push_fin_ack != 0 || ctx->fin_ack != 0)
                RING_VERDICT("Unexpected finalizing packet was sent");
            break;

        default:
            TEST_FAIL("Unexpected argument 'shut' value: %d", shut);
    }

    TEST_STEP("Send a data packet from tester.");
    CHECK_RC(tapi_tcp_send_msg(csap_tst_s, buf, sizeof(buf), TAPI_TCP_AUTO,
                               0, TAPI_TCP_AUTO, 0, NULL, 0));
    TAPI_WAIT_NETWORK;
    memset(&data, 0, sizeof(data));

    TEST_STEP("Count replied by IUT packets.");
    csap_process_packets(pco_tst->ta, csap, &cb_data);
    tsa_print_packet_stats(ctx);

    switch (shut)
    {
        case RPC_SHUT_RDWR:
            if (ctx->rst == 0)
                RING_VERDICT("RST packet was not sent");
            else if (ctx->rst > 1)
                RING_VERDICT("RST packet was sent more than once");

            if (!(data.last_flags & TCP_RST_FLAG))
                RING_VERDICT("Last packet was not RST");

            if (ctx->rst_ack != 0 || ctx->push_fin_ack != 0 ||
                ctx->ack != 0)
            {
                RING_VERDICT("Unexpected packet was sent");
            }

            TEST_SUCCESS;
            break;

        case RPC_SHUT_WR:
            if (ctx->ack != 1)
                RING_VERDICT("Data packet was not ACKed");
            if (!no_ack && ctx->fin_ack != 0)
                RING_VERDICT("Extra FIN-ACK packet was sent");
            if (ctx->rst_ack != 0 || ctx->rst != 0 ||
                ctx->push_fin_ack != 0)
                RING_VERDICT("Unexpected finalizing packet was sent");
            break;

        case RPC_SHUT_RD:
            if (ctx->ack != 1)
                RING_VERDICT("Data packet was not ACKed");
            if (ctx->rst_ack != 0 || ctx->rst != 0 ||
                ctx->push_fin_ack != 0 || ctx->fin_ack != 0)
                RING_VERDICT("Unexpected finalizing packet was sent");
            break;

        default:
            TEST_FAIL("Unexpected argument 'shut' value: %d", shut);
    }

    TEST_STEP("Send two data packets more.");
    CHECK_RC(tapi_tcp_send_msg(csap_tst_s, buf, sizeof(buf), TAPI_TCP_AUTO,
                               0, TAPI_TCP_AUTO, 0, NULL, 0));
    TAPI_WAIT_NETWORK;
    CHECK_RC(tapi_tcp_send_msg(csap_tst_s, buf, sizeof(buf), TAPI_TCP_AUTO,
                               0, TAPI_TCP_AUTO, 0, NULL, 0));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Count replies.");
    memset(&data, 0, sizeof(data));
    rcf_ta_trrecv_stop(pco_tst->ta, 0, csap, tsa_packet_handler, ctx, NULL);
    tsa_print_packet_stats(ctx);

    if (ctx->ack != 2)
        RING_VERDICT("Data packet was not ACKed");
    if (!no_ack && ctx->fin_ack != 0)
        RING_VERDICT("Extra FIN-ACK packet was sent");
    if (ctx->rst_ack != 0 || ctx->rst != 0 ||
        ctx->push_fin_ack != 0)
        RING_VERDICT("Unexpected finalizing packet was sent");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    tapi_tad_csap_destroy(pco_tst->ta, 0, csap);

    if (ss.config.pco_iut != NULL)
        tsa_destroy_session(&ss);

    TEST_END;
}
