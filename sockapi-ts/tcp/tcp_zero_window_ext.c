/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 *
 * $Id$
 */

/** @page tcp-tcp_zero_window_ext  Closing TCP socket despite zero window
 *
 * @objective  Check that TCP socket closes properly despite it received a
 *             packet with the zero window.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT.
 * @param pco_tst           PCO on TESTER.
 * @param active            IUT is active in TCP connection.
 * @param linger            Set @c SO_LINGER socket option.
 * @param handshake         Send a packet with the TCP zero window during
 *                          TCP handshake.
 * @param data_packet_ack   If @c TRUE send a data packet from IUT and
 *                          send ACK to it with zero window. Otherwise
 *                          send a data packet from tester with zero window.
 *                          This parameter makes sense only when
 *                          @p handshake is @c FALSE.
 * @param cache_socket      Create cached socket to be reused.
 * @param overfill_sndbuf   If @c TRUE, try to overfill send buffer
 *                          of IUT socket after it receives packet with
 *                          zero window.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_zero_window_ext"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_tcp.h"
#include "onload.h"
#include "tapi_route_gw.h"

#include "ndn_ipstack.h"
#include "ndn_eth.h"

/** Linger timeout in seconds. */
#define LINGER_TIMEOUT 1

/** Linger timeout precision in microseconds. */
#define LINGER_PRECISION 200000

/** Acceptable socket closing timeout accuracy. */
#define ACCURACY 1

/** Maximum waiting time for a packet arrival, milliseconds. */
#define PKT_TIMEOUT 1000

/** Data length to send at once. */
#define BUF_LEN 300

/** Default Linux MSL, in seconds. */
#define LINUX_MSL 60

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    tapi_route_gateway gateway;
    rcf_rpc_server    *pco_iut2 = NULL;

    const struct sockaddr *gw_tst_lladdr = NULL;

    te_bool         linger;
    te_bool         active;
    te_bool         handshake;
    te_bool         data_packet_ack;
    te_bool         cache_socket;
    te_bool         shut;
    te_bool         overfill_sndbuf;

    uint8_t             tx_buf[BUF_LEN];
    int                 iut_s = -1;
    int                 iut_s_aux = -1;
    tapi_tcp_handler_t  csap_tst_s = -1;
    csap_handle_t       csap = CSAP_INVALID_HANDLE;
    tsa_packets_counter ctx;

    struct rpc_tcp_info   tcp_info;
    tarpc_linger          linger_val = { .l_onoff = 1,
                                         .l_linger = LINGER_TIMEOUT };
    uint64_t              duration;
    int                   msl;

    tapi_tcp_pos_t seqn1;
    tapi_tcp_pos_t seqn2;

    int       time_wait_timeout;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(linger);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_BOOL_PARAM(handshake);
    TEST_GET_BOOL_PARAM(data_packet_ack);
    TEST_GET_BOOL_PARAM(shut);
    TEST_GET_BOOL_PARAM(cache_socket);
    TEST_GET_BOOL_PARAM(overfill_sndbuf);
    TEST_GET_LINK_ADDR(gw_tst_lladdr);

    if (cache_socket)
        TEST_GET_PCO(pco_iut2);
    else
        pco_iut2 = pco_iut;

    TEST_STEP("Configure connection between IUT and Tester via "
              "gateway.");

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    CHECK_RC(tapi_route_gateway_configure(&gateway));
    if (!cache_socket)
        CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name, NULL, NULL,
                                 tst_addr, CVT_HW_ADDR(alien_link_addr),
                                 TRUE));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create auxiliary CSAP to capture packets from IUT.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name,
        TAD_ETH_RECV_DEF, NULL, NULL, tst_addr->sa_family,
        NULL, NULL, -1, -1, &csap));

    TEST_STEP("If @p cache_socket and @p active are @c TRUE - create cached socket.");
    if (active)
        sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                    TRUE, cache_socket);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);

      TEST_STEP("Set @c SO_LINGER if @p linger is @c TRUE.");
    if (linger)
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &linger_val);

    TEST_STEP("Start CSAP sniffer to track transmitted packets.");
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("If @p active is @c FALSE, create listener socket on IUT. "
              "If @p cache_socket is @c TRUE - create cached socket.");
    if (!active)
    {
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

        sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, iut_s,
                                    FALSE, cache_socket);
    }

    if (cache_socket)
    {
        CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name, NULL, NULL,
                                 tst_addr, CVT_HW_ADDR(alien_link_addr),
                                 TRUE));
        CFG_WAIT_CHANGES;
    }

    TEST_STEP("Create TCP socket emulation on Tester. If @p handshake is @c TRUE, "
              "specify zero window for @b tapi_tcp_init_connection(), so that "
              "SYN or SYN-ACK will be sent with it.");

    CHECK_RC(tapi_tcp_init_connection(
                              pco_tst->ta,
                              (active ? TAPI_TCP_SERVER : TAPI_TCP_CLIENT),
                              tst_addr, iut_addr,
                              tst_if->if_name,
                              (const uint8_t *)alien_link_addr->sa_data,
                              (const uint8_t *)gw_tst_lladdr->sa_data,
                              (handshake ? TAPI_TCP_ZERO_WINDOW :
                                           TAPI_TCP_DEF_WINDOW),
                              &csap_tst_s));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Establish TCP connection.");

    if (active)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_connect(pco_iut, iut_s, tst_addr);
    }

    CHECK_RC(tapi_tcp_wait_open(csap_tst_s, PKT_TIMEOUT));

    if (active)
    {
        rpc_connect(pco_iut, iut_s, tst_addr);
    }
    else
    {
        iut_s_aux = iut_s;
        iut_s = rpc_accept(pco_iut, iut_s_aux, NULL, NULL);
    }

    TEST_STEP("If @p handshake is @c FALSE, set TCP window to zero "
              "for TCP socket emulation on Tester.");

    if (!handshake)
    {
        CHECK_RC(tapi_tcp_set_window(csap_tst_s, 0));

        TEST_SUBSTEP("If @p data_packet_ack is @c TRUE, send data "
                     "from IUT and send ACK to it from Tester. Otherwise, "
                     "send data packet from Tester.");

        if (data_packet_ack)
        {
            rpc_send(pco_iut, iut_s, tx_buf, BUF_LEN, 0);
            CHECK_RC(tapi_tcp_wait_packet(csap_tst_s, PKT_TIMEOUT));
            CHECK_RC(tapi_tcp_ack_all(csap_tst_s));
            /* Wait while Onload get segment with zero window from tester. */
            TAPI_WAIT_NETWORK;
        }
        else
        {
            CHECK_RC(tapi_tcp_send_msg(csap_tst_s, tx_buf, BUF_LEN,
                                       TAPI_TCP_AUTO, 0,
                                       TAPI_TCP_AUTO, 0,
                                       NULL, 0));
            rpc_recv(pco_iut, iut_s, tx_buf, BUF_LEN, 0);
            CHECK_RC(tapi_tcp_wait_packet(csap_tst_s, PKT_TIMEOUT));
        }
    }

    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(rcf_ta_trrecv_get(pco_tst->ta, 0, csap, tsa_packet_handler,
                               &ctx, NULL));
    tsa_print_packet_stats(&ctx);

    TEST_STEP("Send a data packet from IUT. Check that it is not sent to Tester "
              "actually because zero TCP window was previously received from it.");
    seqn1 = tapi_tcp_last_seqn_got(csap_tst_s);
    if (overfill_sndbuf)
        rpc_overfill_buffers(pco_iut, iut_s, NULL);
    else
        rpc_send(pco_iut, iut_s, tx_buf, BUF_LEN, 0);

    if (tapi_tcp_wait_packet(csap_tst_s, PKT_TIMEOUT) == 0)
    {
        memset(&ctx, 0, sizeof(ctx));
        CHECK_RC(rcf_ta_trrecv_get(pco_tst->ta, 0, csap,
                                   tsa_packet_handler, &ctx,
                                   NULL));
        tsa_print_packet_stats(&ctx);

        seqn2 = tapi_tcp_last_seqn_got(csap_tst_s);

        if (seqn2 > seqn1)
            TEST_VERDICT("Data packet was sent from IUT despite the zero "
                         "window");
    }

    if (iut_s_aux != -1)
        RPC_CLOSE(pco_iut, iut_s_aux);

    if (tapi_onload_run() &&
        tapi_onload_check_fd(pco_iut, iut_s, NULL) == TAPI_FD_IS_ONLOAD)
        CHECK_RC(tapi_sh_env_get_int(pco_iut, "EF_TCP_TCONST_MSL", &msl));
    else
        msl = LINUX_MSL;

    TEST_STEP("Close or shutdown IUT socket according to @p shut.");
    if (shut)
    {
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);
    }
    else
    {
        RPC_CLOSE(pco_iut, iut_s);
        duration = pco_iut->duration;
    }

    TEST_STEP("Ensure that FIN packet is not received on Tester.");
    if (tapi_tcp_wait_packet(csap_tst_s, PKT_TIMEOUT) == 0 &&
        tapi_tcp_fin_got(csap_tst_s))
        TEST_VERDICT("FIN was sent from IUT despite the zero window");

    TEST_STEP("If @p shut is @c TRUE, check that IUT socket is in "
              "@c TCP_FIN_WAIT1 state.");
    if (shut)
    {
        rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &tcp_info);
        if (tcp_info.tcpi_state != RPC_TCP_FIN_WAIT1)
            TEST_VERDICT("Socket must be in the FIN_WAIT1 state, but it is "
                         "in %s", tcp_state_rpc2str(tcp_info.tcpi_state));
        RPC_CLOSE(pco_iut, iut_s);
        duration = pco_iut->duration;
    }

    TEST_STEP("If @p linger is @c TRUE, check that close() call duration "
              "corresponds to the value of @c SO_LINGER socket option.");
    if (linger)
    {
        uint64_t lt = TE_SEC2US(LINGER_TIMEOUT);

        if (duration > lt + LINGER_PRECISION ||
            duration < lt - LINGER_PRECISION)
            TEST_VERDICT("close() operation took unexpected time");
    }

    TEST_STEP("Wait until socket in TIME_WAIT state is closed.");

    if (linger)
        time_wait_timeout = msl * 2 - LINGER_TIMEOUT + ACCURACY;
    else
        time_wait_timeout = msl * 2 + ACCURACY;

    sockts_wait_socket_closing(pco_iut2, iut_addr, tst_addr,
                               time_wait_timeout);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(rcf_ta_trrecv_stop(pco_tst->ta, 0, csap,
                                tsa_packet_handler, &ctx,
                                NULL));
    tsa_print_packet_stats(&ctx);

    TEST_STEP("Open a new TCP socket on IUT.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Try to bind it to the same address:port.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_s, iut_addr);
    if (rc < 0)
    {
        if (RPC_ERRNO(pco_iut) == RPC_EADDRINUSE)
            TEST_VERDICT("Bind failed with errno EADDRINUSE");
        else
            TEST_VERDICT("Bind failed with unexpected errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));
    CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(csap_tst_s));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
