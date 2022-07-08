/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * TCP tests
 *
 * $Id$
 */

/** @page tcp-fin_data FIN packet processing with data
 *
 * @objective  Exercise FIN packet processing with data in various
 *             situations.
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TST
 * @param linger            Set linger
 * @param shutdown          Use shutdown to close connetion if @c TRUE
 * @param cache_socket      Create cached socket to be reused.
 *
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/fin_data"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_route_gw.h"

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    te_bool linger;
    te_bool shutdown;
    te_bool cache_socket;

    tarpc_linger linger_val = {.l_onoff = 1, .l_linger = 0};

    csap_handle_t          csap = CSAP_INVALID_HANDLE;
    tsa_packets_counter    ctx;

    char                  *sndbuf = NULL;
    char                  *rcvbuf = NULL;
    size_t                 length;

    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(linger);
    TEST_GET_BOOL_PARAM(shutdown);
    TEST_GET_BOOL_PARAM(cache_socket);

    memset(&ctx, 0, sizeof(ctx));

    sndbuf = sockts_make_buf_stream(&length);
    rcvbuf = te_make_buf_by_len(length);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                TRUE, cache_socket);

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Set linger if it is required.");
    if (linger)
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &linger_val);

    TEST_STEP("Prevent packets receiving by tester.");
    CHECK_RC(tapi_route_gateway_set_forwarding(&gateway, FALSE));
    CFG_WAIT_CHANGES;

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_gw->ta, 0, gw_iut_if->if_name,
        TAD_ETH_RECV_DEF, NULL, NULL, tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &csap));

    TEST_STEP("Start CSAP sniffer to track transmitetd packets.");
    CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Send data packet from IUT.");
    RPC_SEND(rc, pco_iut, iut_s, sndbuf, length, 0);

    TEST_STEP("Shutdown or close IUT socket in dependence on @p shutdown to send "
              "FIN packet.");
    if (shutdown)
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
    else
        RPC_CLOSE(pco_iut, iut_s);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Stop CSAP sniffer and check the transmitted packets.");
    rcf_ta_trrecv_stop(pco_gw->ta, 0, csap, tsa_packet_handler, &ctx, NULL);

    RING("Catched packets number %d:\n PSH-ACK: %d\nFIN-ACK: %d\n"
         "PSH-ACK-FIN: %d\nRST-ACK: %d\nOther: %d", ctx.count, ctx.push_ack,
         ctx.fin_ack, ctx.push_fin_ack, ctx.rst_ack, ctx.other);

    TEST_STEP("Allow packets receiving by tester.");
    CHECK_RC(tapi_route_gateway_set_forwarding(&gateway, TRUE));
    CFG_WAIT_CHANGES;

    TEST_STEP("If linger is enabled and socket was closed RST must be passed by "
              "IUT. Send packet from tester and then try to call @b recv() function, "
              "it must fail with ECONNRESET.");
    if (linger && !shutdown)
    {
        rpc_send(pco_tst, tst_s, rcvbuf, length, 0);
        RPC_AWAIT_IUT_ERROR(pco_tst);
        if (rpc_read(pco_tst, tst_s, rcvbuf, length) != -1 ||
            RPC_ERRNO(pco_tst) != RPC_ECONNRESET)
            TEST_VERDICT("Reading attempt must fail with ECONNRESET");

        if (ctx.fin_ack != 0 || ctx.push_fin_ack != 0)
            TEST_VERDICT("FIN packet was caught");
        if (ctx.push_ack == 0)
            TEST_VERDICT("Data packet was not caught");
        if (ctx.rst_ack == 0)
            TEST_VERDICT("RST-ACK was not caught");
    }
    else
    {
        TEST_STEP("In other cases the sent IUT packet must be read by tester "
                  "successfully.");

        if (rpc_read(pco_tst, tst_s, rcvbuf, length) != (int)length ||
            memcmp(sndbuf, rcvbuf, length) != 0)
            TEST_FAIL("Bad packet was received");

        TEST_STEP("The nex call of @b read() function must return zero.");
        if (rpc_read(pco_tst, tst_s, rcvbuf, length) != 0)
            TEST_VERDICT("Tester read a packet with non-zero length after "
                         "shutdown socket at IUT");

        if (ctx.push_ack == 0 && ctx.push_fin_ack == 0)
            TEST_VERDICT("Data packet was not caught");
        if (ctx.fin_ack == 0 && ctx.push_fin_ack == 0)
            TEST_VERDICT("FIN packet was not caught");
    }

    if (ctx.other > 0)
        TEST_VERDICT("Unexpected packets were caught");

    TEST_SUCCESS;
cleanup:
    tapi_tad_csap_destroy(pco_gw->ta, 0, csap);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(sndbuf);
    free(rcvbuf);

    TEST_END;
}
