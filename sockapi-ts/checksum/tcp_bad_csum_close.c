/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/*
 * Socket API Test Suite
 * IP/TCP/UDP checksum tests
 */

/**
 * @page checksum-tcp_bad_csum_close Sending TCP segments with bad checksum while closing a connection
 *
 * @objective Send FIN, RST segments with invalid checksum and check that IUT
 *            ignores it
 *
 * @param env      Testing environment:
 *      - @ref arg_types_env_peer2peer
 * @param segment  What segment to send with invalid checksum:
 *      - FIN
 *      - RST
 * @param protocol Protocol header to corrupt checksum in:
 *      - IPPROTO_IP
 *      - IPPROTO_TCP
 * @param csum_val Value to set as a checksum:
 *      - bad
 *      - zero
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "checksum/tcp_bad_csum_close"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "tapi_sockets.h"
#include "checksum_lib.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct if_nameindex *tst_if;
    const struct if_nameindex *iut_if;
    const struct sockaddr *alien_link_addr;
    const struct sockaddr *iut_lladdr = NULL;
    int iut_s = -1;
    tapi_tcp_handler_t tcp_conn = 0;
    sockts_csum_val csum_val;
    rpc_socket_proto protocol;
    sockts_tcp_segment segment;
    asn_value *tmpl = NULL;
    te_bool done = FALSE;
    char buf[1];
    rpc_tcp_state state;
    te_bool found;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    SOCKTS_GET_CSUM_VAL(csum_val);
    TEST_GET_PROTOCOL(protocol);
    SOCKTS_GET_TCP_SEGMENT_TYPE(segment);

    TEST_STEP("Add tester alien address to IUT ARP table so Linux won't "
              "interfer with TCP socket emulation");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL, tst_addr,
                             CVT_HW_ADDR(alien_link_addr), TRUE));
    CFG_WAIT_CHANGES;

    TEST_STEP("Establish TCP connection between IUT socket and CSAP socket "
              "emulation on Tester");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);
    CHECK_RC(tapi_tcp_init_connection(pco_tst->ta, TAPI_TCP_SERVER, tst_addr,
                                      iut_addr, tst_if->if_name,
                                      CVT_HW_ADDR(alien_link_addr),
                                      CVT_HW_ADDR(iut_lladdr),
                                      0, &tcp_conn));
    TAPI_WAIT_NETWORK;
    pco_iut->op = RCF_RPC_CALL;
    rpc_connect(pco_iut, iut_s, tst_addr);
    CHECK_RC(tapi_tcp_wait_open(tcp_conn, TAPI_WAIT_NETWORK_DELAY));
    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("Initiate a blocking call to @b recv() RPC on IUT");
    pco_iut->op = RCF_RPC_CALL;
    rpc_recv(pco_iut, iut_s, buf, sizeof(buf), 0);

    TEST_STEP("Send TCP segment with invalid checksum from CSAP according to "
              "parameters");
    CHECK_RC(tapi_tcp_conn_template(tcp_conn, NULL, 0, &tmpl));
    CHECK_RC(asn_write_int32(tmpl, sockts_tcpseg2flags(segment),
                             "pdus.0.#tcp.flags.#plain"));
    CHECK_RC(sockts_set_hdr_csum(tmpl, protocol, csum_val));
    CHECK_RC(tapi_tcp_send_template(tcp_conn, tmpl, RCF_MODE_BLOCKING));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that @b recv() is still blocked");
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rpc_recv(pco_iut, iut_s, buf, sizeof(buf), 0);
        TEST_VERDICT("recv() on IUT was unblocked unexpectedly after receiving "
                     "%s with invalid checksum", sockts_tcpseg2str(segment));
    }

    TEST_STEP("Send the same TCP segment with valid checksum");
    if (segment == SOCKTS_TCP_FIN)
        CHECK_RC(tapi_tcp_send_fin(tcp_conn, TAPI_WAIT_NETWORK_DELAY));
    else
        CHECK_RC(tapi_tcp_send_rst(tcp_conn));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that @b recv() is unblocked");
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (!done)
    {
        TEST_VERDICT("recv() on IUT was not unblocked after receiving %s with "
                     "valid checksum", sockts_tcpseg2str(segment));
    }

    TEST_STEP("Call recv() on IUT and check its result");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, buf, sizeof(buf), 0);

    if (segment == SOCKTS_TCP_RST)
    {
        TEST_SUBSTEP("If @p segment is @c RST check that @b recv() fails "
                     "with @c ECONNRESET");

        if (rc >= 0)
        {
            TEST_VERDICT("recv() on IUT unexpectedly succeeded after receiving "
                         "RST with valid checksum");
        }
        CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET,
                        "recv() on IUT after receiving RST with valid checksum");
    }
    else
    {
        TEST_SUBSTEP("If @p segment is @c FIN check that @b recv() return zero "
                     "and finally call close() on IUT socket");

        if (rc != 0)
            TEST_VERDICT("recv() on IUT returned non-zero");

        RPC_CLOSE(pco_iut, iut_s);
        tapi_tcp_wait_packet(tcp_conn, TAPI_WAIT_NETWORK_DELAY);
        tapi_tcp_ack_all(tcp_conn);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Check that connection is fully closed");
    rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr, &state, &found);
    if (found)
    {
        TEST_VERDICT("IUT socket moved to unexpected state %s",
                     tcp_state_rpc2str(state));
    }

    TEST_SUCCESS;

cleanup:
    if (tcp_conn != 0)
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));
    CLEANUP_CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name,
                                     pco_tst->ta, tst_if->if_name,
                                     tst_addr, NULL, FALSE));
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
