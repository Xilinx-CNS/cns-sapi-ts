/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-syn_sent_fin_ack Receiving FIN-ACK in SYN_SENT state
 *
 * @objective  Check that when a socket in SYN_SENT state receives
 *             FIN-ACK from a previous connection, it answers with
 *             RST.
 *
 * @type conformance
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_gw
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/syn_sent_fin_ack"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "tapi_sockets.h"
#include "tapi_tcp.h"

/*
 * How long to wait for termination of TIME_WAIT socket, in seconds.
 */
#define TIME_WAIT_TIMEOUT 200

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    const struct sockaddr *gw_tst_lladdr = NULL;

    int                 iut_s = -1;
    tapi_tcp_handler_t  tst_csap_s = -1;
    te_bool             test_failed = FALSE;

    tapi_tcp_pos_t   fin_seqn;
    tapi_tcp_pos_t   fin_ackn;
    asn_value       *fin_ack_tmpl = NULL;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_LINK_ADDR(gw_tst_lladdr);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CHECK_RC(tapi_route_gateway_break_gw_tst(&gateway));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create TCP socket on IUT and CSAP emulation of TCP socket "
              "on Tester.");

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    CHECK_RC(tapi_tcp_init_connection(
                              pco_tst->ta, TAPI_TCP_SERVER,
                              tst_addr, iut_addr,
                              tst_if->if_name,
                              (const uint8_t *)alien_link_addr->sa_data,
                              (const uint8_t *)gw_tst_lladdr->sa_data,
                              0, &tst_csap_s));
    /*
     * Enabling promiscuous mode can take some time on virtual hosts,
     * see ST-2675.
     */
    VSLEEP(1, "Wait for promiscuous mode to turn on");

    TEST_STEP("Establish connection actively from IUT.");

    pco_iut->op = RCF_RPC_CALL;
    rpc_connect(pco_iut, iut_s, tst_addr);

    CHECK_RC(tapi_tcp_wait_open(tst_csap_s, TAPI_WAIT_NETWORK_DELAY));

    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("Close IUT socket and send @c FIN-ACK from Tester.");

    RPC_CLOSE(pco_iut, iut_s);
    CHECK_RC(tapi_tcp_wait_packet(tst_csap_s, TAPI_WAIT_NETWORK_DELAY));

    /*
     * Save SEQN/ACKN of the last @c FIN-ACK here, so that the same
     * @c FIN-ACK can be resent later manually.
     */
    fin_seqn = tapi_tcp_next_seqn(tst_csap_s);
    fin_ackn = tapi_tcp_next_ackn(tst_csap_s);

    CHECK_RC(tapi_tcp_send_fin_ack(tst_csap_s, TAPI_WAIT_NETWORK_DELAY));

    TEST_STEP("Wait until @c TIME_WAIT socket is gone on IUT.");

    pco_iut->timeout = TE_SEC2MS(TIME_WAIT_TIMEOUT);
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_wait_tcp_socket_termination(pco_iut, iut_addr, tst_addr,
                                         NULL, NULL, NULL);
    if (rc < 0)
        TEST_VERDICT("rpc_wait_tcp_socket_termination() failed on IUT "
                     "with errno %r", RPC_ERRNO(pco_iut));

    TEST_STEP("Create another TCP socket on IUT, @b bind() it to the same "
              "address and call nonblocking @b connect() to the same Tester "
              "address.");

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);

    if (rc == 0)
        TEST_VERDICT("Nonblocking connect() succeeded unexpectedly");
    else if (RPC_ERRNO(pco_iut) != RPC_EINPROGRESS)
        TEST_VERDICT("Nonblocking connect() failed with unexpected "
                     "errno %r", RPC_ERRNO(pco_iut));

    TEST_STEP("Send again @c FIN-ACK from Tester.");

    CHECK_RC(tapi_tcp_conn_template(tst_csap_s, NULL, 0, &fin_ack_tmpl));
    CHECK_RC(asn_write_int32(fin_ack_tmpl, TCP_FIN_FLAG | TCP_ACK_FLAG,
                             "pdus.0.#tcp.flags.#plain"));
    CHECK_RC(asn_write_int32(fin_ack_tmpl, fin_seqn,
                             "pdus.0.#tcp.seqn.#plain"));
    CHECK_RC(asn_write_int32(fin_ack_tmpl, fin_ackn,
                             "pdus.0.#tcp.ackn.#plain"));
    CHECK_RC(tapi_tcp_send_template(tst_csap_s, fin_ack_tmpl,
                                    RCF_MODE_BLOCKING));

    TEST_STEP("Check that TCP socket emulation on Tester got @c RST from IUT.");

    TAPI_WAIT_NETWORK;
    if (tapi_tcp_get_packets(tst_csap_s) < 0)
        TEST_FAIL("tapi_tcp_get_packets() failed");

    if (!tapi_tcp_rst_got(tst_csap_s))
    {
        ERROR_VERDICT("RST was not received on Tester");
        test_failed = TRUE;
    }

    TEST_STEP("Check that connection establishment is still in progress "
              "on IUT.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);

    if (rc == 0)
        TEST_VERDICT("Nonblocking connect() succeeded unexpectedly "
                     "when called the second time");
    else if (RPC_ERRNO(pco_iut) != RPC_EALREADY)
        TEST_VERDICT("Nonblocking connect() failed with unexpected "
                     "errno %r when called the second time",
                     RPC_ERRNO(pco_iut));

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    asn_free_value(fin_ack_tmpl);

    TEST_END;
}
