/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 * 
 * $Id$
 */

/** @page tcp-tcp_window_update  Packets transmission after incresing the window size from 0
 *
 * @objective  Ensure that queued packets will be transmitted immediately
 *             after the TCP window size increasing to enough size with a
 *             data packet.
 *
 * @type reliability
 *
 * @param pco_iut           The first PCO on IUT
 * @param iut_addr          Address/port to be used to connect to @p pco_iut
 * @param pco_tst           The second PCO on IUT
 * @param tst_fake_addr     Address/port to be used to connect to @p pco_tst
 *
 * @par Scenario:
 *
 * @ref SF bug 44888
 * 
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_window_update"


#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_tcp.h"

#include "ndn_ipstack.h"
#include "ndn_eth.h"

#define MAX_TCP_STR_LEN 1000

/**
 * Send a data packet from tester.
 * 
 * @param ss    Session context
 * @param len   Payload length
 */
static void
tcp_send_payload(tsa_session *ss, size_t len)
{
    tapi_tcp_handler_t csap_tst_s = tsa_tst_sock(ss);
    csap_handle_t csap_send = tapi_tcp_conn_snd_csap(csap_tst_s);
    asn_value    *templ = NULL;
    int           ackn;
    uint8_t      *buf = te_make_buf_by_len(len);

    CHECK_RC(tapi_tcp_conn_template(csap_tst_s, buf, len, &templ));
    CHECK_RC(asn_write_int32(templ, TCP_ACK_FLAG | TCP_PSH_FLAG,
                             "pdus.0.#tcp.flags.#plain"));

    ackn = tapi_tcp_next_ackn(csap_tst_s);
    CHECK_RC(asn_write_int32(templ, ackn, "pdus.0.#tcp.ackn.#plain"));

    tapi_tad_trsend_start(ss->config.pco_tst->ta, ss->state.sock.sid,
                          csap_send, templ, RCF_MODE_BLOCKING);
    free(buf);

    CHECK_RC(tapi_tcp_update_sent_ack(csap_tst_s, ackn));
    CHECK_RC(tapi_tcp_update_sent_seq(csap_tst_s, len));

    asn_free_value(templ);
}


int
main(int argc, char *argv[])
{
    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_fake_addr;
    const void                *alien_link_addr = NULL;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    tsa_session     ss = TSA_SESSION_INITIALIZER;
    void           *tx_buf = NULL;
    size_t          buf_len = 300;
    size_t          tst_buf_len = 200;
    int             iut_s = -1;
    asn_value      *repl_pattern = NULL;
    asn_value      *templ = NULL;

    tapi_tcp_handler_t csap_tst_s;
    csap_handle_t      csap_send;
    size_t             ackn;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);

    tx_buf = te_make_buf_by_len(buf_len);

    if (tsa_state_init(&ss, TSA_TST_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    tsa_iut_set(&ss, pco_iut, iut_if, iut_addr);
    tsa_tst_set(&ss, pco_tst, tst_if, tst_fake_addr,
                ((struct sockaddr *)alien_link_addr)->sa_data);
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a tcp socket on IUT and CSAP on tester.");
    tsa_create_session(&ss, 0);

    CHECK_RC(tapi_tcp_pattern(0, 0, FALSE, FALSE, &repl_pattern));

    iut_s = tsa_iut_sock(&ss);

    TEST_STEP("Move the socket and the CSAP to the required TCP state.");
    rc = tsa_do_moves_str(&ss, RPC_TCP_UNKNOWN, RPC_TCP_UNKNOWN, 0,
                          "TCP_ESTABLISHED");

    if (tsa_state_cur(&ss) != RPC_TCP_ESTABLISHED)
        TEST_VERDICT("TCP_ESTABLISHED was not achieved");

    csap_tst_s = tsa_tst_sock(&ss);
    csap_send = tapi_tcp_conn_snd_csap(csap_tst_s);

    TEST_STEP("Send a data packet from IUT.");
    rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    CHECK_RC(tapi_tcp_conn_template(csap_tst_s, NULL, 0, &templ));
    CHECK_RC(asn_write_int32(templ, TCP_ACK_FLAG,
                             "pdus.0.#tcp.flags.#plain"));
    CHECK_RC(tapi_tcp_wait_packet(csap_tst_s, 1000));

    TEST_STEP("Send ACK to IUT with the zero window size.");
    ackn = tapi_tcp_next_ackn(csap_tst_s);
    CHECK_RC(asn_write_int32(templ, ackn, "pdus.0.#tcp.ackn.#plain"));
    CHECK_RC(asn_write_int32(templ, 0, "pdus.0.#tcp.win-size.#plain"));

    tapi_tad_trsend_start(pco_tst->ta, ss.state.sock.sid, csap_send,
                          templ, RCF_MODE_BLOCKING);
    CHECK_RC(tapi_tcp_update_sent_ack(csap_tst_s, ackn));

    TEST_STEP("Send a data packet from IUT.");
    rpc_send(pco_iut, iut_s, tx_buf, buf_len, RPC_MSG_DONTWAIT);

    TEST_STEP("Ensure that the packet was not passed to the wire.");
    if (tapi_tcp_wait_packet(ss.state.csap.csap_tst_s, 100) == 0)
        TEST_VERDICT("Data packet was sent from IUT despite the zero window");

    TEST_STEP("Send a data packet from tester with non-zero window size.");
    tcp_send_payload(&ss, tst_buf_len);
    rpc_recv(pco_iut, iut_s, tx_buf, buf_len, 0);

    TEST_STEP("Receive IUT packet, check ACK number and payload length.");
    if (tapi_tcp_wait_packet(ss.state.csap.csap_tst_s, 1000) == 0)
    {
        if (tapi_tcp_next_ackn(csap_tst_s) -
            tapi_tcp_last_seqn_got(csap_tst_s) != buf_len)
            TEST_VERDICT("IUT data packet was not received");
        if (tapi_tcp_last_ackn_got(csap_tst_s) !=
            tapi_tcp_next_seqn(csap_tst_s))
            TEST_VERDICT("Received packet has wrong ACK number");

        CHECK_RC(tapi_tcp_send_ack(ss.state.csap.csap_tst_s,
                                   tapi_tcp_next_ackn(csap_tst_s)));
    }
    else
        TEST_VERDICT("No packets were received after the window size "
                     "enlarging");

    TEST_SUCCESS;

cleanup:
    if (tsa_destroy_session(&ss) != 0)
       TEST_FAIL("Closing working session with TSA failed");

    free(tx_buf);
    asn_free_value(repl_pattern);
    asn_free_value(templ);

    TEST_END;
}
