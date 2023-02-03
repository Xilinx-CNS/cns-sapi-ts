/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/*
 * Socket API Test Suite
 * IP/TCP/UDP checksum tests
 */

/**
 * @page checksum-tcp_bad_csum_conn Sending TCP segments with bad checksum via established connection
 *
 * @objective Send ACK segment with invalid checksum and check that IUT ignores
 *            it
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param check_ack Check that IUT restransmits allegedly ACKed data:
 *      - FALSE
 *      - TRUE
 * @param check_data Check that sent from IUT data is not passed to user:
 *      - FALSE
 *      - TRUE
 * @param protocol  Protocol header to corrupt checksum in:
 *      - IPPROTO_IP
 *      - IPPROTO_TCP
 * @param csum_val  Value to set as a checksum:
 *      - bad
 *      - zero
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "checksum/tcp_bad_csum_conn"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "checksum_lib.h"

/**
 * Maximum TCP payload length.
 * Do not exceed minimal TCP IPv4 MSS to avoid retransmition of less size than
 * the initial packet. It simplifies the test.
 */
#define MSG_STREAM_MAX 536

/** Maximum waiting time to get the retransmit, in milliseconds. */
#define RTO_TIMEOUT 10000

/**
 * Prepare TCP ACK segment template to send from CSAP socket emulation.
 * If @p check_data test parameter is set to @c TRUE, data from @p _data is
 * used as the segment payload.
 *
 * @param _tcp_conn TAPI handler of TCP connection
 * @param _ipv6     Whether to create IPv6 template (otherwise IPv4)
 * @param _data     Pointer to buffer with payload octets
 * @param _datalen  Payload length
 * @param _tmpl     Location for pointer to ASN value (OUT)
 */
#define PREPARE_ACK_TMPL(_tcp_conn, _ipv6, _data, _datalen, _tmpl) \
    CHECK_RC(tapi_tcp_ip_segment_template(_ipv6,                          \
                                    tapi_tcp_next_seqn(_tcp_conn),        \
                                    tapi_tcp_next_ackn(_tcp_conn), FALSE, \
                                    TRUE, FALSE, FALSE, FALSE, FALSE,     \
                                    check_data ? _data : NULL,            \
                                    _datalen, _tmpl))

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
    te_bool check_ack;
    te_bool check_data;
    asn_value *tmpl = NULL;
    void *data = NULL;
    size_t datalen = MSG_STREAM_MAX;
    uint8_t recv_data[MSG_STREAM_MAX];
    size_t recv_datalen = sizeof(recv_data);
    tapi_tcp_pos_t got_seqn_initial = 0;
    tapi_tcp_pos_t got_seqn = 0;
    te_bool test_failed = FALSE;
    te_bool ipv6_env = FALSE;

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
    TEST_GET_BOOL_PARAM(check_ack);
    TEST_GET_BOOL_PARAM(check_data);

    data = te_make_buf(1, MSG_STREAM_MAX, &datalen);

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

    if (check_ack)
    {
        TEST_STEP("If @p check_ack is @c TRUE");
        TEST_SUBSTEP("Send some data from IUT");
        rpc_send(pco_iut, iut_s, data, datalen, 0);

        CHECK_RC(tapi_tcp_recv_msg(tcp_conn, TAPI_WAIT_NETWORK_DELAY,
                                   TAPI_TCP_QUIET, recv_data, &recv_datalen,
                                   &got_seqn_initial, NULL, NULL));
    }

    TEST_STEP("Send ACK with invalid checksum from Tester according to "
              "@p check_data parameter");

    ipv6_env = (rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET6);
    PREPARE_ACK_TMPL(tcp_conn, ipv6_env, data, datalen, &tmpl);
    CHECK_RC(sockts_set_hdr_csum(tmpl, protocol, csum_val));
    CHECK_RC(tapi_tcp_send_template(tcp_conn, tmpl, RCF_MODE_BLOCKING));

    if (check_data)
    {
        te_bool answer = TRUE;

        TEST_STEP("If @p check_data is @c TRUE");
        TEST_SUBSTEP("Check that IUT socket is not readable");

        RPC_GET_READABILITY(answer, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY);
        if (answer)
        {
            ERROR_VERDICT("Socket 'iut_s' is not expected to be readable, "
                          "but it is");
            test_failed = TRUE;
        }
    }

    if (check_ack)
    {
        TEST_STEP("If @p check_ack is @c TRUE");
        TEST_SUBSTEP("Check that IUT re-transmits the segment");

        rc = tapi_tcp_recv_msg(tcp_conn, TAPI_WAIT_NETWORK_DELAY,
                               TAPI_TCP_QUIET, recv_data, &recv_datalen,
                               &got_seqn, NULL, NULL);
        if (TE_RC_GET_ERROR(rc) == TE_ETIMEDOUT)
        {
            ERROR_VERDICT("IUT does not retransmit data after receiving ACK "
                          "with invalid checksum");
            test_failed = TRUE;
        }
        else if (rc != 0)
        {
            TEST_FAIL("Reading CSAP input packets failed with unexpected "
                      "error %r)", rc);
        }
        else if (got_seqn_initial != got_seqn)
        {
            ERROR("Expected seq = %u, got seq = %u (%+d)", got_seqn_initial,
                  got_seqn, got_seqn - got_seqn_initial);
            ERROR_VERDICT("IUT sent segment which is not a retransmit");
            test_failed = TRUE;
        }
    }

    if (test_failed)
        TEST_STOP;

    TEST_STEP("Send another ACK from Tester with valid checksum");

    /* Update the buffer to check that IUT eventually receives valid data */
    if (check_data)
        te_fill_buf(data, datalen);

    PREPARE_ACK_TMPL(tcp_conn, ipv6_env, data, datalen, &tmpl);
    CHECK_RC(tapi_tcp_send_template(tcp_conn, tmpl, RCF_MODE_BLOCKING));
    CHECK_RC(tapi_tcp_update_sent_ack(tcp_conn, tapi_tcp_next_ackn(tcp_conn)));
    if (check_data)
        CHECK_RC(tapi_tcp_update_sent_seq(tcp_conn, datalen));

    if (check_ack)
    {
        TEST_STEP("If @p check_ack is @c TRUE");
        TEST_SUBSTEP("Check that there is not retransmits from IUT");

        rc = tapi_tcp_recv_msg(tcp_conn, RTO_TIMEOUT,
                               TAPI_TCP_QUIET, NULL, NULL,
                               &got_seqn, NULL, NULL);
        if (rc == 0 && got_seqn == got_seqn_initial)
        {
            ERROR_VERDICT("IUT retransmitted segment after valid checksum ACK");
            test_failed = TRUE;
        }
        else if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_ETIMEDOUT)
        {
            TEST_FAIL("Reading CSAP input packets failed with unexpected "
                      "error %r)", rc);
        }
    }

    if (check_data)
    {
        te_bool answer = FALSE;

        TEST_STEP("If @p check_data is @c TRUE");
        TEST_SUBSTEP("Check that IUT is readable");

        RPC_GET_READABILITY(answer, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY);
        if (!answer)
        {
            ERROR_VERDICT("Socket 'iut_s' is expected to be readable, "
                          "but it is not");
            test_failed = TRUE;
        }

        TEST_SUBSTEP("Receive data on IUT and compare it with the sent one");
        rc = rpc_recv(pco_iut, iut_s, recv_data, recv_datalen, 0);
        SOCKTS_CHECK_RECV_EXT(pco_iut, data, recv_data, datalen, rc,
                              "After sending data with valid checksum");
    }

    if (test_failed)
        TEST_STOP;

    TEST_STEP("Pass some data between IUT and Tester");
    CHECK_RC(sockts_check_tcp_conn_csap(pco_iut, iut_s, tcp_conn));

    TEST_SUCCESS;

cleanup:
    asn_free_value(tmpl);
    free(data);
    if (tcp_conn != 0)
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name,
                                     pco_tst->ta, tst_if->if_name,
                                     tst_addr, NULL, FALSE));
    CFG_WAIT_CHANGES;
    TEST_END;
}
