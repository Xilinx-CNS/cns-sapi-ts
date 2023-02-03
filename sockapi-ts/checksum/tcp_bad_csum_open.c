/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IP/TCP/UDP checksum tests
 */

/**
 * @page checksum-tcp_bad_csum_open Sending TCP segments with bad checksum while establishing a connection
 *
 * @objective Send SYN or SYNACK segments with invalid checksum and check that
 *            IUT ignores it
 *
 * @param env      Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param segment  What segment to send with invalid checksum:
 *      - SYN
 *      - SYNACK
 * @param protocol   Protocol header to corrupt checksum in:
 *      - IPPROTO_IP
 *      - IPPROTO_TCP
 * @param csum_val Value to set as a checksum:
 *      - bad
 *      - zero
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@arknetworks.am>
 */

#define TE_TEST_NAME "checksum/tcp_bad_csum_open"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "checksum_lib.h"

/**
 * Finish TCP connection establishment on @p rpcs RPC server according to
 * @p active parameter. If it is @c TRUE call @b connect(), otherwise call
 * @b accept().
 * The function jumps to cleanup if an error occurs.
 *
 * @param rpcs      RPC server
 * @param sock      Socket
 * @param connaddr  Address to connect
 * @param active    Whether to establish the connection actively
 *
 * @return connected socket
 */
static int
iut_finish_conn_estab(rcf_rpc_server *rpcs, int sock,
                      const struct sockaddr *connaddr,
                      te_bool active)
{
    if (active)
    {
        rpc_connect(rpcs, sock, connaddr);
    }
    else
    {
        int accept_sock = -1;

        accept_sock = rpc_accept(rpcs, sock, NULL, NULL);
        rpc_close(rpcs, sock);
        sock = accept_sock;
    }

    return sock;
}

/**
 * Wait for incoming TCP segments on @p tcp_conn CSAP socket emulation during
 * the @p timeout.
 *
 * @param tcp_conn  CSAP socket emulation handler
 * @param timeout   Timeout in ms for waiting
 * @param got_flags Flags field of the received segment
 *
 * @return Status code (zero if some packet was catched)
 */
static int
wait_tcp_seg(tapi_tcp_handler_t tcp_conn, int timeout, uint8_t *got_flags)
{
    int rc = tapi_tcp_wait_packet(tcp_conn, timeout);

    if (rc == 0)
    {
        return tapi_tcp_recv_msg(tcp_conn, 0, TAPI_TCP_QUIET, NULL, NULL,
                                 NULL, NULL, got_flags);
    }

    return rc;
}

/**
 * Send TCP segment via @p tcp_conn CSAP socket emulation.
 *
 * @param tcp_conn  CSAP socket emulation handler
 * @param seqn      Sequence number of the segment
 * @param flags     Flags of the segment
 * @param proto     Protocol header to set user checksum (if needed)
 * @param csum      Checksum value to set
 *
 * @return Status code
 */
static te_errno
tcp_send_seg(tapi_tcp_handler_t tcp_conn, uint32_t seqn, uint8_t flags,
             rpc_socket_proto proto, sockts_csum_val csum)
{
#define _CHECK_RC(_expr) \
    do {                                                             \
        if ((rc = (_expr)) != 0)                                     \
        {                                                            \
            ERROR("%s(): %s failed (%r)", __FUNCTION__, #_expr, rc); \
            goto exit;                                               \
        }                                                            \
    } while (0)

    te_errno rc = 0;
    asn_value *tmpl = NULL;

    _CHECK_RC(tapi_tcp_conn_template(tcp_conn, NULL, 0, &tmpl));
    _CHECK_RC(asn_write_int32(tmpl, flags, "pdus.0.#tcp.flags.#plain"));
    _CHECK_RC(asn_write_uint32(tmpl, seqn, "pdus.0.#tcp.seqn.#plain"));
    _CHECK_RC(asn_write_uint32(tmpl, tapi_tcp_next_ackn(tcp_conn),
                               "pdus.0.#tcp.ackn.#plain"));
    _CHECK_RC(sockts_set_hdr_csum(tmpl, proto, csum));
    _CHECK_RC(tapi_tcp_send_template(tcp_conn, tmpl, RCF_MODE_BLOCKING));

exit:
    asn_free_value(tmpl);
    return rc;
#undef _CHECK_RC
}

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
    sockts_tcp_segment segment;
    sockts_csum_val csum_val;
    te_bool done = FALSE;
    uint8_t got_flags;
    rpc_socket_proto protocol;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    SOCKTS_GET_TCP_SEGMENT_TYPE(segment);
    SOCKTS_GET_CSUM_VAL(csum_val);
    TEST_GET_PROTOCOL(protocol);

    TEST_STEP("Add tester alien address to IUT ARP table so Linux won't "
              "interfer with TCP socket emulation");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL, tst_addr,
                             CVT_HW_ADDR(alien_link_addr), TRUE));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create and bind @c SOCK_STREAM socket on IUT");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);

    TEST_STEP("Create CSAP socket emulation on Tester");
    CHECK_RC(tapi_tcp_create_conn(pco_tst->ta, tst_addr, iut_addr,
                                  tst_if->if_name, CVT_HW_ADDR(alien_link_addr),
                                  CVT_HW_ADDR(iut_lladdr), 0, &tcp_conn));
    TAPI_WAIT_NETWORK;

    if (segment == SOCKTS_TCP_SYN)
    {
        TEST_STEP("If @p segment is @c SYN");

        TEST_SUBSTEP("Call @b listen() and @b accept() on IUT socket");
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        pco_iut->op = RCF_RPC_CALL;
        rpc_accept(pco_iut, iut_s, NULL, NULL);

        TEST_SUBSTEP("Send SYN with invalid checksum from CSAP");
        CHECK_RC(tcp_send_seg(tcp_conn, tapi_tcp_first_seqn_sent(tcp_conn),
                              TCP_SYN_FLAG, protocol, csum_val));
    }
    else if (segment == SOCKTS_TCP_SYNACK)
    {
        TEST_STEP("If @p segment is @c SYNACK");

        TEST_SUBSTEP("Call @b connect() on IUT socket");
        pco_iut->op = RCF_RPC_CALL;
        rpc_connect(pco_iut, iut_s, tst_addr);

        TEST_SUBSTEP("Wait for @c SYN segment from IUT");
        CHECK_RC(wait_tcp_seg(tcp_conn, TAPI_WAIT_NETWORK_DELAY, NULL));

        TEST_SUBSTEP("Send @c SYNACK with invalid checksum from CSAP");
        CHECK_RC(tcp_send_seg(tcp_conn, tapi_tcp_next_seqn(tcp_conn),
                              TCP_SYN_FLAG | TCP_ACK_FLAG, protocol, csum_val));
    }
    else
    {
        TEST_FAIL("Invalid segment parameter");
    }

    TEST_STEP("Check that CSAP catches nothing from IUT");
    rc = wait_tcp_seg(tcp_conn, TAPI_WAIT_NETWORK_DELAY, &got_flags);
    if (rc == 0)
    {
        TEST_SUBSTEP("If CSAP catch IUTs repsonse establish the connection");
        if (segment == SOCKTS_TCP_SYN)
        {
            uint32_t next_seq = tapi_tcp_first_seqn_sent(tcp_conn) + 1;

            CHECK_RC(tcp_send_seg(tcp_conn, next_seq, TCP_ACK_FLAG, protocol,
                                  SOCKTS_CSUM_UNSPEC));
        }
        iut_s = iut_finish_conn_estab(pco_iut, iut_s, tst_addr,
                                      segment == SOCKTS_TCP_SYNACK);

        TEST_VERDICT("IUT sent %s in response to segment with invalid checksum "
                     "and successfully established TCP connection",
                      sockts_tcpflags2str(got_flags));
    }
    else if (TE_RC_GET_ERROR(rc) != TE_ETIMEDOUT)
    {
        TEST_FAIL("Reading CSAP input packets failed with unexpected error %r)",
                  rc);
    }

    TEST_STEP("Check that the RPC call on IUT is blocked");
    rcf_rpc_server_is_op_done(pco_iut, &done);
    if (done)
    {
        TEST_VERDICT("%s call unexpectedly unblocked",
                     segment == SOCKTS_TCP_SYN ? "accept" : "connect");
    }

    TEST_STEP("Resend the segment from CSAP with valid checksum");
    if (segment == SOCKTS_TCP_SYN)
    {
        CHECK_RC(tapi_tcp_start_conn(tcp_conn, TAPI_TCP_CLIENT));
    }
    else
    {
        CHECK_RC(tcp_send_seg(tcp_conn, tapi_tcp_next_seqn(tcp_conn),
                              TCP_SYN_FLAG | TCP_ACK_FLAG, protocol,
                              SOCKTS_CSUM_UNSPEC));
        CHECK_RC(tapi_tcp_update_sent_seq(tcp_conn, 1));
    }

    TEST_STEP("Check that CSAP catches IUT answer (@c SYNACK in case of @c "
              "SYN, and @c ACK in case of @c SYNACK)");
    rc = wait_tcp_seg(tcp_conn, TAPI_WAIT_NETWORK_DELAY, &got_flags);
    if (TE_RC_GET_ERROR(rc) == TE_ETIMEDOUT)
    {
        TEST_VERDICT("No repsonse from IUT after sending valid segment");
    }
    else if (rc != 0)
    {
        TEST_FAIL("Reading CSAP input packets failed with unexpected error %r)",
                  rc);
    }

    if (segment == SOCKTS_TCP_SYN && got_flags != (TCP_ACK_FLAG | TCP_SYN_FLAG))
    {
        TEST_VERDICT("IUT sent %s instead of SYN-ACK",
                     sockts_tcpflags2str(got_flags));
    }
    else if (segment == SOCKTS_TCP_SYNACK && got_flags != (TCP_ACK_FLAG))
    {
        TEST_VERDICT("IUT sent %s instead of ACK",
                     sockts_tcpflags2str(got_flags));
    }

    if (segment == SOCKTS_TCP_SYN)
    {
        TEST_STEP("Finish the connection establishment if @p segment is @c SYN "
                  "(send @c ACK from CSAP)");
        CHECK_RC(tapi_tcp_ack_all(tcp_conn));
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Check that the RPC call on IUT is unblocked");
    rcf_rpc_server_is_op_done(pco_iut, &done);
    if (!done)
    {
        TEST_VERDICT("%s call is still blocked after sending segment with "
                     "valid checksum", segment == SOCKTS_TCP_SYN ? "accept" :
                                                                   "connect");
    }
    iut_s = iut_finish_conn_estab(pco_iut, iut_s, tst_addr,
                                  segment == SOCKTS_TCP_SYNACK);

    TEST_STEP("Check that data can be sent between IUT and Tester via "
              "the established connection");
    CHECK_RC(sockts_check_tcp_conn_csap(pco_iut, iut_s, tcp_conn));

    TEST_SUCCESS;

cleanup:
    if (tcp_conn != 0)
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name,
                                     pco_tst->ta, tst_if->if_name,
                                     tst_addr, NULL, FALSE));
    CFG_WAIT_CHANGES;
    TEST_END;
}
