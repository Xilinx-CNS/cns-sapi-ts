/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-ack_out_of_window ACK arrives in a packet spanning the end of TCP window
 *
 * @objective Check that space is freed in send queue when ACK is
 *            received in a TCP packet retransmit which spans the
 *            end of TCP window.
 *
 * @type conformance
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_peer2peer_gw
 *                            - @ref arg_types_env_peer2peer_gw_ipv6
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/ack_out_of_window"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "te_dbuf.h"
#include "tapi_sockets.h"

/** Maximum number of retransmit attempts for the last Tester packet */
#define MAX_RETRANSMIT_ATTEMPTS 50

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    const struct sockaddr *gw_tst_lladdr = NULL;

    int iut_s = -1;
    tapi_tcp_handler_t csap_tst_s = -1;
    unsigned int window = 0;

    char tst_send_buf[SOCKTS_MSG_STREAM_MAX];
    unsigned int tst_send_len;
    size_t min_len;
    size_t max_len;
    unsigned int unacked_len = 0;
    unsigned int exp_unacked_len = 0;

    te_dbuf recv_data = TE_DBUF_INIT(0);
    te_dbuf tst_sent_data = TE_DBUF_INIT(0);
    uint8_t *iut_sent_data = NULL;
    uint64_t iut_sent_len = 0;

    te_bool too_much_acked_verdict = FALSE;
    te_bool writable;
    int i;

    tapi_tcp_pos_t last_ackn_got;
    tapi_tcp_pos_t last_seqn_sent;
    tapi_tcp_pos_t exp_ackn;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_LINK_ADDR(gw_tst_lladdr);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    CHECK_RC(tapi_route_gateway_configure(&gateway));
    CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    CFG_WAIT_CHANGES;

    rcf_tr_op_log(FALSE);

    TEST_STEP("Establish TCP connection between IUT socket and CSAP "
              "TCP socket emulation on Tester.");

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);

    CHECK_RC(tapi_tcp_init_connection(pco_tst->ta, TAPI_TCP_SERVER,
                                      tst_addr, iut_addr,
                                      tst_if->if_name,
                                      (uint8_t *)alien_link_addr->sa_data,
                                      (uint8_t *)gw_tst_lladdr->sa_data,
                                      0, &csap_tst_s));
    /*
     * Enabling promiscuous mode can take some time on virtual hosts,
     * see ST-2675.
     */
    VSLEEP(1, "Wait for promiscuous mode to turn on");

    pco_iut->op = RCF_RPC_CALL;
    rpc_connect(pco_iut, iut_s, tst_addr);
    CHECK_RC(tapi_tcp_wait_open(csap_tst_s, TAPI_WAIT_NETWORK_DELAY));
    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("Send packets from CSAP until the IUT TCP window is so "
              "small that the last sent packet is bigger than it and "
              "at least some data from it is not acknowledged by IUT.");

    while (TRUE)
    {
        window = tapi_tcp_last_win_got(csap_tst_s);
        RING("Current IUT TCP window is %u", window);

        if (window < sizeof(tst_send_buf))
        {
            min_len = window + 1;
            max_len = sizeof(tst_send_buf);
        }
        else
        {
            max_len = MIN(window - 1, sizeof(tst_send_buf));
            min_len = MIN(max_len, sizeof(tst_send_buf) / 2);
        }
        tst_send_len = rand_range(min_len, max_len);
        te_fill_buf(tst_send_buf, tst_send_len);

        RING("Sending %u bytes to IUT", tst_send_len);
        if (tst_send_len > window)
        {
            RING("Expecting %u bytes to be out of window",
                 tst_send_len - window);
        }
        CHECK_RC(tapi_tcp_send_msg(csap_tst_s,
                                   (uint8_t *)tst_send_buf, tst_send_len,
                                   TAPI_TCP_AUTO, 0, TAPI_TCP_AUTO, 0,
                                   NULL, 0));

        CHECK_RC(te_dbuf_append(&tst_sent_data, tst_send_buf, tst_send_len));

        CHECK_RC(tapi_tcp_wait_msg(csap_tst_s, TAPI_WAIT_NETWORK_DELAY));

        last_ackn_got = tapi_tcp_last_ackn_got(csap_tst_s);
        last_seqn_sent = tapi_tcp_last_seqn_sent(csap_tst_s);
        exp_ackn = last_seqn_sent + tst_send_len;
        unacked_len = exp_ackn - last_ackn_got;
        if (unacked_len > tst_send_len)
            TEST_VERDICT("Invalid ACKN was received from IUT");

        if (unacked_len == 0)
        {
            if (window == 0 && !too_much_acked_verdict)
            {
                RING_VERDICT("IUT TCP window is zero but all the sent "
                             "packet is acknowledged");
                too_much_acked_verdict = TRUE;
            }
        }
        else
        {
            if (window < tst_send_len)
            {
                RING("%u bytes were not acked in the last ACK, "
                     "difference between the packet size and TCP "
                     "window is %u",
                     unacked_len, tst_send_len - window);

                if (unacked_len < tst_send_len)
                {
                    RING_VERDICT("Packet sent to IUT was partially "
                                 "acknowledged due to small window");

                    exp_unacked_len = tst_send_len - window;
                    if (unacked_len != exp_unacked_len)
                    {
                        RING_VERDICT("%s data than expected was "
                                     "acknowledged in the last "
                                     "packet sent to IUT",
                                     (unacked_len > exp_unacked_len ?
                                                      "Less" : "More"));
                    }
                }
                else if (window > 0)
                {
                    RING_VERDICT("No data from the last packet sent to IUT "
                                 "was acknowledged while IUT TCP window "
                                 "was greater than zero");
                }

                break;
            }
            else
            {
                TEST_VERDICT("Packet sent to IUT within its TCP window "
                             "was not fully acknowledged");
            }
        }
    }

    window = tapi_tcp_last_win_got(csap_tst_s);
    RING("The last IUT TCP window is %u", window);
    if (window != 0)
        RING_VERDICT("The last TCP window is not zero");

    TEST_STEP("Overfill send buffer of the IUT socket so that it "
              "becomes not writable.");
    rpc_overfill_buffers_data(pco_iut, iut_s, &iut_sent_len,
                              FUNC_DEFAULT_IOMUX,
                              &iut_sent_data);

    TEST_STEP("In a loop process packets got from IUT on Tester and "
              "send back retransmit of the last (out-of-window) "
              "Tester packet with updated ACKN, until IUT socket "
              "becomes writable.");

    for (i = 0; i < MAX_RETRANSMIT_ATTEMPTS; i++)
    {
        if (tapi_tcp_get_packets(csap_tst_s) < 0)
            TEST_FAIL("tapi_tcp_get_packets() failed");
        RING("Retransmitting %u bytes to IUT, attempt %d", tst_send_len,
             i + 1);
        CHECK_RC(tapi_tcp_send_msg(csap_tst_s,
                                   (uint8_t *)tst_send_buf, tst_send_len,
                                   TAPI_TCP_EXPLICIT, last_seqn_sent,
                                   TAPI_TCP_EXPLICIT,
                                   tapi_tcp_next_ackn(csap_tst_s),
                                   NULL, 0));
        MSLEEP(100);
        RPC_GET_WRITABILITY(writable, pco_iut, iut_s, 0);
        if (writable)
            break;
    }

    if (!writable)
    {
        TEST_VERDICT("IUT socket is not writable after sending ACKs "
                     "in retransmitted packets");
    }

    TEST_STEP("Receive all data on IUT and check it for correctness "
              "(retransmitting the last Tester packet one more time).");
    rpc_read_fd2te_dbuf_append(pco_iut, iut_s, 0, 0, &recv_data);
    RING("Retransmit the last Tester packet once more");
    CHECK_RC(tapi_tcp_send_msg(csap_tst_s,
                               (uint8_t *)tst_send_buf, tst_send_len,
                               TAPI_TCP_EXPLICIT, last_seqn_sent,
                               TAPI_TCP_EXPLICIT,
                               tapi_tcp_next_ackn(csap_tst_s),
                               NULL, 0));
    rpc_read_fd2te_dbuf_append(pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY,
                               0, &recv_data);
    SOCKTS_CHECK_RECV_EXT(pco_iut, tst_sent_data.ptr, recv_data.ptr,
                          tst_sent_data.len, recv_data.len,
                          "Receiving data from Tester");

    TEST_STEP("Receive all data on Tester and check it for correctness.");
    te_dbuf_reset(&recv_data);
    CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                TAPI_TCP_AUTO, &recv_data));
    SOCKTS_CHECK_RECV_EXT(pco_tst, iut_sent_data, recv_data.ptr,
                          iut_sent_len, recv_data.len,
                          "Receiving data from IUT");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_CHECK_RC(tapi_tcp_send_rst(csap_tst_s));
    CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(csap_tst_s));

    free(iut_sent_data);
    te_dbuf_free(&tst_sent_data);
    te_dbuf_free(&recv_data);

    TEST_END;
}
