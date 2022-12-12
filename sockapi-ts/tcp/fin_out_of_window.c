/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-fin_out_of_window FIN arrives when TCP window is filled
 *
 * @objective Check what happens when peer sends data until
 *            TCP window is filled, and in the last packet
 *            FIN flag is set.
 *
 * @type conformance
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_peer2peer_gw
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/fin_out_of_window"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "te_dbuf.h"
#include "tapi_sockets.h"

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    const struct sockaddr *gw_tst_lladdr = NULL;

    int                 iut_s = -1;
    tapi_tcp_handler_t  csap_tst_s = -1;
    size_t              window = 0;
    char                data[SOCKTS_MSG_STREAM_MAX];
    size_t              data_len = 0;
    size_t              sent_data = 0;
    size_t              send_limit = 0;
    size_t              received_data = 0;
    asn_value          *pkt_tmpl = NULL;

    tapi_tcp_pos_t      first_ackn_got;
    tapi_tcp_pos_t      cur_ackn_got;
    tapi_tcp_pos_t      last_ackn_got;
    tapi_tcp_pos_t      exp_ackn;
    rpc_tcp_state       tcp_state;

    te_dbuf             send_dbuf = TE_DBUF_INIT(0);
    te_dbuf             recv_dbuf = TE_DBUF_INIT(0);
    te_bool             test_failed = FALSE;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_LINK_ADDR(gw_tst_lladdr);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    CHECK_RC(tapi_route_gateway_configure(&gateway));
    CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    CFG_WAIT_CHANGES;

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

    TEST_STEP("Send data from CSAP socket emulation until TCP window advertised "
              "by IUT does not allow to send any more. In the last packet with "
              "data @c FIN flag should be set.");

    window = tapi_tcp_last_win_got(csap_tst_s);
    RING("Initial IUT TCP window is %" TE_PRINTF_SIZE_T "u", window);
    send_limit = window;

    first_ackn_got = tapi_tcp_last_ackn_got(csap_tst_s);

    while (TRUE)
    {
        data_len = rand_range(1, MIN(SOCKTS_MSG_STREAM_MAX,
                                     send_limit - sent_data));
        te_fill_buf(data, data_len);

        if (sent_data + data_len >= send_limit)
            tapi_tcp_wait_msg(csap_tst_s, TAPI_WAIT_NETWORK_DELAY);
        else
            tapi_tcp_wait_msg(csap_tst_s, 0);

        window = tapi_tcp_last_win_got(csap_tst_s);
        cur_ackn_got = tapi_tcp_last_ackn_got(csap_tst_s);
        send_limit = (cur_ackn_got - first_ackn_got) + window;

        RING("IUT TCP window is %" TE_PRINTF_SIZE_T "u, "
             "%" TE_PRINTF_SIZE_T "u bytes sent since last ACKN",
             window, sent_data - (cur_ackn_got - first_ackn_got));

        if (sent_data >= send_limit)
            TEST_VERDICT("TCP window was reduced so that it looks "
                         "like too much data is already sent");
        else if (sent_data + data_len > send_limit)
            data_len = send_limit - sent_data;

        CHECK_RC(te_dbuf_append(&send_dbuf, data, data_len));
        sent_data += data_len;

        if (sent_data < send_limit)
        {
            CHECK_RC(tapi_tcp_send_msg(csap_tst_s,
                                       (uint8_t *)data, data_len,
                                       TAPI_TCP_AUTO, 0, TAPI_TCP_AUTO, 0,
                                       NULL, 0));
        }
        else
        {
            CHECK_RC(tapi_tcp_conn_template(csap_tst_s,
                                            (uint8_t *)data, data_len,
                                            &pkt_tmpl));
            CHECK_RC(asn_write_uint32(pkt_tmpl, TCP_ACK_FLAG | TCP_FIN_FLAG,
                                      "pdus.0.#tcp.flags.#plain"));
            CHECK_RC(tapi_tcp_send_template(csap_tst_s, pkt_tmpl,
                                            RCF_MODE_BLOCKING));
            CHECK_RC(tapi_tcp_update_sent_seq(csap_tst_s,
                                              data_len + 1));

            break;
        }
    }

    RING("%" TE_PRINTF_SIZE_T "u bytes were sent", sent_data);

    exp_ackn = first_ackn_got + sent_data + 1;

    tapi_tcp_wait_msg(csap_tst_s, TAPI_WAIT_NETWORK_DELAY);
    window = tapi_tcp_last_win_got(csap_tst_s);
    cur_ackn_got = tapi_tcp_last_ackn_got(csap_tst_s);
    RING("Finally IUT TCP window is %" TE_PRINTF_SIZE_T "u",
         window);
    if (window != 0 && (cur_ackn_got - first_ackn_got) + window > sent_data)
        RING("TCP window was extended after Tester sent the last "
             "packet with FIN");
    if (cur_ackn_got < exp_ackn)
        RING_VERDICT("Last packet with FIN was not acknowledged right "
                     "after sending");

    TEST_STEP("Receive all data on IUT. Check that last recv() returns @c 0.");

    while (TRUE)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_recv(pco_iut, iut_s, data, sizeof(data), RPC_MSG_DONTWAIT);
        if (rc <= 0)
            break;
        received_data += rc;
        CHECK_RC(te_dbuf_append(&recv_dbuf, data, rc));
    }
    if (rc < 0)
    {
        ERROR_VERDICT("Last recv() failed with %r instead of returning 0",
                      RPC_ERRNO(pco_iut));
        test_failed = TRUE;
    }

    RING("%" TE_PRINTF_SIZE_T "u bytes were received on IUT",
         received_data);

    TEST_STEP("Check that IUT received all the data sent from Tester.");

    if (sent_data != received_data)
    {
        ERROR_VERDICT("Unexpected amount of data was received on IUT");
        test_failed = TRUE;
    }
    else if (memcmp(recv_dbuf.ptr, send_dbuf.ptr, sent_data) != 0)
    {
        ERROR_VERDICT("Data received on IUT differs from data sent "
                      "from Tester");
        test_failed = TRUE;
    }

    TEST_STEP("Check that IUT socket moved to @c CLOSE_WAIT state and "
              "acknowledged @c FIN.");

    tapi_tcp_wait_msg(csap_tst_s, TAPI_WAIT_NETWORK_DELAY);

    tcp_state = tapi_get_tcp_sock_state(pco_iut, iut_s);
    if (tcp_state != RPC_TCP_CLOSE_WAIT)
    {
        ERROR_VERDICT("At the end IUT socket is in %s state instead "
                      "of TCP_CLOSE_WAIT", tcp_state_rpc2str(tcp_state));
        test_failed = TRUE;
    }

    last_ackn_got = tapi_tcp_last_ackn_got(csap_tst_s);
    RING("Last ACKN got from IUT is %u, expected is %u",
         last_ackn_got, exp_ackn);

    if (last_ackn_got != exp_ackn)
    {
        if (last_ackn_got == exp_ackn - 1)
            TEST_VERDICT("IUT acknowledged all the data but not FIN");
        else
            TEST_VERDICT(
                  "Last ACKN from IUT is %s than expected",
                  (tapi_tcp_compare_seqn(last_ackn_got, exp_ackn) < 0 ?
                   "less" : "more"));
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_CHECK_RC(tapi_tcp_send_rst(csap_tst_s));
    CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(csap_tst_s));
    asn_free_value(pkt_tmpl);

    te_dbuf_free(&send_dbuf);
    te_dbuf_free(&recv_dbuf);

    TEST_END;
}
