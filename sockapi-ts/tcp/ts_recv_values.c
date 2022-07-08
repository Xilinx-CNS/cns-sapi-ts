/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-ts_recv_values Receiving various timestamp values
 *
 * @objective Check what happens after receiving a packet
 *            with various timestamp values.
 *
 * @type conformance
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_peer2peer_gw
 * @param tcp_state   TCP state to check.
 * @param start_ts    TCP timestamp value in the first packet
 *                    from tester:
 *                    - @c 0xffffd8ef
 *                    - @c 0
 *                    - @c 1
 *                    - @c -1 (choose timestamp randomly)
 * @param test_ts     TCP timestamp value in a test packet:
 *                    - @c 0xfffffff0
 *                    - @c 0xffffffff
 *                    - @c 0
 *                    - @c 1
 *                    - @c -1 (timestamp option is missing)
 * @param test_data   If @c TRUE, test packet should carry some payload.
 * @param test_flags  Combination of the following values, separated
 *                    by delimiter '.':
 *                    - @c none
 *                    - @c ACKPrev (ACK with not updated ACKN)
 *                    - @c ACKCur (ACK with updated ACKN)
 *                    - @c FIN
 *                    - @c RST
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/ts_recv_values"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_route_gw.h"
#include "tapi_tcp.h"
#include "tapi_sockets.h"

/**
 * Which TCP flags may be set in a test packet.
 */
typedef enum {
    TEST_PKT_FLAG_ACK_PREV = 0x1, /**< @c ACK with not updated ACKN */
    TEST_PKT_FLAG_ACK_CUR = 0x2,  /**< @c ACK with updated ACKN */
    TEST_PKT_FLAG_FIN = 0x4,      /**< @c FIN */
    TEST_PKT_FLAG_RST = 0x8,      /**< @c RST */
} test_pkt_flags;

/**
 * Convert test_pkt_flags to TCP flags which CSAP understands.
 *
 * @param flags       Value to convert.
 *
 * @return Converted value.
 */
static uint32_t
pkt_flags_h2rpc(uint32_t flags)
{
    uint32_t result = 0;

    if (flags & (TEST_PKT_FLAG_ACK_PREV | TEST_PKT_FLAG_ACK_CUR))
        result = result | TCP_ACK_FLAG;
    if (flags & TEST_PKT_FLAG_FIN)
        result = result | TCP_FIN_FLAG;
    if (flags & TEST_PKT_FLAG_RST)
        result = result | TCP_RST_FLAG;

    return result;
}

/** Maximum length of TCP flag name. */
#define FLAG_STR_LEN 256

/**
 * Obtain combination of test_pkt_flags from string representation.
 *
 * @param str       String to parse.
 * @param flags     Where to save parsed flags.
 *
 * @return Status code.
 */
static te_errno
pkt_flags_str2h(const char *str, uint32_t *flags)
{
    unsigned int i;
    unsigned int j;
    char         flag_str[FLAG_STR_LEN];

    *flags = 0;

    for (i = 0, j = 0; ; i++)
    {
        if (str[i] == '\0' || str[i] == '.')
        {
            flag_str[j] = '\0';
            j = 0;

            if (strcasecmp(flag_str, "ACKPrev") == 0)
            {
                *flags = *flags | TEST_PKT_FLAG_ACK_PREV;
            }
            else if (strcasecmp(flag_str, "ACKCur") == 0)
            {
                *flags = *flags | TEST_PKT_FLAG_ACK_CUR;
            }
            else if (strcasecmp(flag_str, "FIN") == 0)
            {
                *flags = *flags | TEST_PKT_FLAG_FIN;
            }
            else if (strcasecmp(flag_str, "RST") == 0)
            {
                *flags = *flags | TEST_PKT_FLAG_RST;
            }
            else if (strcasecmp(flag_str, "None") != 0)
            {
                ERROR("Unknown TCP flag specifier '%s'", flag_str);
                return TE_EINVAL;
            }
        }
        else
        {
            flag_str[j] = str[i];
            j++;
        }

        if (str[i] == '\0')
            break;
    }

    return 0;
}

/**
 * Maximum value of TCP timestamp.
 */
#define MAX_TCP_TS 0xffffffff

/**
 * Check that TCP timestamp echo-reply in the last received packet
 * has expected value.
 *
 * @param csap_tst_s          CSAP TCP socket emulation handle.
 * @param timeout             How long to wait for packet (in ms).
 * @param test_ts             Expected TCP timestamp echo-reply value
 *                            (if negative, check that the last sent
 *                             TS is echoed).
 */
static te_bool
check_ts_echo(tapi_tcp_handler_t csap_tst_s, int timeout, int64_t test_ts)
{
    te_errno  rc;
    uint32_t  last_ts_echo_got;
    uint32_t  last_ts_sent;

    rc = tapi_tcp_wait_msg(csap_tst_s, timeout);
    if (rc != 0)
    {
        ERROR_VERDICT("Expected reply packet was not catched");
        return FALSE;
    }
    else
    {
        CHECK_RC(tapi_tcp_conn_get_ts(csap_tst_s, NULL, NULL,
                                      NULL, &last_ts_sent, NULL, NULL,
                                      NULL, &last_ts_echo_got));
        RING("Timestamp echo-reply in IUT packet is %u",
             last_ts_echo_got);
        if ((test_ts >= 0 && last_ts_echo_got != (uint32_t)test_ts) ||
            (test_ts < 0 && last_ts_echo_got != last_ts_sent))
        {
            ERROR_VERDICT("IUT sent unexpected value as "
                          "timestamp echo-reply");
            return FALSE;
        }
    }

    return TRUE;
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    const struct sockaddr *tst_fake_addr = NULL;

    rpc_tcp_state   tcp_state;
    int64_t         start_ts;
    int64_t         test_ts;
    te_bool         reverse_ts;
    te_bool         test_data;
    const char     *test_flags;
    uint32_t        parsed_flags;
    uint32_t        set_flags;

    tsa_session         ss = TSA_SESSION_INITIALIZER;
    tapi_tcp_handler_t  csap_tst_s;
    int                 iut_s;
    int                 iut_s_aux = -1;

    char                send_buf[SOCKTS_MSG_STREAM_MAX];
    char                recv_buf[SOCKTS_MSG_STREAM_MAX];
    char               *data = NULL;
    size_t              data_len = 0;
    uint32_t            last_ts_sent;
    uint32_t            ts_to_echo;
    uint32_t            last_ts_echo_sent;
    uint32_t            test_ts_echo;
    te_bool             iut_ts_enabled = FALSE;
    asn_value          *pkt_tmpl = NULL;
    int                 iut_ts_val;

    rpc_tcp_state       cur_state;
    rpc_tcp_state       exp_state;
    te_bool             exp_ignored = FALSE;
    te_bool             exp_retransmit = FALSE;
    te_bool             exp_reply = FALSE;
    te_bool             readable;
    te_bool             test_failed = FALSE;
    te_bool             found;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_TCP_STATE(tcp_state);
    TEST_GET_INT64_PARAM(start_ts);
    TEST_GET_INT64_PARAM(test_ts);
    TEST_GET_BOOL_PARAM(test_data);
    TEST_GET_STRING_PARAM(test_flags);

    if (test_ts >= 0 &&
        (uint32_t)test_ts - (uint32_t)start_ts > MAX_TCP_TS / 2)
    {
        reverse_ts = TRUE;
        RING("A case is tested when timestamp of test packet "
             "is before zero while start timestamp is after it");
    }
    else
    {
        reverse_ts = FALSE;
    }

    if (start_ts < 0)
        start_ts = rand_range(0, RAND_MAX);

    CHECK_RC(pkt_flags_str2h(test_flags, &parsed_flags));
    te_fill_buf(send_buf, sizeof(send_buf));

    TEST_STEP("Enable TCP timestamps on IUT.");

    CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &iut_ts_val,
                                     "net/ipv4/tcp_timestamps"));
    if (!iut_ts_val)
        TEST_FAIL("Timestamps on IUT should have been enabled in "
                  "timestamps_prologue");

    TEST_STEP("Create TCP socket on IUT, move it to the desired @p tcp_state. "
              "On the other end CSAP TCP socket emulation should be used, and "
              "it should start with timestamp value @p start_ts in the first "
              "packet.");

    if (tsa_state_init(&ss, TSA_TST_GW_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    tsa_iut_set(&ss, pco_iut, iut_if, iut_addr);
    tsa_tst_set(&ss, pco_tst, tst_if, tst_fake_addr, NULL);
    tsa_gw_preconf(&ss, TRUE);
    tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
               gw_iut_if, gw_tst_if,
               alien_link_addr->sa_data);

    CHECK_RC(tsa_create_session(&ss, 0));
    csap_tst_s = tsa_tst_sock(&ss);

    CHECK_RC(tapi_tcp_conn_enable_ts(csap_tst_s, TRUE, start_ts));

    tcp_move_to_state(&ss, tcp_state, OL_PASSIVE_CLOSE, FALSE);

    iut_s = tsa_iut_sock(&ss);

    TEST_STEP("If @p test_flags is @c ACKCur and it is not expected that TCP "
              "state will be changed as a result of receiving the test packet, "
              "send some data from IUT socket.");

    if (parsed_flags == TEST_PKT_FLAG_ACK_CUR &&
        (tcp_state == RPC_TCP_ESTABLISHED ||
         tcp_state == RPC_TCP_CLOSE_WAIT))
    {
        data_len = rand_range(1, sizeof(send_buf));
        rpc_send(pco_iut, iut_s, send_buf, data_len, 0);
        exp_retransmit = TRUE;
    }

    tapi_tcp_wait_msg(csap_tst_s, TAPI_WAIT_NETWORK_DELAY);

    TEST_STEP("Send test packet to IUT socket according to @p test_data "
              "and @p test_flags, with TCP timestamp value chosen according "
              "to @p test_ts.");

    if (test_data)
    {
        data = send_buf;
        data_len = rand_range(1, sizeof(send_buf));
    }

    CHECK_RC(tapi_tcp_conn_template(csap_tst_s, (uint8_t *)data, data_len,
                                    &pkt_tmpl));

    set_flags = pkt_flags_h2rpc(parsed_flags);
    CHECK_RC(asn_write_uint32(pkt_tmpl, set_flags,
                              "pdus.0.#tcp.flags.#plain"));

    if (parsed_flags & TEST_PKT_FLAG_ACK_CUR)
        CHECK_RC(asn_write_uint32(pkt_tmpl, tapi_tcp_next_ackn(csap_tst_s),
                                  "pdus.0.#tcp.ackn.#plain"));
    else if (parsed_flags & TEST_PKT_FLAG_ACK_PREV)
        CHECK_RC(asn_write_uint32(pkt_tmpl,
                                  tapi_tcp_last_ackn_sent(csap_tst_s),
                                  "pdus.0.#tcp.ackn.#plain"));
    else
        CHECK_RC(asn_write_uint32(pkt_tmpl, 0, "pdus.0.#tcp.ackn.#plain"));

    if (test_ts >= 0)
    {
        CHECK_RC(tapi_tcp_conn_get_ts(csap_tst_s, NULL, &iut_ts_enabled,
                                      NULL, &last_ts_sent, NULL,
                                      &ts_to_echo,
                                      &last_ts_echo_sent, NULL));
        if (!iut_ts_enabled)
            TEST_FAIL("TCP timestamp option is not set by IUT socket");
        if (!reverse_ts && last_ts_sent < MAX_TCP_TS / 2)
            TEST_FAIL("TCP timestamp is already overflown");

        if (parsed_flags & TEST_PKT_FLAG_ACK_CUR)
            test_ts_echo = ts_to_echo;
        else if (parsed_flags & TEST_PKT_FLAG_ACK_PREV)
            test_ts_echo = last_ts_echo_sent;
        else
            test_ts_echo = 0;

        CHECK_RC(tapi_tcp_set_ts_opt(pkt_tmpl, test_ts, test_ts_echo));
    }

    CHECK_RC(tapi_tcp_send_template(csap_tst_s, pkt_tmpl,
                                    RCF_MODE_BLOCKING));
    TAPI_WAIT_NETWORK;

    TEST_STEP("If TCP state change is expected on IUT, check that it happened.");

    cur_state = tapi_get_tcp_sock_state(pco_iut, iut_s);
    if (cur_state == RPC_TCP_FIN_WAIT1 ||
        cur_state == RPC_TCP_CLOSING ||
        cur_state == RPC_TCP_LAST_ACK)
        exp_retransmit = TRUE;

    exp_state = tcp_state;

    if (tcp_state == RPC_TCP_SYN_RECV)
    {
        exp_state = RPC_TCP_LISTEN;

        if (reverse_ts)
            exp_ignored = TRUE;
    }
    else if (!(set_flags & (TCP_ACK_FLAG | TCP_RST_FLAG)))
    {
        /*
         * RFC 793 says that after establishing connection @c ACK flag
         * "is always sent". And Linux indeed ignores packets without
         * @c ACK flag.
         */

        exp_ignored = TRUE;
    }
    else if (reverse_ts && !(set_flags & TCP_RST_FLAG))
    {
        exp_ignored = TRUE;
    }
    else if (set_flags & TCP_RST_FLAG)
    {
        exp_state = RPC_TCP_CLOSE;
    }
    else if (set_flags & TCP_FIN_FLAG)
    {
        exp_reply = TRUE;

        if (tcp_state == RPC_TCP_ESTABLISHED)
            exp_state = RPC_TCP_CLOSE_WAIT;

        if (tcp_state == RPC_TCP_FIN_WAIT1)
        {
            if (parsed_flags & TEST_PKT_FLAG_ACK_CUR)
                exp_state = RPC_TCP_TIME_WAIT;
            else
                exp_state = RPC_TCP_CLOSING;
        }

        if (tcp_state == RPC_TCP_FIN_WAIT2)
            exp_state = RPC_TCP_TIME_WAIT;
    }
    else if (parsed_flags & TEST_PKT_FLAG_ACK_CUR)
    {
        if (tcp_state == RPC_TCP_LAST_ACK)
            exp_state = RPC_TCP_CLOSE;
        if (tcp_state == RPC_TCP_CLOSING)
            exp_state = RPC_TCP_TIME_WAIT;
        if (tcp_state == RPC_TCP_FIN_WAIT1)
            exp_state = RPC_TCP_FIN_WAIT2;
    }

    if (exp_state == RPC_TCP_LISTEN)
    {
        rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_fake_addr,
                                 &cur_state, &found);

        RPC_GET_READABILITY(readable, pco_iut, iut_s, 0);
        if (readable)
        {
            RPC_AWAIT_ERROR(pco_iut);
            iut_s_aux = rpc_accept(pco_iut, iut_s, NULL, NULL);
            if (iut_s_aux < 0)
            {
                ERROR_VERDICT("Listener is readable but accept() on "
                              "IUT failed with errno %r",
                              RPC_ERRNO(pco_iut));
                test_failed = TRUE;
            }
            else
            {
                cur_state = tapi_get_tcp_sock_state(pco_iut, iut_s_aux);
            }
        }

        if (exp_ignored)
        {
            if (readable)
            {
                ERROR_VERDICT("IUT listener was readable after receiving "
                              "packet with wrong timestamp");
                test_failed = TRUE;
            }
            else
            {
                exp_retransmit = TRUE;
            }
        }
        else if (set_flags & TCP_RST_FLAG)
        {
            if (readable)
            {
                ERROR_VERDICT("IUT listener was readable after receiving "
                              "RST in SYN_RCVD state");
                test_failed = TRUE;

                if (iut_s_aux >= 0 && cur_state != RPC_TCP_CLOSE)
                {
                    ERROR_VERDICT("Socket accepted on IUT is in %s state "
                                  "instead of TCP_CLOSE",
                                  tcp_state_rpc2str(cur_state));
                }
            }
            else
            {
                if (found)
                {
                    ERROR_VERDICT("After receiving RST IUT socket still "
                                  "hangs in %s state",
                                  tcp_state_rpc2str(cur_state));
                    test_failed = TRUE;
                }
            }
        }
        else if (set_flags & TCP_ACK_FLAG)
        {
            if (!readable)
            {
                ERROR_VERDICT("Listener on IUT is not readable");
                test_failed = TRUE;
            }
            else if (cur_state != RPC_TCP_ESTABLISHED)
            {
                ERROR_VERDICT("Socket accepted on IUT is in %s state "
                              "instead of TCP_ESTABLISHED",
                              tcp_state_rpc2str(cur_state));
                test_failed = TRUE;
            }
        }

        if (iut_s_aux >= 0)
            iut_s = iut_s_aux;
    }
    else if (cur_state != exp_state &&
             !(cur_state == RPC_TCP_CLOSE &&
               exp_state == RPC_TCP_TIME_WAIT))
    {
        ERROR_VERDICT("After receiving a test packet socket is in %s "
                      "instead of %s", tcp_state_rpc2str(cur_state),
                      tcp_state_rpc2str(exp_state));
        test_failed = TRUE;
    }
    else if (exp_state == RPC_TCP_TIME_WAIT)
    {
        iut_s_aux = rpc_socket(pco_iut,
                               rpc_socket_domain_by_addr(iut_addr),
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_bind(pco_iut, iut_s_aux, iut_addr);
        if (rc >= 0)
        {
            ERROR_VERDICT("Binding another socket to the same address "
                          "succeeded on IUT while socket should be in "
                          "TIME_WAIT state");
            test_failed = TRUE;
        }
        else if (RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
        {
            ERROR_VERDICT("Binding another socket to the same address "
                          "on IUT failed with unexpected errno %r",
                          RPC_ERRNO(pco_iut));
            test_failed = TRUE;
        }

        RPC_CLOSE(pco_iut, iut_s_aux);
    }

    TEST_STEP("If the test packet contained some payload, check that it can be "
              "read from IUT socket (unless test packet is expected to be "
              "ignored because it has no @c ACK flag set or timestamp is bad).");

    if (test_data)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_recv(pco_iut, iut_s, recv_buf, sizeof(recv_buf),
                      RPC_MSG_DONTWAIT);

        if (exp_ignored)
        {
            if (rc >= 0)
            {
                ERROR_VERDICT("recv() on IUT passed after receiving a "
                              "packet which should have been ignored");
                test_failed = TRUE;
            }
            else if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            {
                ERROR_VERDICT("recv() on IUT failed with unexpected errno "
                              "%r after receiving a packet which should "
                              "have been ignored", RPC_ERRNO(pco_iut));
                test_failed = TRUE;
            }
        }
        else
        {
            if (rc < 0)
            {
                ERROR_VERDICT("recv() on IUT failed with unexpected "
                              "errno %r", RPC_ERRNO(pco_iut));
                test_failed = TRUE;
            }
            else if ((size_t)rc != data_len ||
                     memcmp(data, recv_buf, data_len) != 0)
            {
                ERROR_VERDICT("Data received on IUT differs from "
                              "sent data");
                test_failed = TRUE;
            }
        }
    }

    TEST_STEP("If reply packet is expected from IUT socket, check that "
              "in it TCP timestamp echo-reply is updated to @p test_ts "
              "if @p test_ts >= 0, or is the last timestamp value "
              "sent from Tester before the test packet otherwise.");

    if (exp_reply)
    {
        if (!check_ts_echo(csap_tst_s, 0, test_ts))
            test_failed = TRUE;
    }

    TEST_STEP("If test packet acknowledged some packet from IUT or had @c RST "
              "bit set, and IUT should not have ignored it because of bad "
              "timestamp, check that IUT is not retransmitting anything now. If "
              "IUT sent a packet and did not received correct packet with "
              "acknowledgment, check that it still retransmits it.");

    if ((parsed_flags & (TEST_PKT_FLAG_ACK_CUR | TEST_PKT_FLAG_RST)))
    {
        RING("Checking if IUT socket still transmits some packets");
        tapi_tcp_wait_packet(csap_tst_s, 0);

        rc = tapi_tcp_wait_packet(csap_tst_s, 2000);
        if (rc == 0)
            RING("New packet(s) from IUT socket was detected");
        else
            RING("No new packets from IUT socket were detected");

        if (exp_ignored && exp_retransmit)
        {
            if (rc != 0)
                TEST_VERDICT("Failed to catch expected retransmits from "
                             "IUT socket at the end");
        }
        else
        {
            if (rc == 0)
                TEST_VERDICT("IUT socket retransmits packets at the end");
        }
    }

    TEST_STEP("If reply packet was not expected from IUT socket, but test "
              "packet should have been accepted and current TCP state allows "
              "to send data, send some data from IUT socket and check that "
              "TCP echo-reply is set to @p test_ts if @p test_ts >= 0, or "
              "to the last timestamp sent from Tester before the test packet "
              "otherwise.");

    if (!exp_reply && !exp_ignored &&
        (cur_state == RPC_TCP_ESTABLISHED ||
         cur_state == RPC_TCP_CLOSE_WAIT))
    {
        data_len = rand_range(1, sizeof(send_buf));
        rpc_send(pco_iut, iut_s, send_buf, data_len, 0);

        if (!check_ts_echo(csap_tst_s, TAPI_WAIT_NETWORK_DELAY, test_ts))
            test_failed = TRUE;
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);

    asn_free_value(pkt_tmpl);

    if (tsa_destroy_session(&ss) != 0)
       TEST_FAIL("Closing working session with TSA failed");

    TEST_END;
}
