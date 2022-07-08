/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP
 *
 */

/** @page tcp-ts_send TCP timestamps in sent packets
 *
 * @objective Check that if TCP timestamps are enabled, all the packets
 *            sent from IUT (including ACKs) contain this option.
 *
 * @type conformance
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_peer2peer
 *                            - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type           Socket type:
 *                            - @c tcp_active
 *                            - @c tcp_passive_close
 * @param passive_close       If @c TRUE, close TCP connection on Tester
 *                            firstly; otherwise - on IUT.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/ts_send"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "tcp_test_macros.h"

/**
 * Delay in ms between send() calls to ensure IUT ACKs every packet
 * independently. See ON-13425 and ST-2619.
 */
#define TEST_SEND_WAIT 50

/**
 * Structure used to pass data to CSAP callback and retrieve
 * processing results.
 */
typedef struct csap_data {
    const struct sockaddr *iut_addr;  /**< IUT IP address. */
    const struct sockaddr *tst_addr;  /**< Tester IP address. */

    te_bool iut_pkt_got;    /**< Set to TRUE when the first packet
                                 from IUT is captured */
    te_bool tst_pkt_got;    /**< Set to TRUE when the first packet
                                 from Tester is captured */
    uint32_t last_ts_got;   /**< Last timestamp got from Tester */
    uint32_t last_ts_sent;  /**< Last timestamp sent to Tester */

    te_bool failed; /**< Set to TRUE if some error occurred when
                         processing captured packets */
} csap_data;

/**
 * Append TCP flags description to te_string.
 *
 * @param flags     TCP flags.
 * @param str       Pointer to te_string.
 *
 * @return Status code.
 */
static te_errno
append_flags_descr(uint32_t flags, te_string *str)
{
    te_bool added_flag = FALSE;

#define CHECK_FLAG(_flags, _f, _s) \
    do {                                                  \
        te_errno _rc;                                     \
                                                          \
        if (_flags & TCP_ ## _f ## _FLAG)                 \
        {                                                 \
            if (added_flag)                               \
                _rc = te_string_append(_s, "|%s", #_f);   \
            else                                          \
                _rc = te_string_append(_s, "%s", #_f);    \
                                                          \
            if (_rc != 0)                                 \
                return _rc;                               \
                                                          \
            added_flag = TRUE;                            \
        }                                                 \
    } while (0)

    CHECK_FLAG(flags, SYN, str);
    CHECK_FLAG(flags, FIN, str);
    CHECK_FLAG(flags, RST, str);
    CHECK_FLAG(flags, ACK, str);

    if (!added_flag)
        return te_string_append(str, "no");

    return 0;
#undef CHECK_FLAG
}

/**
 * Process TCP packet captured by CSAP.
 *
 * @param pkt         TCP packet.
 * @param user_data   Pointer to csap_data.
 */
static void
pkt_handler(asn_value *pkt, void *user_data)
{
#define CB_CHECK_RC(_expr) \
    do {                                              \
        te_errno _rc = (_expr);                       \
                                                      \
        if (_rc != 0)                                 \
        {                                             \
            ERROR("%s returned %r", #_expr, _rc);     \
            data->failed = TRUE;                      \
            goto cleanup;                             \
        }                                             \
    } while (0)

    csap_data *data = (csap_data *)user_data;

    uint32_t ts_value;
    uint32_t ts_echo;
    uint32_t flags;
    unsigned int payload_len;
    te_errno rc;

    sockts_addrs_direction dir;

    te_string pkt_descr = TE_STRING_INIT_STATIC(1024);
    const char *pkt_source;

    if (data->failed)
        goto cleanup;

    rc = sockts_tcp_asn_addrs_match(pkt, data->iut_addr, data->tst_addr,
                                    &dir);
    if (rc != 0)
    {
        data->failed = TRUE;
        goto cleanup;
    }
    if (dir == SOCKTS_ADDRS_NO_MATCH)
        goto cleanup;
    else if (dir == SOCKTS_ADDRS_FORWARD)
        pkt_source = "IUT";
    else
        pkt_source = "Tester";

    CB_CHECK_RC(asn_read_uint32(pkt, &flags, "pdus.0.#tcp.flags"));
    CB_CHECK_RC(tapi_tcp_get_hdrs_payload_len(pkt, NULL, &payload_len));

    CB_CHECK_RC(te_string_append(&pkt_descr, "packet with "));
    CB_CHECK_RC(append_flags_descr(flags, &pkt_descr));
    CB_CHECK_RC(te_string_append(&pkt_descr, " flag(s)"));

    if (payload_len > 0)
        CB_CHECK_RC(te_string_append(&pkt_descr, " and payload"));

    CB_CHECK_RC(te_string_append(&pkt_descr, " sent from %s",
                                 pkt_source));

    rc = tapi_tcp_get_ts_opt(pkt, &ts_value, &ts_echo);
    if (rc != 0)
    {
        ERROR_VERDICT("Failed to get TCP timestamp from a %s",
                      pkt_descr.ptr);
        data->failed = TRUE;
        goto cleanup;
    }

    RING("%s: TCP timestamp value %u echo-reply %u", pkt_descr.ptr,
         ts_value, ts_echo);

    if (dir == SOCKTS_ADDRS_BACKWARD)
    {
        data->last_ts_got = ts_value;
        data->tst_pkt_got = TRUE;
    }
    else
    {
        if (data->tst_pkt_got)
        {
            if (ts_echo != data->last_ts_got)
            {
                ERROR("IUT echoes %u instead of %u in TCP timestamp "
                      "echo-reply", ts_echo, data->last_ts_got);
                ERROR_VERDICT("Unexpected timestamp echo-reply");
                data->failed = TRUE;
            }
        }

        if (data->iut_pkt_got)
        {
            if (data->last_ts_sent > ts_value &&
                data->last_ts_sent - ts_value < UINT_MAX / 2)
            {
                ERROR_VERDICT("The next IUT packet has smaller timestamp");
                data->failed = TRUE;
            }
        }

        data->last_ts_sent = ts_value;
        data->iut_pkt_got = TRUE;
    }

cleanup:

    asn_free_value(pkt);
#undef CB_CHECK_RC
}

/**
 * Check data transmissoin in one direction.
 *
 * @param rpcs1     RPC server holding the socket which sends data.
 * @param s1        Socket from which to send data.
 * @param rpcs2     RPC server holding the socket which receives data.
 * @param s2        Socket which should receive data.
 * @param send_wait Number of milliseconds to wait before next send.
 *
 * @return Status code.
 */
static te_errno
test_send(rcf_rpc_server *rpcs1, int s1, rcf_rpc_server *rpcs2, int s2,
          int send_wait)
{
    sockts_test_send_rc       rc;
    sockts_test_send_ext_args args = SOCKTS_TEST_SEND_EXT_ARGS_INIT;

    args.rpcs_send = rpcs1;
    args.s_send = s1;
    args.rpcs_recv = rpcs2;
    args.s_recv = s2;
    args.send_wait = send_wait;

    rc = sockts_test_send_ext(&args);

    if (rc == SOCKTS_TEST_SEND_NO_DATA)
        return TE_ENODATA;
    else if (rc != 0)
        return TE_EFAIL;

    return 0;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct if_nameindex *tst_if = NULL;
    sockts_socket_type sock_type;
    te_bool passive_close;

    int iut_s = -1;
    int tst_s = -1;

    csap_handle_t csap_recv = CSAP_INVALID_HANDLE;
    csap_data user_data;
    tapi_tad_trrecv_cb_data cb_data;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(passive_close);

    /* Do not print captured packets in log */
    rcf_tr_op_log(FALSE);

    TEST_STEP("Create a CSAP on Tester to capture TCP packets sent "
              "and received over the Tester interface.");

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name,
        TAD_ETH_RECV_OUT | TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL, iut_addr->sa_family, NULL, NULL, -1, -1,
        &csap_recv));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_recv, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Send packets in both directions over the established "
              "connection.");
    CHECK_RC(test_send(pco_iut, iut_s, pco_tst, tst_s, TEST_SEND_WAIT));
    CHECK_RC(test_send(pco_tst, tst_s, pco_iut, iut_s, TEST_SEND_WAIT));

    TEST_STEP("Close the connection according to @p passive_close.");

    if (passive_close)
    {
        RPC_CLOSE(pco_tst, tst_s);
        TAPI_WAIT_NETWORK;
    }

    RPC_CLOSE(pco_iut, iut_s);
    TAPI_WAIT_NETWORK;

    if (!passive_close)
    {
        RPC_CLOSE(pco_tst, tst_s);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Check the packets captured by the CSAP. "
              "Every packet sent from IUT should have appropriate "
              "TCP timestamp value and timestamp echo-reply.");

    memset(&cb_data, 0, sizeof(cb_data));
    memset(&user_data, 0, sizeof(user_data));

    user_data.iut_addr = iut_addr;
    user_data.tst_addr = tst_addr;

    cb_data.callback = &pkt_handler;
    cb_data.user_data = &user_data;

    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, csap_recv,
                                 &cb_data, NULL));

    if (!user_data.iut_pkt_got || !user_data.tst_pkt_got)
        TEST_FAIL("CSAP captured no packets from IUT and/or from Tester");

    if (user_data.failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(
                                  pco_tst->ta, 0,
                                  csap_recv));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
