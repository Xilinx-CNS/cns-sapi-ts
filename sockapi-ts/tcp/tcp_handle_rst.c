/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page tcp-tcp_handle_rst TCP socket handling RST flag received from peer 
 *
 * @objective Check that socket in different TCP socket states processes
 *            packet with RST flag from peer correctly.
 * 
 * @type conformance
 *
 * @reference MAN 7 tcp
 * @reference RFC 793
 * @reference RFC 1122
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param pco_gw           PCO on host in the tested network
 *                         that is able to forward incoming packets
 *                         (gateway)
 * @param iut_if           Network interface on @p pco_iut
 * @param tst_if           Network interface on @p pco_tst
 * @param iut_addr         Network address on @p pco_iut
 * @param tst_addr         Network address on @p pco_tst
 * @param gw_iut_addr      Gateway address on interface conneced with
 *                         @p pco_iut
 * @param gw_tst_addr      Gateway address on interface conneced with
 *                         @p pco_iut
 * @param alien_link_addr  Invalid ethernet address
 * @param tcp_state        TCP state to be tested
 * @param loopback         Whether loopback interface is to be tested
 *                         or not
 * @param tst_type         What should be used on the TST side (socket,
 *                         CSAP, etc)?
 * @param close_iut        Close IUT socket before RST transmission.
 * @param send_data        If @c TRUE, RST packet should be sent with
 *                         some payload.
 * @param seqn_val         Value of sequence number in RST segment
 *                         - next (valid seq number)
 *                         - next_plus_1 (next + 1)
 *                         - next-1 (next - 1)
 *                         - next-2 (next - 2)
 *                         - next_plus_maxoffs (next + 2^31 - 1)
 *
 * @note In linux at least up to 2.6.38.2 kernel TCP_CLOSE is displayed
 *       instead of TCP_TIME_WAIT in tcpi_state field of tcp_info structure
 *       (see https://bugzilla.kernel.org/show_bug.cgi?id=33902).
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_handle_rst"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_sniffer.h"

/* Remove this when ST-2364 is fixed */
#define DEBUG_TSA_CSAP

#define MAX_TCP_STR_LEN 1000

/* Maximum offset of the incorrect sequence number. */
#define MAX_OFFT ((((uint32_t)1) << 31) - 1)

/* Length of data to send in ESTABLISHED state. */
#define BUF_LEN 10000

/**
 * Available options to choose which sequence number should be used in the
 * RST segment.
 */
typedef enum {
    SEQN_NEXT,          /**< next - valid sequence number */
    SEQN_NEXT_MINUS_1,  /**< next - 1 */
    SEQN_NEXT_MINUS_2,  /**< next - 2 */
    SEQN_NEXT_PLUS_1,   /**< next + 1 */
    SEQN_NEXT_PLUS_MAX  /**< next + 2^31 - 1 */
} seqn_value;

/**
 * List of possible values of "seqn_val" test parameter,
 * to be passed to TEST_GET_ENUM_PARAM().
 */
#define SEQN_VALUE   \
    { "next",   SEQN_NEXT },                \
    { "next-1", SEQN_NEXT_MINUS_1 },        \
    { "next-2", SEQN_NEXT_MINUS_2 },        \
    { "next_plus_1", SEQN_NEXT_PLUS_1 },         \
    { "next_plus_maxoffs", SEQN_NEXT_PLUS_MAX }

/** Get random boolean value */
#define RANDOM_BOOLEAN (rand_range(1, 1000) > 500 ? TRUE : FALSE)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_gw = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *gw_iut_addr = NULL;
    const struct sockaddr *gw_tst_addr = NULL;

    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *gw_iut_if = NULL;
    const struct if_nameindex *gw_tst_if = NULL;
    const struct sockaddr     *alien_link_addr = NULL;

    tsa_session ss = TSA_SESSION_INITIALIZER;

    const char     *tcp_state;
    tsa_tst_type    tst_type;
    te_bool         close_iut;
    te_bool         active;
    te_bool         loopback = FALSE;
    te_bool         send_data;
    uint32_t        flags = 0;

    rpc_tcp_state       state_to;
    rpc_tcp_state       state_prev;
    tapi_tcp_handler_t  csap_tst_s;
    char                send_buf[SOCKTS_MSG_STREAM_MAX];
    char                recv_buf[SOCKTS_MSG_STREAM_MAX];
    size_t              data_len = 0;
    asn_value          *pkt_tmpl = NULL;
    seqn_value          seqn_val = SEQN_NEXT;
    int                 seqn;
    te_bool             pass_data;
    uint8_t            *buf = NULL;
    te_dbuf             recv_data = TE_DBUF_INIT(0);

    int iut_s = -1;
    int opt_val = 0;
    int exp_err = 0;

    te_bool is_failed = FALSE;

#ifdef DEBUG_TSA_CSAP
    tapi_sniffer_id *sniff_gw_iut = NULL;
    tapi_sniffer_id *sniff_gw_tst = NULL;
#endif

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_TSA_TST_TYPE_PARAM(tst_type);
    TEST_GET_BOOL_PARAM(close_iut);
    TEST_GET_BOOL_PARAM(loopback);
    TEST_GET_BOOL_PARAM(send_data);
    TEST_GET_ENUM_PARAM(seqn_val, SEQN_VALUE);

    if (!loopback)
    {
        TEST_GET_PCO(pco_gw);
        TEST_GET_ADDR_NO_PORT(gw_iut_addr);
        TEST_GET_ADDR_NO_PORT(gw_tst_addr);
        TEST_GET_LINK_ADDR(alien_link_addr);
        TEST_GET_IF(gw_iut_if);
        TEST_GET_IF(gw_tst_if);
    }

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);

    TEST_GET_STRING_PARAM(tcp_state);

#ifdef DEBUG_TSA_CSAP
    /* Configure sniffers on gateway to debug ST-2364 */
    if (!loopback)
    {
        CHECK_NOT_NULL(sniff_gw_iut = tapi_sniffer_add(
                                          pco_gw->ta, gw_iut_if->if_name,
                                          NULL, NULL, TRUE));
        CHECK_NOT_NULL(sniff_gw_tst = tapi_sniffer_add(
                                          pco_gw->ta, gw_tst_if->if_name,
                                          NULL, NULL, TRUE));
    }
#endif

    TEST_STEP("Choose randomly values of @b pass_data (if @c TRUE, "
              "some data will be sent after connection establishment) and "
              "@b active (if @c TRUE, connection will be established "
              "actively from IUT, otherwise - passively).");
    if (strcmp(tcp_state, "TCP_SYN_SENT") == 0)
    {
        TEST_SUBSTEP("If @p tcp_state is @c TCP_SYN_SENT, @b pass_data "
                     "can only be @c FALSE and @b active can only be "
                     "@c TRUE.");
        pass_data = FALSE;
        active = TRUE;
    }
    else
    {
        pass_data = RANDOM_BOOLEAN;
        active = RANDOM_BOOLEAN;
    }

    RING("pass_data=%s active=%s", (pass_data ? "TRUE" : "FALSE"),
         (active ? "TRUE" : "FALSE"));

    TEST_STEP("Initialize TSA state structure and open sockets with help "
              "of @b tsa_init() and @b tsa_create_session().");
    if (tsa_state_init(&ss, tst_type) != 0)
        TEST_FAIL("Unable to initialize TSA");

    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL));

    if (!loopback)
    {
        CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
                            gw_iut_if, gw_tst_if,
                            alien_link_addr->sa_data));
        CFG_WAIT_CHANGES;
    }

    if (tst_type == TSA_TST_SOCKET)
        flags = TSA_TST_USE_REUSEADDR;

    if (loopback)
        flags = flags | TSA_NO_CONNECTIVITY_CHANGE | TSA_MOVE_IGNORE_ERR;

    if (!active)
        flags |= TSA_ESTABLISH_PASSIVE | TSA_MOVE_IGNORE_START_ERR;

    tsa_create_session(&ss, flags);

    if (tsa_state_cur(&ss) == RPC_TCP_UNKNOWN)
    {
        RING_VERDICT("TCP socket is in unknown TCP state just "
                     "after creation");
        tsa_state_cur_set(&ss, RPC_TCP_CLOSE);
    }

    TEST_STEP("Move IUT socket to @p tcp_state TCP state. Active/passive "
              "connection establishment depends on the @b active variable. "
              "If there is TCP_ESTABLISHED state on the way to this state "
              "from TCP_CLOSE, we stop at it to perform sending operations "
              "(if @b pass_data is @c TRUE) and then resume moving "
              "to @p tcp_state from it.");
    rc = tsa_do_moves_str(&ss, RPC_TCP_UNKNOWN, RPC_TCP_ESTABLISHED,
                          flags, tcp_state);
    if (rc == TSA_ESTOP)
    {
        /* We are in TCP_ESTABLISHED state */
        if (pass_data)
        {
            buf = te_make_buf_by_len(BUF_LEN);

            /* Send data from IUT to Tester */
            rpc_send(pco_iut, tsa_iut_sock(&ss), buf, BUF_LEN, 0);
            if (tst_type == TSA_TST_GW_CSAP)
            {
                tapi_tcp_recv_data(tsa_tst_sock(&ss), TAPI_WAIT_NETWORK_DELAY,
                                   TAPI_TCP_AUTO, &recv_data);
            }
            else
            {
                rpc_drain_fd_simple(pco_tst, tsa_tst_sock(&ss), NULL);
            }

            /* Send data from Tester to IUT */
            if (tst_type == TSA_TST_GW_CSAP)
            {
                int     data_sent = 0;
                char    rx_buf[1024];
                int     data_chunk = sizeof(rx_buf);

                while (data_sent < BUF_LEN)
                {
                    if (BUF_LEN - data_sent < data_chunk)
                        data_chunk = BUF_LEN - data_sent;

                    CHECK_RC(tapi_tcp_send_msg(tsa_tst_sock(&ss),
                                               buf + data_sent,
                                               data_chunk,
                                               TAPI_TCP_AUTO, 0,
                                               TAPI_TCP_AUTO, 0,
                                               NULL, 0));
                    TAPI_WAIT_NETWORK;
                    data_sent += rpc_recv(pco_iut, tsa_iut_sock(&ss),
                                          rx_buf, sizeof(rx_buf), 0);
                }
            }
            else
            {
                rpc_send(pco_tst, tsa_tst_sock(&ss), buf, BUF_LEN, 0);
                rpc_drain_fd_simple(pco_iut, tsa_iut_sock(&ss), NULL);
            }
        }

        rc = tsa_do_moves_str(&ss, tsa_state_to(&ss), RPC_TCP_UNKNOWN,
                              flags, tsa_rem_path(&ss));
    }

    if (rc != 0 || tsa_state_to(&ss) != tsa_state_cur(&ss))
    {
        if (tsa_state_to(&ss) == RPC_TCP_TIME_WAIT &&
            tsa_state_cur(&ss) == RPC_TCP_CLOSE)
            RING("%s is not observable",
                 tcp_state_rpc2str(tsa_state_to(&ss)));
        else
            TEST_VERDICT("%s was not achieved",
                         tcp_state_rpc2str(tsa_state_to(&ss)));
    }

    state_to = tsa_state_to(&ss);

    TEST_STEP("Close IUT socket if @p close_iut. "
              "In case of passive connection opening close listening socket too.");
    if (close_iut)
        RPC_CLOSE(pco_iut, ss.state.iut_s);

    /* In SYN_SENT state we have no listening socket.*/
    if (close_iut && !active && state_to != RPC_TCP_SYN_SENT)
        RPC_CLOSE(pco_iut, ss.state.iut_s_aux);

    TEST_STEP("Send RST.");
    if (send_data || seqn_val != SEQN_NEXT)
    {
        if (tst_type == TSA_TST_SOCKET)
            TEST_FAIL("RST with data or invalid SEQN cannot be checked"
                      "when socket is used on Tester");

        csap_tst_s = tsa_tst_sock(&ss);
        tapi_tcp_wait_msg(csap_tst_s, TAPI_WAIT_NETWORK_DELAY);

        if (send_data)
        {
            data_len = rand_range(1, sizeof(send_buf));
            te_fill_buf(send_buf, data_len);
        }

        CHECK_RC(tapi_tcp_conn_template(csap_tst_s,
                                        send_data ? (uint8_t *)send_buf : NULL,
                                        send_data ? data_len : 0,
                                        &pkt_tmpl));
        CHECK_RC(asn_write_uint32(pkt_tmpl, TCP_ACK_FLAG | TCP_RST_FLAG,
                                  "pdus.0.#tcp.flags.#plain"));
        CHECK_RC(asn_write_uint32(pkt_tmpl, tapi_tcp_next_ackn(csap_tst_s),
                                  "pdus.0.#tcp.ackn.#plain"));

        switch (seqn_val)
        {
            case SEQN_NEXT:
                seqn = tapi_tcp_next_seqn(csap_tst_s);
                break;
            case SEQN_NEXT_PLUS_1:
                seqn = tapi_tcp_next_seqn(csap_tst_s) + 1;
                break;
            case SEQN_NEXT_MINUS_1:
                seqn = tapi_tcp_next_seqn(csap_tst_s) - 1;
                break;
            case SEQN_NEXT_MINUS_2:
                seqn = tapi_tcp_next_seqn(csap_tst_s) - 2;
                break;
            case SEQN_NEXT_PLUS_MAX:
                seqn = tapi_tcp_next_seqn(csap_tst_s) + MAX_OFFT;
                break;
            default:
                TEST_FAIL("Invalid test parameter 'seqn_val'");
                break;
        }
        CHECK_RC(asn_write_uint32(pkt_tmpl, seqn, "pdus.0.#tcp.seqn.#plain"));

        CHECK_RC(tapi_tcp_send_template(csap_tst_s, pkt_tmpl,
                                        RCF_MODE_BLOCKING));
    }
    else
    {
        tsa_tst_send_rst(&ss);
    }
    TAPI_WAIT_NETWORK;

    TEST_STEP("Create new TCP socket and check if it is possible to bind to the "
              "same address:port.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                          RPC_SOCK_STREAM, RPC_PROTO_DEF);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_s, iut_addr);

    if (close_iut)
    {
        TEST_SUBSTEP("If @p close_iut is TRUE binding address:port must be released "
                     "immediately in case of valid sequence number. In case of invalid "
                     "sequence number binding must fail.");
        if (rc != 0 && seqn_val == SEQN_NEXT)
            TEST_VERDICT("bind() unexpectedly failed with %r",
                         RPC_ERRNO(pco_iut));
        /* SYN_SENT->close()->bind() always succeed. No sense to check it. */
        if (rc == 0 && seqn_val != SEQN_NEXT && state_to != RPC_TCP_SYN_SENT)
            TEST_VERDICT("bind() unexpectedly succeed with invalid SEQN "
                         "in RST segment");
        TEST_SUCCESS;
    }
    else
    {
        TEST_SUBSTEP("Else, IUT socket descriptor is still open - address should not be "
                     "released.");
        if (rc == 0)
        {
            RING_VERDICT("bind() unexpectedly succeed");
            is_failed = TRUE;
        }
        else
        {
            CHECK_RPC_ERRNO_NOEXIT(pco_iut, RPC_EADDRINUSE, is_failed,
                                   "bind() failed but returned "
                                   "unexpected errno");
        }
    }
    RPC_CLOSE(pco_iut, iut_s);

    TEST_STEP("Check that IUT socket is in TCP_CLOSE state after "
              "receiving valid RST. After receiving invalid RST state "
              "must not change.");
    state_prev = tsa_state_cur(&ss);
    tsa_update_cur_state(&ss);
    if (tsa_state_cur(&ss) != RPC_TCP_CLOSE && seqn_val == SEQN_NEXT)
    {
        RING_VERDICT("TCP socket is in %s state after "
                     "receiving valid RST",
                     tcp_state_rpc2str(tsa_state_cur(&ss)));
        is_failed = TRUE;
    }
    else if (tsa_state_cur(&ss) != state_prev && seqn_val != SEQN_NEXT)
    {
        /* In SYN_SENT state sequence number of RST segment does not matter. */
        if (tsa_state_cur(&ss) == RPC_TCP_CLOSE &&
            state_to == RPC_TCP_SYN_SENT)
            TEST_SUCCESS;

        TEST_VERDICT("TCP socket is in %s state after "
                     "receiving invalid RST",
                     tcp_state_rpc2str(tsa_state_cur(&ss)));
    }
    else if (tsa_state_cur(&ss) == state_prev && seqn_val != SEQN_NEXT)
    {
        TEST_SUCCESS;
    }

    TEST_STEP("Check value of @c SO_ERROR socket option.");
    iut_s = tsa_iut_sock(&ss);

    /*
     * In case of RST received in TCP_SYN_SENT state,
     * error is reported by connect() call, and SO_ERROR
     * option is reset to zero.
     */
    if (state_to == RPC_TCP_SYN_SENT)
        exp_err = RPC_ECONNREFUSED;
    else if (state_to != RPC_TCP_TIME_WAIT)
        exp_err = RPC_ECONNRESET;
    else
        exp_err = RPC_EOK;

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != exp_err)
    {
        RING_VERDICT("SO_ERROR socket option is equal to %s, "
                     "but must be %s",
                     errno_rpc2str(opt_val),
                     errno_rpc2str(exp_err));
        is_failed = TRUE;
    }

    TEST_STEP("Check values returned by @b send() and @b recv() functions.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, send_buf, sizeof(send_buf), 0);
    if (rc < 0)
    {
        if (RPC_ERRNO(pco_iut) == RPC_EPIPE)
            RING("send() function failed with errno %s",
                 errno_rpc2str(RPC_ERRNO(pco_iut)));
        else
            RING_VERDICT("send() function failed with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        RING_VERDICT("send() function succeed on socket received RST");
        is_failed = TRUE;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, recv_buf, sizeof(recv_buf), 0);
    if (rc < 0)
    {
        RING_VERDICT("recv() function failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else if (rc == 0)
    {
        RING("recv() function succeed on socket received RST");
    }
    else if (rc > 0)
    {
        RING_VERDICT("recv() returned some data from received RST");
        if ((size_t)rc != data_len || memcmp(send_buf, recv_buf, rc) != 0)
            TEST_VERDICT("Data received on IUT does not match sent data");
    }

    if (is_failed)
        TEST_STOP;
    else
        TEST_SUCCESS;

cleanup:

#ifdef DEBUG_TSA_CSAP
    /* Temporary code to debug ST-2364 */
    if (!loopback)
    {
        rpc_system(pco_gw, "ip neigh show");
        rpc_system(pco_gw, "ip -6 neigh show");

        CLEANUP_CHECK_RC(tapi_sniffer_del(sniff_gw_iut));
        CLEANUP_CHECK_RC(tapi_sniffer_del(sniff_gw_tst));
    }
#endif

    te_dbuf_free(&recv_data);
    free(buf);
    asn_free_value(pkt_tmpl);

    if (tsa_destroy_session(&ss) != 0)
        CLEANUP_TEST_FAIL("Closing working session with TSA failed");

    TEST_END;
}
