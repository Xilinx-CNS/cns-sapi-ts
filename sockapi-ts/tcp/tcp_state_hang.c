/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page tcp-tcp_state_hang Check whether socket can hang in some state after receiving ACK with incorrect sequence number
 *
 * @objective Check that socket cannot hang in TCP_SYN_RECV, TCP_CLOSING,
 *            TCP_LAST_ACK or TCP_FIN_WAIT1 due to receiving an ACK
 *            with incorrect sequence number
 *
 * @type conformance
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param iut_if           Network interface on @p pco_iut
 * @param tst_if           Network interface on @p pco_tst
 * @param iut_addr         Network address on @p pco_iut
 * @param tst_addr         Network address on @p pco_tst
 * @param alien_link_addr  Invalid ethernet address
 * @param tcp_state        TCP state to be tested
 * @param opening          Connection establishment way
 * @param seqn             Which sequence number should be used in the
 *                         invalid ACK message.
 * @param cache_socket     If @c TRUE, create cached socket to be reused.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_state_hang"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_sniffer.h"

/* Remove this when ST-2364 is fixed */
#define DEBUG_TSA_CSAP

#define MAX_TCP_STR_LEN 1000
#define TIMEOUT_USED "Timeout was used. "

#define MAX_ATTEMPTS 60
#define MSEC_BEFORE_NEXT_ATTEMPT 1000
#define RETRIES_NUM_STR "4"
#define RETRIES_NUM atoi(RETRIES_NUM_STR)
#define FIN_TIMEOUT 15
#define IUT_PKGS_TIMEOUT 2000
#define SYNACK_RETRIES 3

/* Maximum offset of the incorrect sequence number. */
#define MAX_OFFT ((((uint32_t)1) << 31) - 1)

/**
 * Available options to choose which sequence number should be used in the
 * invalid ACK message.
 */
typedef enum {
    TEST_ACK_SEQN_LAST = 0, /**< Sequence number of the previous packet,
                                 (imitate zero window) */
    TEST_ACK_SEQN_1,        /**< last_seqn-1 */
    TEST_ACK_SEQN_M,        /**< last_seqn-2^31+1 */
    TEST_ACK_SEQN_RAND,     /**< last_seqn-random */
} test_ack_seqn;

#define TEST_ACK_SEQN   \
    { "last_seqn", TEST_ACK_SEQN_LAST },        \
    { "last_seqn-1", TEST_ACK_SEQN_1 },         \
    { "last_seqn-2^31+1", TEST_ACK_SEQN_M },    \
    { "last_seqn-random", TEST_ACK_SEQN_RAND }

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    rcf_rpc_server             *pco_gw = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *gw_iut_addr = NULL;
    const struct sockaddr      *gw_tst_addr = NULL;
    const struct sockaddr      *tst_alien_addr = NULL;
    const struct sockaddr      *alien_link_addr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *gw_tst_if = NULL;
    const struct if_nameindex  *gw_iut_if = NULL;

    const char *tcp_state;
    int         opening;
    int         seqn;

    te_bool cache_socket;

    tsa_session ss = TSA_SESSION_INITIALIZER;

    int                 retries2 = 0;
    int                 iut_s;
    int                 opt_val;
    tapi_tcp_handler_t  csap_tst_s;
    tapi_tcp_pos_t      last_seqn;
    rpc_tcp_state       last_state;
    rpc_tcp_state       state;

#ifdef DEBUG_TSA_CSAP
    tapi_sniffer_id *sniff_gw_iut = NULL;
    tapi_sniffer_id *sniff_gw_tst = NULL;
#endif

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_gw);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_gw, gw_iut_addr);
    TEST_GET_ADDR(pco_gw, gw_tst_addr);
    TEST_GET_ADDR(pco_tst, tst_alien_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(gw_tst_if);
    TEST_GET_IF(gw_iut_if);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_STRING_PARAM(tcp_state);
    TEST_GET_ENUM_PARAM(seqn, TEST_ACK_SEQN);
    TEST_GET_ENUM_PARAM(opening, OPENING_LISTENER);
    TEST_GET_BOOL_PARAM(cache_socket);

#ifdef DEBUG_TSA_CSAP
    /* Configure sniffers on gateway to debug ST-2364 */
    CHECK_NOT_NULL(sniff_gw_iut = tapi_sniffer_add(
                                      pco_gw->ta, gw_iut_if->if_name,
                                      NULL, NULL, TRUE));
    CHECK_NOT_NULL(sniff_gw_tst = tapi_sniffer_add(
                                      pco_gw->ta, gw_tst_if->if_name,
                                      NULL, NULL, TRUE));
#endif

    state = tcp_state_str2rpc(tcp_state);

   TEST_STEP("Initialize TSA state structure and open sockets with help of @b "
             "tsa_init() and @b tsa_create_session().");

    if (tsa_state_init(&ss, TSA_TST_GW_CSAP) != 0)
        TEST_FAIL("Unable to initialize TSA");

    tsa_iut_set(&ss, pco_iut, iut_if, iut_addr);
    tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL);
    tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
               gw_iut_if, gw_tst_if,
               alien_link_addr->sa_data);
    CFG_WAIT_CHANGES;

    if (state == RPC_TCP_SYN_RECV)
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, SYNACK_RETRIES, NULL,
                                         "net/ipv4/tcp_synack_retries"));

    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, &retries2,
                                                 "net/ipv4/tcp_retries2"));
    rcf_rpc_server_restart(pco_iut);

    TEST_STEP("If @p cache_socket is @c TRUE and @p opening is @c OL_ACTIVE - create "
              "cached socket.");
    if (opening == OL_ACTIVE)
    {
        sockts_create_cached_socket(pco_iut, pco_gw, iut_addr, gw_iut_addr, -1,
                                    TRUE, cache_socket);
    }

    tsa_create_session(&ss, 0);
    /*
     * Enabling promiscuous mode can take some time on virtual hosts,
     * see ST-2675.
     */
    VSLEEP(1, "Wait for promiscuous mode to turn on");

    if (state == RPC_TCP_FIN_WAIT1)
    {
        /* From TCP_FIN_WAIT1 we can move to TCP_FIN_WAIT2 after
         * receiving an ACK. See comments in tcp_timeout.c for explanation
         * why this is required to move from TCP_FIN_WAIT2 to
         * TCP_CLOSE due to timeout */
        iut_s = tsa_iut_sock(&ss);
        opt_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &opt_val);
        opt_val = RETRIES_NUM;
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_KEEPCNT, &opt_val);
        opt_val = 10;
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_KEEPIDLE, &opt_val);
        opt_val = 2;
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_KEEPINTVL, &opt_val);
    }

    TEST_STEP("Move socket to the target state @p tcp_state, connection is "
              "established on one of ways in dependence on @p opening.");
    tcp_move_to_state(&ss, state, opening,
                      opening == OL_ACTIVE ? FALSE : cache_socket);

   TEST_STEP("Once we achieved the last state in @p tcp_state_seq, "
             "send to IUT an ACK with sequence number of the previously "
             "sent packet.");

    csap_tst_s = tsa_tst_sock(&ss);

    /* Process FIN packet in TCP_FIN_WAIT1 and TCP_LAST_ACK states. */
    last_state = tsa_state_cur(&ss);
    if (last_state != RPC_TCP_CLOSING)
        tapi_tcp_wait_msg(csap_tst_s, IUT_PKGS_TIMEOUT);

    tsa_update_cur_state(&ss);
    last_state = tsa_state_cur(&ss);

    last_seqn = tapi_tcp_last_seqn_sent(csap_tst_s);

    switch (seqn)
    {
        case TEST_ACK_SEQN_LAST:
            /* Do nothing */
            break;

        case TEST_ACK_SEQN_1:
            last_seqn--;
            break;

        case TEST_ACK_SEQN_M:
            last_seqn -= MAX_OFFT;
            break;

        case TEST_ACK_SEQN_RAND:
            last_seqn -= rand_range(1, MAX_OFFT);
            break;

        default:
            TEST_FAIL("Ivalid test parameter 'seqn'=%d", seqn);
    }

    tapi_tcp_send_msg(csap_tst_s, NULL, 0,
                      TAPI_TCP_EXPLICIT, last_seqn,
                      TAPI_TCP_EXPLICIT,
                      tapi_tcp_next_ackn(csap_tst_s),
                      NULL, 0);

    /* Delay to make sure the ACK packet is delivered. */
    TAPI_WAIT_NETWORK;

   TEST_STEP("Check whether this have caused transition to another TCP state.");
    tsa_update_cur_state(&ss);
    if (tsa_state_cur(&ss) != last_state)
        RING_VERDICT("Sending ACK with incorrect sequence number "
                     "resulted in changing TCP state from %s to %s",
                     tcp_state_rpc2str(last_state),
                     tcp_state_rpc2str(tsa_state_cur(&ss)));

    TEST_STEP("Check that after a while socket is moved to TCP_CLOSE state.");
    if (state == RPC_TCP_SYN_RECV)
        sockts_wait_cleaned_listenq(pco_iut, iut_addr);
    else
        tcp_test_wait_for_tcp_close(&ss, MSEC_BEFORE_NEXT_ATTEMPT,
                                    MAX_ATTEMPTS);

    TEST_SUCCESS;

cleanup:

#ifdef DEBUG_TSA_CSAP
    /* Temporary code to debug ST-2364 */
    rpc_system(pco_gw, "ip neigh show");
    rpc_system(pco_gw, "ip -6 neigh show");
    CLEANUP_CHECK_RC(tapi_sniffer_del(sniff_gw_iut));
    CLEANUP_CHECK_RC(tapi_sniffer_del(sniff_gw_tst));
#endif

    if (tsa_destroy_session(&ss) != 0)
       TEST_FAIL("Closing working session with TSA failed");

    CLEANUP_CHECK_RC(
        tapi_cfg_sys_ns_set_int(pco_iut->ta, retries2, NULL,
                                "net/ipv4/tcp_retries2"));

    TEST_END;
}
