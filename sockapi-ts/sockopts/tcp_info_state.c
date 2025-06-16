/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-tcp_info_state tcpi_state field reporting TCP socket state in tcp_info structure
 *
 * @objective Check that all possible TCP socket states are displayed
 *            correctly in all possible transitions between them.
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
 * @param tcp_state_seq    Tested sequence of TCP states transitions
 * @param loopback         Whether loopback interface is to be tested
 *                         or not
 * @param tst_type         What should be used on the TST side (socket,
 *                         CSAP, etc)?
 *
 * @note In linux transition from TCP_LISTEN to TCP_SYN_SENT is
 *       not supported, transition from TCP_LISTEN to TCP_SYN_RECV cannot
 *       be observed. At least up to 2.6.38.2 kernel TCP_CLOSE is displayed
 *       instead of TCP_TIME_WAIT in tcpi_state field of tcp_info structure
 *       (see https://bugzilla.kernel.org/show_bug.cgi?id=33902).
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_info_state"

#include "sockapi-test.h"

#define MAX_TCP_STR_LEN 1000
#define TIMEOUT_USED "Timeout was used. "

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
    const struct if_nameindex *gw_tst_if = NULL;
    const struct if_nameindex *gw_iut_if = NULL;
    const void                *alien_link_addr = NULL;

    tsa_session ss = TSA_SESSION_INITIALIZER;
    uint32_t    flags = 0;

    const char     *tcp_state_seq;
    tsa_tst_type    tst_type;
    te_bool         loopback;
    char           *timeout_msg;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_TSA_TST_TYPE_PARAM(tst_type);
    TEST_GET_BOOL_PARAM(loopback);

    if (tst_type == TSA_TST_SOCKET && !loopback)
    {
        TEST_GET_PCO(pco_gw);
        TEST_GET_ADDR_NO_PORT(gw_iut_addr);
        TEST_GET_ADDR_NO_PORT(gw_tst_addr);
        TEST_GET_IF(gw_iut_if);
        TEST_GET_IF(gw_tst_if);
    }

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    if (!loopback)
        TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);

    TEST_GET_STRING_PARAM(tcp_state_seq);

   TEST_STEP("Initialize TSA state structure and open sockets with help of @b "
             "tsa_init() and @b tsa_create_session().");

    if (tsa_state_init(&ss, tst_type) != 0)
        TEST_FAIL("Unable to initialize TSA");

    tsa_iut_set(&ss, pco_iut, iut_if, iut_addr);
    if (tst_type == TSA_TST_CSAP)
    {
        tsa_tst_set(&ss, pco_tst, tst_if, tst_addr,
                    ((struct sockaddr *)
                        alien_link_addr)->sa_data);
        CFG_WAIT_CHANGES;
    }
    else
        tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL);

    if (tst_type == TSA_TST_SOCKET)
    {
        if (!loopback)
        {
            if (tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
                           gw_iut_if, gw_tst_if,
                           ((struct sockaddr *)alien_link_addr)->
                                                     sa_data) != 0)
                TEST_FAIL("Gateway initialization failed");

            CFG_WAIT_CHANGES;
        }

        flags = TSA_TST_USE_REUSEADDR;
    }

    if (loopback)
        flags = flags | TSA_NO_CONNECTIVITY_CHANGE;

    tsa_create_session(&ss, flags);

    if (tsa_state_cur(&ss) == RPC_TCP_UNKNOWN)
    {
        RING_VERDICT("TCP socket is in unknown TCP state just "
                     "after creation");
        tsa_state_cur_set(&ss, RPC_TCP_CLOSE);
    }

    TEST_STEP("Call @b tsa_do_moves_str() for tested sequence of TCP states "
              "transitions @p tcp_state_seq.");

    rc = tsa_do_moves_str(&ss,  RPC_TCP_UNKNOWN, RPC_TCP_UNKNOWN, 0,
                          tcp_state_seq);

    if (rc > 0)
    {
        timeout_msg = (tsa_timeout_used(&ss)) ? TIMEOUT_USED : "";
        TEST_VERDICT("%s -> %s failed with rc %s in %s. %s"
                     "Socket in %s instead",
                     tcp_state_rpc2str(tsa_state_from(&ss)),
                     tcp_state_rpc2str(tsa_state_to(&ss)),
                     te_rc_err2str(rc), te_rc_mod2str(rc), timeout_msg,
                     tcp_state_rpc2str(tsa_state_cur(&ss)));
    }

    TEST_SUCCESS;

cleanup:

    if (tsa_destroy_session(&ss) != 0)
       TEST_FAIL("Closing working session with TSA failed");

    TEST_END;
}
