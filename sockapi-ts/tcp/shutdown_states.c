/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page tcp-shutdown Calling shutdown() in different states of TCP socket
 *
 * @objective Check behaviour and effects of shutdown() call on TCP socket in
 *            different TCP states.
 * 
 * @type conformance
 *
 * @reference MAN 7 tcp
 * @reference RFC 793
 * @reference RFC 1122
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param pco_gw            PCO on host in the tested network
 *                          that is able to forward incoming packets
 *                          (gateway)
 * @param iut_if            Network interface on @p pco_iut
 * @param tst_if            Network interface on @p pco_tst
 * @param iut_addr          Network address on @p pco_iut
 * @param tst_addr          Network address on @p pco_tst
 * @param alien_link_addr   Invalid ethernet address
 * @param tcp_state         TCP state in which @b shutdown() to be called
 * @param loopback          Whether loopback interface is to be tested
 *                          or not
 * @param tst_type          What should be used on the TST side (socket,
 *                          CSAP, etc)?
 * @param shutdown_how      Should @b shutdown() be called with SHUT_RD,
 *                          SHUT_WR or SHUT_RDWR?
 * @param tst_send_before   Whether to send data from TESTER before
 *                          @b shutdown() call or not
 * @param tst_send_after    Whether to send data from TESTER after
 *                          @b shutdown() call or not
 * @param iut_send_before   Whether to send data from IUT before
 *                          @b shutdown() call (so that it will be unsent
 *                          yet when @b shutdown() is called) or not
 *
 * @note In linux at least up to 2.6.38.2 kernel TCP_CLOSE is displayed
 *       instead of TCP_TIME_WAIT in tcpi_state field of tcp_info structure
 *       (see https://bugzilla.kernel.org/show_bug.cgi?id=33902).
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/shutdown_states"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_sniffer.h"

/* Remove this when ST-2364 is fixed */
#define DEBUG_TSA_CSAP

#define MAX_TCP_STR_LEN 1000
#define TST_BUF_LEN 100
#define SLEEP_SEC 1000

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

    uint8_t *buf;
    uint8_t *iut_buf;
    uint8_t *tst_buf_before;
    uint8_t *tst_buf_after;

    tsa_session ss = TSA_SESSION_INITIALIZER;

    const char     *tcp_state;
    tsa_tst_type    tst_type;

    rpc_tcp_state   state_to;
    rpc_tcp_state   state_from;
    uint32_t        flags = 0;
    size_t          tst_recv_len;
    uint64_t        iut_sent_len = 0;

    int iut_s = -1;
    int tst_s = -1;

    rpc_shut_how    shutdown_how = RPC_SHUT_NONE;

    te_bool tst_send_before = FALSE;
    te_bool tst_send_after = FALSE;
    te_bool iut_send_before = FALSE;
    te_bool loopback = FALSE;
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
    TEST_GET_BOOL_PARAM(loopback);

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
    TEST_GET_TSA_TST_TYPE_PARAM(tst_type);
    TEST_GET_BOOL_PARAM(tst_send_after);
    TEST_GET_BOOL_PARAM(tst_send_before);
    TEST_GET_BOOL_PARAM(iut_send_before);
    TEST_GET_SHUT_HOW(shutdown_how);

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

    buf = te_make_buf_by_len(TST_BUF_LEN * 2);
    iut_buf = te_make_buf_by_len(TST_BUF_LEN);
    tst_buf_before = te_make_buf_by_len(TST_BUF_LEN - 1);
    tst_buf_after = te_make_buf_by_len(TST_BUF_LEN + 1);

   TEST_STEP("Initialize TSA state structure and open sockets with help of @b "
             "tsa_init() and @b tsa_create_session().");

    if (tsa_state_init(&ss, tst_type) != 0)
        TEST_FAIL("Unable to initialize TSA");

    tsa_iut_set(&ss, pco_iut, iut_if, iut_addr);
    tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL);

    if (tst_type == TSA_TST_SOCKET)
    {
        if (!loopback)
        {
            if (tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
                           gw_iut_if, gw_tst_if,
                           alien_link_addr->sa_data) != 0)
                TEST_FAIL("Gateway initialization failed");

            CFG_WAIT_CHANGES;
        }

        flags = TSA_TST_USE_REUSEADDR;
    }
    else
    {
        CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
                            gw_iut_if, gw_tst_if,
                            alien_link_addr->sa_data));
        CFG_WAIT_CHANGES;
    }

    if (loopback)
        flags = flags | TSA_NO_CONNECTIVITY_CHANGE;

    tsa_create_session(&ss, flags);

    /*
     * Enabling promiscuous mode can take some time on virtual hosts,
     * see ST-2675.
     */
    VSLEEP(1, "Wait for promiscuous mode to turn on");

    if (tsa_state_cur(&ss) == RPC_TCP_UNKNOWN)
    {
        RING_VERDICT("TCP socket is in unknown TCP state just "
                     "after creation");
        tsa_state_cur_set(&ss, RPC_TCP_CLOSE);
    }


    TEST_STEP("Call @b tsa_do_moves_str() to achieve @p tcp_state. If "
              "there is TCP_ESTABLISHED state on the way to this state from "
              "TCP_CLOSE, we stop at it to perform sending operations (if "
              "required) and then resume moving to @p tcp_state from it.");

    rc = tsa_do_moves_str(&ss, RPC_TCP_UNKNOWN, RPC_TCP_ESTABLISHED,
                          (loopback ? TSA_MOVE_IGNORE_ERR : 0),
                          tcp_state);

    if (rc == TSA_ESTOP)
    {
        /* We are in TCP_ESTABLISHED state */
        if (iut_send_before)
        {
            iut_s = tsa_iut_sock(&ss);

            if (tst_type == TSA_TST_GW_CSAP)
                rpc_send(pco_iut, iut_s, iut_buf, TST_BUF_LEN,
                         0);
            else
                rpc_overfill_buffers(pco_iut, iut_s,
                                     &iut_sent_len);
        }

        if (tst_send_before)
        {
            tst_s = tsa_tst_sock(&ss);
            if (tst_type == TSA_TST_GW_CSAP)
            {
                tapi_tcp_wait_msg(tst_s, SLEEP_SEC);
                tapi_tcp_send_msg(tst_s, tst_buf_before, TST_BUF_LEN - 1,
                                  TAPI_TCP_AUTO, 0, TAPI_TCP_AUTO, 0,
                                  NULL, 0);
            }
            else
            {
                rpc_send(pco_tst, tst_s, tst_buf_before,
                         TST_BUF_LEN - 1, 0);
            }

            TAPI_WAIT_NETWORK;
        }

        rc = tsa_do_moves_str(&ss, tsa_state_to(&ss), RPC_TCP_UNKNOWN,
                              (loopback ? TSA_MOVE_IGNORE_ERR : 0),
                              tsa_rem_path(&ss));
    }

    if (rc != 0 || tsa_state_to(&ss) != tsa_state_cur(&ss))
    {
        TEST_STEP("If @b tsa_do_moves_str() returned unexpected error, "
                  "write corresponding verdict and end the test.");

        if (tsa_state_to(&ss) == RPC_TCP_TIME_WAIT &&
            tsa_state_cur(&ss) == RPC_TCP_CLOSE)
            RING_VERDICT("%s is not observable",
                         tcp_state_rpc2str(tsa_state_to(&ss)));
        else if (tsa_state_to(&ss) != tsa_state_cur(&ss))
            TEST_VERDICT("%s was not achieved",
                         tcp_state_rpc2str(tsa_state_to(&ss)));
        else
            TEST_VERDICT("Unexpected error occured");
    }

    tst_s = tsa_tst_sock(&ss);
    iut_s = tsa_iut_sock(&ss);
    state_from = tsa_state_cur(&ss);

    TEST_STEP("Call @b shutdown(@p shutdown_how) in @p tcp_state");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_shutdown(pco_iut, iut_s, shutdown_how);
    if (rc == 0)
        RING_VERDICT("shutdown() successed");
    else
        RING_VERDICT("shutdown() failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    TAPI_WAIT_NETWORK;

    tsa_update_cur_state(&ss);
    state_to = tsa_state_cur(&ss);
    RING_VERDICT("After shutdown() call TCP state is %s",
                 tcp_state_rpc2str(state_to));

    TEST_STEP("If required, send data from TESTER after @b shutdown() "
              "call on IUT socket");
    if (tst_send_after)
    {
        if (tst_type == TSA_TST_GW_CSAP)
        {
            tapi_tcp_wait_msg(tst_s, SLEEP_SEC);
            tapi_tcp_send_msg(tst_s, tst_buf_after, TST_BUF_LEN + 1,
                              TAPI_TCP_AUTO, 0, TAPI_TCP_AUTO, 0,
                              NULL, 0);
        }
        else
            rpc_send(pco_tst, tst_s, tst_buf_after,
                     TST_BUF_LEN + 1, 0);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that data sent from TESTER to IUT and vica versa "
              "according to @p tst_send_before, @p iut_send_before, "
              "@p tst_send_after was received or not received as expected.");

    if (iut_send_before)
    {
        iut_sent_len = (tst_type == TSA_TST_GW_CSAP) ? TST_BUF_LEN :
                                                       iut_sent_len;

        if (tst_type == TSA_TST_GW_CSAP)
        {
            tst_recv_len = TST_BUF_LEN;
            tapi_tcp_recv_msg(tst_s, SLEEP_SEC, TAPI_TCP_AUTO,
                              buf, &tst_recv_len, NULL, NULL, 0);
        }
        else
        {
            rc = 0;
            tst_recv_len = 0;

            do {
                RPC_AWAIT_IUT_ERROR(pco_tst);
                rc = rpc_recv(pco_tst, tst_s, buf,
                              TST_BUF_LEN, RPC_MSG_DONTWAIT);
                if (rc > 0)
                    tst_recv_len += rc;
            } while (rc > 0);

            if (rc < 0 && RPC_ERRNO(pco_tst) != RPC_EAGAIN)
            {
                RING_VERDICT("recv() on Tester failed with errno %s",
                             errno_rpc2str(RPC_ERRNO(pco_tst)));
                is_failed = TRUE;
            }
        }

        if (tst_recv_len == 0)
        {
            RING_VERDICT("Data sent before shutdown() call was not "
                         "received by TESTER");
            is_failed = TRUE;
        }
        else if (tst_recv_len != iut_sent_len)
        {
            RING_VERDICT("%lu bytes received instead of %lu by TESTER",
                         tst_recv_len, (size_t)TST_BUF_LEN);
            is_failed = TRUE;
        }
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, iut_buf, TST_BUF_LEN,
                  RPC_MSG_DONTWAIT);

    if (rc >= 0)
    {
        if (rc != TST_BUF_LEN)
        {
            if (rc > 0)
            {
                RING_VERDICT("send() returned %d > 0 not equal to size of "
                             "data to be sent %d",
                             rc, TST_BUF_LEN);
                is_failed = TRUE;
            }
            else
                RING_VERDICT("send() returned 0");
        }
        else
            RING_VERDICT("send() returned length of data to be sent");
    }
    else
        RING_VERDICT("send() failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    if (rc > 0 && (shutdown_how == RPC_SHUT_WR ||
        shutdown_how == RPC_SHUT_RDWR))
    {
        RING_VERDICT("Data was sent successfully after shutdown(WR) "
                     "on socket");
        is_failed = TRUE;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, buf, TST_BUF_LEN * 2,
                  RPC_MSG_DONTWAIT);

    if (rc < 0)
        RING_VERDICT("recv() failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    else if (rc == 0)
        RING_VERDICT("recv() returned 0");

    /* @p tst_send_before and @p tst_send_after can be TRUE only
     * in iterations testing SHUT_RD (SHUT_RDWR). */

    if (shutdown_how == RPC_SHUT_RD ||
        shutdown_how == RPC_SHUT_RDWR)
    {
        if (rc <= 0 && tst_send_before)
        {
            RING_VERDICT("Data sent before shutdown() call was lost");
            is_failed = TRUE;
        }
        else if (rc > 0 && !tst_send_before)
        {
            if (tst_send_after && rc == TST_BUF_LEN + 1)
                RING_VERDICT("Data sent after shutdown(RD) call was "
                             "received");
            else
                TEST_FAIL("Unexpected data was received");

            is_failed = TRUE;
        } else if (rc > 0 && tst_send_before)
        {
            if (rc != TST_BUF_LEN - 1)
            {
                is_failed = TRUE;
                RING_VERDICT("Data of incorrect length was received");
            }
            else
                RING_VERDICT("Data send before shutdown(RD) call "
                             "was received");
        }
    }

    if (state_from == RPC_TCP_SYN_SENT)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s, tst_addr);

        if (rc < 0)
            RING_VERDICT("Second connect() call after shutdown() failed "
                         "with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        else
            RING_VERDICT("Second connect() call after shutdown() "
                         "sucesseed");
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

    if (tsa_destroy_session(&ss) != 0)
       TEST_FAIL("Closing working session with TSA failed");

    free(buf);
    free(iut_buf);
    free(tst_buf_before);
    free(tst_buf_after);

    TEST_END;
}
