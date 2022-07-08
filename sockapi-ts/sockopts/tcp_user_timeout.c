/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-tcp_user_timeout Usage of TCP_USER_TIMEOUT socket option
 *
 * @objective Check that transmit functions returns @c -1 with @c ETIMEDOUT
 *            after specified by @c TCP_USER_TIMEOUT timeout.
 *
 * @type conformance
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_peer2peer_gw
 *                            - @ref arg_types_env_peer2peer_gw_ipv6
 * @param func                @b write()
 * @param tcp_state           TCP state to achieve:
 *                            - @c TCP_SYN_SENT
 *                            - @c TCP_SYN_RECV
 *                            - @c TCP_ESTABLISHED
 *                            - @c TCP_FIN_WAIT1
 *                            - @c TCP_CLOSE_WAIT
 *                            - @c TCP_LAST_ACK
 *                            - @c TCP_CLOSING
 * @param user_timeout        TSP_USER_TIMEOUT:
 *                            - @c smaller than RTO timeout
 *                            - @c greater than RTO timeout
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 *         Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_user_timeout"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"

#define BUF_LEN 512

#define SMALL_RETRIES_NUM 1

/* MEDIUM_RETRIES_NUM corresponds to /proc/sys/net/ipv4/tcp_retries2 parameter
 * that sets the number of retransmits. For some reason Linux sends one
 * excessive retransmit for tcp_retries2 from range [0-3]. For  tcp_retries2 set
 * to 4 and further Linux does not send excessive retransmit and Onload matches
 * this behavior. */
#define MEDIUM_RETRIES_NUM 4

#define MIN_RTO 2500
#define TIMEOUT_DIFF 5000
#define MIN_USER_TIMEOUT 900

#define TEST_IUT_TIMEOUT (60 * 1000)
#define TIMEOUT_INACCURACY 800

#define TST_SET_OPT_WITH_CHECKING(_level, _opt, _optval, _iut_s) \
        do {                                                        \
            int optval = _optval;                                   \
                                                                    \
            RPC_AWAIT_IUT_ERROR(pco_iut);                           \
            ret = rpc_setsockopt(pco_iut, _iut_s, _opt, &optval);   \
            if (ret != 0)                                           \
            {                                                       \
                TEST_VERDICT("setsockopt(%s) failed with errno %s", \
                             sockopt_rpc2str(_opt),                 \
                             errno_rpc2str(RPC_ERRNO(pco_iut)));    \
            }                                                       \
            optval = 0;                                             \
            rpc_getsockopt(pco_iut, _iut_s, _opt, &optval);         \
            if (optval != _optval)                                  \
                TEST_FAIL("It's impossible to set "#_opt" to %d",   \
                          _optval);                                 \
        } while (0)

static void
send_check_result(rcf_rpc_server *pco_iut, int iut_s, rpc_send_f func,
                  uint8_t *tst_buf, te_bool should_succeed)
{
    int rc = 0;

    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, tst_buf, BUF_LEN, 0);
    if (should_succeed)
    {
        if (rc == -1)
        {
            TEST_VERDICT("Send function unexpectedly failed with errno %r",
                         RPC_ERRNO(pco_iut));
        }
    }
    else
    {
        if (rc == -1)
        {
            if (RPC_ERRNO(pco_iut) != RPC_ETIMEDOUT)
                TEST_VERDICT("Send function failed with unexpected errno");
        }
        else
        {
            TEST_VERDICT("Send function unexpectedly succeeds");
        }
    }
}

static void
create_tsa(tsa_session *ss, tsa_tst_type tst_type,
           rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
           rcf_rpc_server *pco_gw,
           const struct if_nameindex  *iut_if,
           const struct if_nameindex *tst_if,
           const struct if_nameindex  *gw_iut_if,
           const struct if_nameindex *gw_tst_if,
           const struct sockaddr *iut_addr,
           const struct sockaddr *tst_addr,
           const struct sockaddr *gw_iut_addr,
           const struct sockaddr *gw_tst_addr,
           const struct sockaddr *alien_link_addr,
           uint32_t flags)
{
    CHECK_RC(tsa_state_init(ss, tst_type));

    CHECK_RC(tsa_iut_set(ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(ss, pco_tst, tst_if, tst_addr, NULL));

    tsa_gw_preconf(ss, TRUE);
    CHECK_RC(tsa_gw_set(ss, pco_gw, gw_iut_addr, gw_tst_addr,
                        gw_iut_if, gw_tst_if,
                        ((struct sockaddr *)alien_link_addr)->sa_data));
    CFG_WAIT_CHANGES;
    CHECK_RC(tsa_create_session(ss, flags));
}

static void
wait_connection_termination(tsa_session *ss,
                            rpc_tcp_state tcp_state, int flags,
                            rcf_rpc_server *pco_iut,
                            const struct sockaddr *iut_addr,
                            const struct sockaddr *tst_addr,
                            int iut_s, rpc_send_f func,
                            uint8_t *tst_buf, te_bool send_allowed,
                            int *result, char *vpref)
{
    int rc;
    int fdflags;
    rpc_tcp_state last_state;

    if (tcp_state == RPC_TCP_SYN_RECV)
    {
        flags |= TSA_MOVE_IGNORE_ERR;
        CHECK_RC(tsa_do_moves_str(ss, RPC_TCP_UNKNOWN, RPC_TCP_UNKNOWN, flags,
                                  "TCP_CLOSE -> TCP_LISTEN -> TCP_SYN_RECV"));
    }
    else
    {
        CHECK_RC(tsa_do_moves_str(ss, RPC_TCP_UNKNOWN, RPC_TCP_UNKNOWN,
                                  flags, tcp_state_rpc2str(tcp_state)));
    }

    CHECK_RC(tsa_break_tst_iut_conn(ss));

    if (send_allowed)
    {
        send_check_result(pco_iut, iut_s, func, tst_buf, TRUE);
    }

    pco_iut->timeout = TEST_IUT_TIMEOUT;
    CHECK_RC(rpc_wait_tcp_socket_termination(pco_iut, iut_addr, tst_addr,
                                             &last_state, NULL, result));
    if (last_state != tcp_state)
    {
        TEST_VERDICT("%s: the last state observed in connection "
                     "was different from expected", vpref);
    }

    if (send_allowed)
    {
        send_check_result(pco_iut, iut_s, func, tst_buf, FALSE);
    }

    if (tcp_state == RPC_TCP_SYN_SENT)
    {
        fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);
        fdflags |= RPC_O_NONBLOCK;
        fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, fdflags);
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s, tst_addr);
        if (rc >= 0)
        {
            TEST_VERDICT("%s: connect unexpectedly succeeds after "
                         "waiting for termination", vpref);
        }
        else
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_ETIMEDOUT,
                            "%s: connect function failed", vpref);
        }
    }
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    int                    iut_s = -1;
    int                    iut_s2 = -1;
    int                    ret;

    /* buffers for test purposes */
    uint8_t                  tst_buf[BUF_LEN];

    rpc_send_f               func;
    const char              *user_timeout;
    int                      time_without_user_timeout = 0;
    int                      time_with_user_timeout = 0;
    int                      time4wait;
    rpc_tcp_state            tcp_state;
    tsa_tst_type             tst_type = TSA_TST_SOCKET;

    te_bool                  user_timeout_expected = FALSE;

    struct sockaddr_storage  iut_addr_aux;
    struct sockaddr_storage  tst_addr_aux;

    tsa_session ss = TSA_SESSION_INITIALIZER;
    tsa_session ss2 = TSA_SESSION_INITIALIZER;
    uint32_t flags = 0;
    te_bool send_allowed = FALSE;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_SEND_FUNC(func);
    TEST_GET_TCP_STATE(tcp_state);
    TEST_GET_STRING_PARAM(user_timeout);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr_aux));
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &tst_addr_aux));

    TEST_STEP("Configure routes between IUT and Tester "
              "via Gateway.");
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    CHECK_RC(tapi_route_gateway_configure(&gateway));
    CFG_WAIT_CHANGES;

    if (tcp_state == RPC_TCP_ESTABLISHED ||
        tcp_state == RPC_TCP_CLOSE_WAIT)
    {
        send_allowed = TRUE;
    }

    if (tcp_state == RPC_TCP_SYN_SENT ||
        tcp_state == RPC_TCP_SYN_RECV)
    {
        if (strcmp(user_timeout, "smaller") == 0 &&
            tcp_state == RPC_TCP_SYN_SENT)
        {
            user_timeout_expected = TRUE;
        }
        else
        {
            user_timeout_expected = FALSE;
        }
    }
    else
    {
        user_timeout_expected = TRUE;
    }

    if (tcp_state == RPC_TCP_SYN_SENT)
    {
        TEST_STEP("If @p tcp_state is @c TCP_SYN_SENT "
                  "reduce /proc/sys/net/ipv4/tcp_syn_retries.");
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, SMALL_RETRIES_NUM, NULL,
                                         "net/ipv4/tcp_syn_retries"));
    }
    else if (tcp_state == RPC_TCP_SYN_RECV)
    {
        TEST_STEP("If @p tcp_state is @c TCP_SYN_RECV "
                  "reduce /proc/sys/net/ipv4/tcp_synack_retries.");
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, SMALL_RETRIES_NUM, NULL,
                                         "net/ipv4/tcp_synack_retries"));
    }
    else
    {
        TEST_STEP("If @p tcp_state is not @c TCP_SYN_SENT or @c TCP_SYN_RECV "
                  "reduce /proc/sys/net/ipv4/tcp_retries2 "
                  "so that achieving retransmission timeout will not take too much time.");
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, MEDIUM_RETRIES_NUM, NULL,
                                         "net/ipv4/tcp_retries2"));
    }

    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    if (user_timeout_expected)
        RING("Connection should be affected by @c TCP_USER_TIMEOUT");
    else
        RING("Connection should not be affected by @c TCP_USER_TIMEOUT");

    if (tcp_state == RPC_TCP_SYN_RECV)
    {
        tst_type = TSA_TST_GW_CSAP;
        flags |= TSA_TST_USE_REUSEADDR | TSA_ESTABLISH_PASSIVE | TSA_MOVE_IGNORE_START_ERR;
    }

    TEST_STEP("Prepare first TSA state instance, create TCP socket on IUT "
              "and peer on Tester");
    create_tsa(&ss, tst_type, pco_iut, pco_tst, pco_gw,
               iut_if, tst_if, gw_iut_if, gw_tst_if,
               iut_addr, tst_addr, gw_iut_addr,
               gw_tst_addr, alien_link_addr, flags);

    iut_s = tsa_iut_sock(&ss);

    TEST_STEP("Move the first connection to @p tcp_state. "
              "If allowed by @p tcp_state, write some data "
              "with @p func to the IUT socket, "
              "breaking connectivity from Tester to IUT before that "
              "so that data is never acknowledged.");
    TEST_STEP("Wait for connection disappearance due to timeout, "
              "measuring time it took. "
              "If @p func was called before, call it again and "
              "check that it fails with ETIMEDOUT. "
              "If SYN_SENT is checked, check that connect() "
              "on IUT now fails with ETIMEDOUT.");
    wait_connection_termination(&ss, tcp_state, flags, pco_iut,
                                iut_addr, tst_addr,
                                iut_s, func, tst_buf, send_allowed,
                                &time_without_user_timeout,
                                "First connection");

    CHECK_RC(tsa_destroy_session(&ss));

    if (time_without_user_timeout < MIN_RTO)
        TEST_FAIL("Too small RTO for this test");

    if (strcmp(user_timeout, "greater") == 0)
        time4wait = time_without_user_timeout + TIMEOUT_DIFF;
    else
        time4wait = MAX(time_without_user_timeout - TIMEOUT_DIFF, MIN_USER_TIMEOUT);

    TEST_STEP("Prepare second TSA state instance, create TCP socket on IUT "
              "and peer on Tester.");
    create_tsa(&ss2, tst_type, pco_iut, pco_tst, pco_gw,
               iut_if, tst_if, gw_iut_if, gw_tst_if,
               SA(&iut_addr_aux), SA(&tst_addr_aux), gw_iut_addr,
               gw_tst_addr, alien_link_addr, flags);

    iut_s2 = tsa_iut_sock(&ss2);

    TEST_STEP("Set @c TCP_USER_TIMEOUT socket option on "
              "IUT socket used in second connection.");
    TST_SET_OPT_WITH_CHECKING(RPC_SOL_TCP, RPC_TCP_USER_TIMEOUT,
                              time4wait, iut_s2);

    TEST_STEP("Perform the same steps as for the first connection.");
    wait_connection_termination(&ss2, tcp_state, flags, pco_iut,
                                SA(&iut_addr_aux), SA(&tst_addr_aux),
                                iut_s2, func, tst_buf, send_allowed,
                                &time_with_user_timeout,
                                "Second connection");

    RING("Termination time without @c USER_TIMEOUT: %d "
         "time with @c USER_TIMEOUT: %d",
         time_without_user_timeout, time_with_user_timeout);

    TEST_STEP("Compare time periods it took to terminate the first and "
              "the second connection. Check whether "
              "the termination period for the second connection was "
              "greater or smaller according to @p user_timeout. "
              "For SYN_SENT expect TCP_USER_TIMEOUT "
              "to take effect only if it is smaller than RTO."
              "For SYN_RECV effect is not expected.");
    if (user_timeout_expected)
    {
        if (abs(time_with_user_timeout - time4wait) > TIMEOUT_INACCURACY)
        {
            TEST_VERDICT("Actual timeout differs too much "
                         "from @c TCP_USER_TIMEOUT value");
        }
    }
    else if (abs(time_with_user_timeout - time_without_user_timeout) > TIMEOUT_INACCURACY)
    {
        TEST_VERDICT("Connection was unexpectedly affected by TCP_USER_TIMEOUT");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tsa_destroy_session(&ss2));

    TEST_END;
}
