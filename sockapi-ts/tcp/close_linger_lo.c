/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 */

/** @page tcp-close_linger_lo Closing TCP socket with set-on linger option with loopback connection
 *
 * @objective Check that tcp socket will be closed according to
 *            @c SO_LINGER socket option in case of loopback environment.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_lo
 *                      - @ref arg_types_env_peer2peer_lo_ipv6
 * @param tcp_state       TCP state to be tested
 *                        - @c TCP_ESTABLISHED
 *                        - @c TCP_CLOSE_WAIT
 *                        - @c TCP_FIN_WAIT1
 *                        - @c TCP_FIN_WAIT2
 *                        - @c TCP_CLOSING
 *                        - @c TCP_LAST_ACK
 *                        - @c TCP_TIME_WAIT
 * @param sock_type     IUT socket type:
 *                      - @c tcp_active (actively opened TCP socket)
 *                      - @c tcp_passive (passively opened TCP socket)
 * @param way           How to close IUT socket:
 *                      - @b close()
 *                      - @b exit()
 *                      - @b kill()
 *                      - @b dup2()
 * @param zero_linger   Whether we test zero value of @p l_linger or
 *                      non-zero.
 * @param sq_state      State of send queue:
 *                      - @c empty - send queue is empty when @b close()
 *                      is called
 *                      - @c during - send queue becomes empty during
 *                      linger period
 *                      - @c timeout - send queue remains non-empty during
 *                      whole linger period
 * @param single_sock   Whether we test a single socket file descriptor or
 *                      two file descriptors of the same socket
 * @param set_before    Whether to set @c SO_LINGER option before or after
 *                      socket file descriptor duplication (the parameter
 *                      makes sense if only we duplicate file descriptor
 *                      at all)
 * @param use_fork      Whether to use @b fork() or
 *                      @b dup() to duplicate socket
 *                      file descriptor (if we duplicate
 *                      it)
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/close_linger_lo"

#include "sockapi-test.h"
#include <netinet/tcp.h>
#include "linger.h"
#include "sockapi-ts_tcp.h"

/* In case of sq_state is during: the period in seconds for send queue
 * on IUT socket to be full.
 */
#define DURING_SLEEP_TIME 2

/**
 * State of send queue.
 */
typedef enum {
    SQ_EMPTY = 0, /**< Send queue is empty */
    SQ_DURING,    /**< Send queue becomes empty during linger period */
    SQ_TIMEOUT    /**< Send queue remains non-empty during whole linger
                    *  period
                    */
} sq_state_t;

#define SQ_STATE \
    { "empty", SQ_EMPTY },    \
    { "during", SQ_DURING },  \
    { "timeout", SQ_TIMEOUT }

static te_bool is_failed = FALSE;
static te_bool found = FALSE;

static void
close_check_linger(char *str, rcf_rpc_server *pco_iut,
                   rcf_rpc_server *pco_iut_par, rcf_rpc_server *pco_tst,
                   int *iut_s, int tst_s, const struct sockaddr *iut_addr,
                   const struct sockaddr *tst_addr, int linger_time,
                   te_bool should_linger, closing_way way, int sq_state,
                   rpc_tcp_state tcp_state, te_bool shutdown_iut)
{
    unsigned long int      exp_duration = 0;
    unsigned long int      max_duration = 0;
    rpc_sigset_p           tst_sigmask = RPC_NULL;
    unsigned char          buf[4096] = {};
    size_t                 buflen = sizeof(buf);
    int                    rc = 0;
    int                    result = 0;
    rpc_tcp_state          got_tcp_state;
    rpc_tcp_state          exp_state;
    int                    tmp_s = -1;
    te_bool                exp_found = TRUE;

    UNUSED(result);

    /* Perform socket closing according to way */
    pco_iut->timeout = TE_SEC2MS(linger_time) + pco_iut->def_timeout;
    if (way == CL_CLOSE)
    {
        pco_iut->op = RCF_RPC_CALL;
        sockts_close(pco_iut, pco_iut_par, iut_s, way);
    }
    else if (way == CL_DUP2)
    {
        tmp_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);
        pco_iut->op = RCF_RPC_CALL;
        rpc_dup2(pco_iut, tmp_s, *iut_s);
    }
    else
    {
        sockts_close(pco_iut, pco_iut_par, iut_s, way);
    }

    /* Make send queue empty in case of SQ_DURING after DURING_SLEEP_TIME */
    if (sq_state == SQ_DURING && should_linger)
    {
        struct timeval start_time;
        struct timeval end_time;

        SLEEP(DURING_SLEEP_TIME);
        gettimeofday(&start_time, NULL);
        rpc_drain_fd_simple(pco_tst, tst_s, NULL);
        gettimeofday(&end_time, NULL);
        exp_duration = should_linger ?
            TE_SEC2US(DURING_SLEEP_TIME) : 0;
        max_duration = should_linger ?
            TE_SEC2US(DURING_SLEEP_TIME) +
            TIMEVAL_SUB(end_time, start_time) : 0;
    }

    if (way == CL_CLOSE)
    {
        pco_iut->op = RCF_RPC_WAIT;
        sockts_close(pco_iut, pco_iut_par, iut_s, way);
    }
    else if (way == CL_DUP2)
    {
        uint64_t        duration;

        pco_iut->op = RCF_RPC_WAIT;
        rpc_dup2(pco_iut, tmp_s, *iut_s);

        duration = pco_iut->duration;
        RPC_CLOSE(pco_iut, tmp_s);
        RPC_CLOSE(pco_iut, *iut_s);
        pco_iut->duration = duration;
    }

    /* Check closing duration. */
    if (way == CL_EXIT || way == CL_KILL || sq_state == SQ_EMPTY)
        exp_duration = 0;
    else if (sq_state != SQ_DURING)
        exp_duration = should_linger ? TE_SEC2US(linger_time) : 0;
    max_duration = max_duration == 0 ? exp_duration : max_duration;

    CHECK_CALL_DURATION_INT_GEN(pco_iut->duration, TST_TIME_INACCURACY,
                                TST_TIME_INACCURACY_MULTIPLIER,
                                exp_duration, max_duration,
                                ERROR, RING_VERDICT,
                                "%sclose() call on 'iut_s' had "
                                "unexpectedly %s duration", str,
                                pco_iut->duration < exp_duration ?
                                "short" : "long");
    TAPI_WAIT_NETWORK;

    /* Check socket state after performing closing. */
    if (should_linger)
    {
        if (linger_time > 0)
        {
            if (sq_state == SQ_TIMEOUT)
            {
                if (tcp_state == RPC_TCP_ESTABLISHED)
                    exp_state = RPC_TCP_FIN_WAIT1;
                else if (tcp_state == RPC_TCP_CLOSE_WAIT)
                    exp_state = RPC_TCP_LAST_ACK;
                else
                    exp_state = tcp_state;
            }
            else
            {
                if (tcp_state == RPC_TCP_CLOSING ||
                    tcp_state == RPC_TCP_TIME_WAIT)
                    exp_state = RPC_TCP_TIME_WAIT;
                else if (tcp_state == RPC_TCP_ESTABLISHED ||
                         tcp_state == RPC_TCP_FIN_WAIT1 ||
                         tcp_state == RPC_TCP_FIN_WAIT2)
                    exp_state = RPC_TCP_FIN_WAIT2;
                else
                    exp_found = FALSE;
            }
        }
        else
        {
            if (tcp_state == RPC_TCP_TIME_WAIT)
            {
                exp_state = RPC_TCP_TIME_WAIT;
            }
            else
            {
                exp_found = FALSE;
                exp_state = RPC_TCP_UNKNOWN;
            }
        }
    }
    else
    {
        exp_found = TRUE;
        exp_state = tcp_state;
    }

    rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr,
                             &got_tcp_state, &found);
    if (exp_found && !found)
    {
        ERROR_VERDICT("Socket disappeared unexpectedly after closing");
    }
    else if (!exp_found && found)
    {
        ERROR_VERDICT("Socket should disappear after closing, but it is "
                      "instead in %s state",
                      tcp_state_rpc2str(got_tcp_state));
    }
    else if (found && got_tcp_state != exp_state)
    {
        ERROR_VERDICT("Socket is in %s instead of %s after closing",
                      tcp_state_rpc2str(got_tcp_state),
                      tcp_state_rpc2str(exp_state));
    }

    /* Test can't send any packets from Tester after shutdown() on Tester
     * socket. */
    if (tcp_state == RPC_TCP_TIME_WAIT ||
        tcp_state == RPC_TCP_CLOSE_WAIT ||
        tcp_state == RPC_TCP_CLOSING ||
        tcp_state == RPC_TCP_LAST_ACK)
        return;

    if (!should_linger)
        return;

    /* In the rest of this function test sends some amount of packets (1-3)
     * from Tester to IUT until it finally gets EPIPE and SIGPIPE signal.
     */
    if (linger_time != 0)
    {
        /*
         * Non-zero linger_time means that RST was not sent, so that the
         * first send should be successfully completed.
         */
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_send(pco_tst, tst_s, buf, buflen, 0);
        if (rc < 0)
        {
            TEST_VERDICT("%ssend() on Tester should succeed, but it "
                         "failed with %r", str, RPC_ERRNO(pco_tst));
        }
        TAPI_WAIT_NETWORK;
    }

    if ((linger_time == 0 && !shutdown_iut) || sq_state == SQ_TIMEOUT)
    {
        /*
         * If we call send() after receiving RST from peer,
         * it fails with ECONNRESET only if FIN did not arrive
         * from peer yet. Otherwise it fails with EPIPE
         * immediately.
         *
         * SQ_TIMEOUT means that send queue is overfilled and IUT cannot
         * send FIN. Zero linger_time prevents sending FIN, but in case of
         * shutdown() on IUT socket FIN was already sent.
         */
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_send(pco_tst, tst_s, buf, buflen, 0);
        if (rc >= 0)
        {
            TEST_VERDICT("%ssend() on Tester should fail with "
                         "ECONNRESET, but it succeeded", str);
        }
        CHECK_RPC_ERRNO(pco_tst, RPC_ECONNRESET,
                        "%ssend() on Tester failed, but ", str);
        TAPI_WAIT_NETWORK;
    }

    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_send(pco_tst, tst_s, buf, buflen, 0);
    if (rc >= 0)
    {
        TEST_VERDICT("%ssend() on Tester should fail with EPIPE, "
                     "but it succeeded", str);
    }
    CHECK_RPC_ERRNO(pco_tst, RPC_EPIPE,
                    "%ssend() on Tester failed, but ", str);

    /* Check that SIGPIPE is delivered to pco_tst */
    tst_sigmask = rpc_sigreceived(pco_tst);
    rc = rpc_sigismember(pco_tst, tst_sigmask, RPC_SIGPIPE);
    if (rc != TRUE)
    {
        RING_VERDICT("%ssend() on Tester returns -1 and sets "
                     "errno to EPIPE, but the process does not receive "
                     "SIGPIPE signal", str);
        is_failed = TRUE;
    }

    rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr,
                             &got_tcp_state, &found);
    if (found)
    {
        ERROR_VERDICT("%safter trying to send data from peer IUT socket "
                      "still hangs in %s", str,
                      tcp_state_rpc2str(got_tcp_state));
        is_failed = TRUE;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut_par = NULL;
    rcf_rpc_server *pco_dup = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             iut_l = -1;
    int             dup_s = -1;
    int             tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    tarpc_linger           opt_val;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                restore_signal_handler = FALSE;

    te_bool                single_sock = FALSE;
    te_bool                set_before  = FALSE;
    te_bool                zero_linger  = FALSE;
    int                    linger_time;
    te_bool                use_fork    = FALSE;
    closing_way            way;
    sq_state_t             sq_state;
    te_bool                shutdown_iut;
    te_bool                shutdown_tst;
    sockts_socket_type     sock_type;
    rpc_tcp_state          tcp_state;
    rpc_tcp_state          got_tcp_state;
    te_bool                exp_free_addr;
    te_bool                overfilled = FALSE;
    te_bool                tst_first = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(way, CLOSING_WAY);

    TEST_GET_BOOL_PARAM(single_sock);
    TEST_GET_BOOL_PARAM(set_before);
    TEST_GET_BOOL_PARAM(use_fork);
    TEST_GET_BOOL_PARAM(zero_linger);

    TEST_GET_TCP_STATE(tcp_state);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_ENUM_PARAM(sq_state, SQ_STATE);

    ST_LINGER_CREATE_PROCESS;

    TEST_STEP("Create a pair of connected TCP sockets on IUT and "
              "Tester according to @p sock_type (if connection is "
              "opened passively on IUT, listener socket is not closed).");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, &iut_l);

    /* Switch on SO_LINGER socket option */
    opt_val.l_onoff = 1;
    if (sq_state == SQ_DURING)
    {
        /* Test sets here big linger timeout to be sure that send queue
         * becomes empty during linger period.
         */
        linger_time = rand_range(DURING_SLEEP_TIME + 5,
                                 DURING_SLEEP_TIME + 10);
    }
    else
    {
        linger_time = zero_linger ? 0 : rand_range(1, 3);
    }
    opt_val.l_linger = linger_time;
    TEST_STEP("If @p set_before is @c TRUE, enable @c SO_LINGER on "
              "the IUT socket, setting @c l_linger according to "
              "@p zero_linger value.");
    if (set_before)
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);

    TEST_STEP("If @p single_sock is @c FALSE, duplicate IUT socket "
              "descriptor with @b fork() or @b dup() as specified "
              "by @p use_fork.");
    if (!single_sock)
    {
        if (use_fork)
        {
            rcf_rpc_server_fork(pco_iut, "pco_iut_child2", &pco_dup);
            dup_s = iut_s;
        }
        else
        {
            pco_dup = pco_iut;
            dup_s = rpc_dup(pco_iut, iut_s);
        }
    }

    TEST_STEP("If @p set_before is @c FALSE, set @c SO_LINGER option "
              "on IUT socket with @c l_linger accoring to @p zero_linger "
              "value.");
    if (!set_before)
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);

    TEST_STEP("Register handler for @c SIGPIPE signal on Tester.");
    CHECK_RC(tapi_sigaction_simple(pco_tst, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    TEST_STEP("Overfill receive buffer of Tester socket unless "
              "@p sq_state is @c empty.");
    if (sq_state != SQ_EMPTY)
    {
        overfilled = TRUE;
        rpc_overfill_buffers(pco_iut, iut_s, NULL);
    }

    TEST_STEP("According to @p tcp_state call or don't call "
              "shutdown(@c SHUT_WR) on IUT and Tester sockets "
              "in correct order and check that IUT socket state "
              "is appropriate after this.");
    switch (tcp_state)
    {
        case RPC_TCP_ESTABLISHED:
            shutdown_iut = FALSE;
            shutdown_tst = FALSE;
        break;
        case RPC_TCP_CLOSE_WAIT:
            shutdown_iut = FALSE;
            shutdown_tst = TRUE;
        break;
        case RPC_TCP_FIN_WAIT2:
        case RPC_TCP_FIN_WAIT1:
            shutdown_iut = TRUE;
            shutdown_tst = FALSE;
        break;
        case RPC_TCP_LAST_ACK:
            shutdown_iut = TRUE;
            shutdown_tst = TRUE;
            tst_first = TRUE;
        break;
        default: /* TCP_CLOSING and TCP_TIME_WAIT*/
            shutdown_iut = TRUE;
            shutdown_tst = TRUE;
        break;
    }
    sockts_shutdown_check_tcp_state(pco_iut, iut_s, iut_addr, pco_tst,
                                    tst_s, tst_addr, shutdown_iut,
                                    shutdown_tst, tst_first,
                                    &got_tcp_state, overfilled);
    if (tcp_state != got_tcp_state)
    {
        ERROR_VERDICT("Socket is in %s instead of %s after shutdown actions",
                      tcp_state_rpc2str(got_tcp_state),
                      tcp_state_rpc2str(tcp_state));
    }

    if (!single_sock)
    {
        TEST_STEP("If @p single_sock is @c FALSE, close the original "
                  "IUT socket according to @p way. "
                  "If there was no shutdown on Tester socket "
                  "at the previous steps, check also "
                  "that sending data from Tester socket does not fail "
                  "and @c SIGPIPE is not received by Tester process.");

        close_check_linger("[the first socket] ", pco_iut, pco_iut_par,
                           pco_tst, &iut_s, tst_s, iut_addr, tst_addr,
                           linger_time, FALSE, way, sq_state, tcp_state,
                           shutdown_iut);
        if (!shutdown_tst)
        {
            CHECK_RC(sockts_test_send(pco_tst, tst_s, pco_dup, dup_s, NULL,
                                      NULL, RPC_PF_UNSPEC, FALSE,
                                      "The first sending from Tester"));
            TAPI_WAIT_NETWORK;
            CHECK_RC(sockts_test_send(pco_tst, tst_s, pco_dup, dup_s, NULL,
                                      NULL, RPC_PF_UNSPEC, FALSE,
                                      "The second sending from Tester"));
        }
    }

    TEST_STEP("Close (remaining) IUT socket according to @p way, check "
              "that closing function returns according to "
              "@p sq_state parameter. Check that IUT socket is in expected "
              "state. If there was not "
              "shutdown on Tester socket at the previous steps , check "
              "also that attempts to send data from Tester socket fail "
              "and @c SIGPIPE is received by Tester process.");
    if (single_sock)
    {
        close_check_linger("[single socket] ", pco_iut, pco_iut_par,
                           pco_tst, &iut_s, tst_s, iut_addr, tst_addr,
                           linger_time, TRUE, way, sq_state,
                           tcp_state, shutdown_iut);
    }
    else
    {
        close_check_linger("[the second socket] ", pco_dup, pco_iut_par,
                           pco_tst, &dup_s, tst_s, iut_addr, tst_addr,
                           linger_time, TRUE, way, sq_state,
                           tcp_state, shutdown_iut);
    }

    TEST_STEP("Close IUT listener socket (and its duplicate if @p use_fork "
              "is @c TRUE) if it was created before.");
    if (use_fork && iut_l >= 0)
        rpc_close(pco_dup, iut_l);
    ST_LINGER_CLOSE_LISTENER;

    TEST_STEP("Check that @p iut_addr is still in use only if "
              "closed socket still hangs in some TCP state. "
              "Otherwise it should be free (so that "
              "a new TCP socket can be bound to it).");
    exp_free_addr = found ? FALSE : TRUE;

    rc = is_addr_inuse(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, iut_addr);
    if (rc < 0)
    {
        ERROR_VERDICT("Unexpected error when checking whether address is "
                      "in use");
        is_failed = TRUE;
    }
    else
    {
        if (exp_free_addr && rc)
        {
            TEST_VERDICT("IUT address is in use when it should "
                         "be free");
            is_failed = TRUE;
        }
        else if (!exp_free_addr && !rc)
        {
            TEST_VERDICT("IUT address is free when it should be in "
                         "use");
            is_failed = TRUE;
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut, dup_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (restore_signal_handler)
    {
        CLEANUP_RPC_SIGACTION(pco_tst, RPC_SIGPIPE, &old_act,
                              SIGNAL_REGISTRAR);
    }

    if (use_fork)
        rcf_rpc_server_destroy(pco_dup);

    if (pco_iut_par != NULL)
        rcf_rpc_server_destroy(pco_iut);

    TEST_END;
}
