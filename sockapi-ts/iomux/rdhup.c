/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-rdhup Testing the RDHUP event
 *
 * @objective Check that iomux event @c EVT_RDHUP is handled properly when
 *            @b close() or @b shutdown() is called on IUT or TST socket.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_addr      Network address on IUT
 * @param tst_addr      Network address on TESTER
 * @param who           Who does socket shutdown or close
 * @param shutdown_how  How to shutdown or close socket
 * @param special       Special flags (NONE, SO_LINGER or MSG_MORE)
 * @param iomux         I/O multiplexing function type
 *
 * @par Scenario:
 *
 * - Establish a TCP connection.
 * - Call non-blocking @b iomux(). It should return @c 0.
 * - Call @b setsockopt(SO_LINGER) on TST if @p special == @c SO_LINGER and
 *   @p who == @c TST.
 * - Call @b iomux() with non-zero timeout. It should block.
 * - In case @p who == @c IUT wait until @b iomux() call is finished.
 *   Result should be @c 0.
 * - Call @b send(MSG_MORE) on TST if @p special == @c MSG_MORE and
 *   @p who == @c TST.
 * - On the @p who side call @b close() or @b shutdown() in dependence
 *   on the @p shutdown_how.
 * - In case @p who == @c TST wait until @b iomux() call is finished
 *   and analyze its results:
 *   - if @p shutdown_how == @c SHUT_RD @b iomux() should return @c 0;
 *   - if @p special == @c SO_LINGER @b iomux() should return @c 1 with
 *     event @c EVT_RDHUP | @c EVT_HUP | @c EVT_EXC | @c EVT_ERR;
 *   - in other cases it should return @c 1 with event @c EVT_RDHUP.
 * - Call non-blocking @b iomux().
 *   - if @p who == @c TST result should be the same as in the previous
 *     point;
 *   - if @p who == @c IUT:
 *     - if @p shutdown_how == @c SHUT_NONE - nothing to check;
 *     - if @p shutdown_how == @c SHUT_WR function @b iomux() should
 *       return @c 0;
 *     - if @p shutdown_how == @c SHUT_RD function @b iomux() should
 *       return @c 1 with event @c EVT_RDHUP;
 *     - if @p shutdown_how == @c SHUT_RDWR function @b iomux() should
 *       return @c 1 with event @c EVT_RDHUP | @c EVT_HUP | @c EVT_EXC.
 * - Call @b iomux() with non-zero timeout.
 *   Result should be the same as in the previous point.
 *   If there is an expected event, then @b iomux() should return
 *   immediately.
 *
 * @author Oleg Sadakov <Oleg.Sadakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/rdhup"

#include "sockapi-test.h"

#include "iomux.h"

/** iomux timeout value (more than @b TAPI_WAIT_NETWORK) */
#define TIMEOUT 3

/** Enum for @p who */
typedef enum who_e {
    IUT,
    TST
} who_t;

#define WHO_MAPPING_LIST \
    {"IUT", IUT}, \
    {"TST", TST}

/** Enum for @p special */
typedef enum special_e {
    SPECIAL_NONE,      /**< No special cases */
    SPECIAL_SO_LINGER, /**< Call @b setsockopt() with @c SO_LINGER */
    SPECIAL_MSG_MORE   /**< Call @b send() with @c MSG_MORE */
} special_t;

#define SPECIAL_MAPPING_LIST \
    {"NONE",      SPECIAL_NONE}, \
    {"SO_LINGER", SPECIAL_SO_LINGER}, \
    {"MSG_MORE",  SPECIAL_MSG_MORE}

/**
 * Call @b iomux_call() and check that @b rc and @b event.revents values
 * are expected.
 *
 * @param t @b iomux_call() timeout
 */
#define IOMUX_CALL_AND_CHECK(t)                                        \
do {                                                                   \
    event.revents = 0;                                                 \
    timeout.tv_sec = (t);                                              \
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);              \
    if (rc != expected_rc || event.revents != expected_revents)        \
        TEST_VERDICT("Unexpected event (rc: %d, revents: %s)",         \
            rc, iomux_event_rpc2str(event.revents));                   \
} while (0)

/**
 * Call non-blocking @b iomux_call().
 *
 * @param t @b iomux_call() timeout
 */
#define IOMUX_CALL_DEFERRED(t)                                         \
do {                                                                   \
    event.revents = 0;                                                 \
    timeout.tv_sec = (t);                                              \
    pco_iut->op = RCF_RPC_CALL;                                        \
    iomux_call(iomux, pco_iut, &event, 1, &timeout);                   \
} while (0)

/**
 * Check that the @b iomux_call() is finished.
 *
 * @param immediately @b iomux_call() returns immediately
 */
#define IOMUX_CALL_IMMEDIATELY(immediately)                            \
do {                                                                   \
    te_bool iomux_done;                                                \
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &iomux_done));         \
    if (iomux_done != (immediately))                                   \
    {                                                                  \
        TEST_FAIL((immediately) ?                                      \
            "iomux() should be completed immediately" :                \
            "iomux() should be blocked");                              \
    }                                                                  \
} while (0)

/**
 * Set expected @p rc and @p revents for IUT.
 *
 * @param shutdown_how How to shutdown or close socket
 * @param rc           Variable for expected rc value
 * @param revents      Variable for expected revents value
 */
static void
expected_for_iut(rpc_shut_how shutdown_how, int *rc, uint16_t *revents)
{
    switch (shutdown_how)
    {
        case RPC_SHUT_WR:
            *rc = 0;
            *revents = 0;
            break;

        case RPC_SHUT_RD:
            *rc = 1;
            *revents = EVT_RDHUP;
            break;

        case RPC_SHUT_RDWR:
            *rc = 1;
            *revents = EVT_RDHUP | EVT_HUP | EVT_EXC;
            break;

        default:
            TEST_FAIL("Unexpected shutdown_how argument value "
                      "is requested");
    }
}

/**
 * Set expected @p rc and @p revents for TST.
 *
 * @param shutdown_how How to shutdown or close socket
 * @param special      Special flags (NONE, SO_LINGER or MSG_MORE)
 * @param rc           Variable for expected rc value
 * @param revents      Variable for expected revents value
 */
static void
expected_for_tst(rpc_shut_how shutdown_how, special_t special,
                 int *rc, uint16_t *revents)
{
    switch (shutdown_how)
    {
        case RPC_SHUT_RD:
            *rc = 0;
            *revents = 0;
            break;

        case RPC_SHUT_NONE:
        case RPC_SHUT_WR:
        case RPC_SHUT_RDWR:
            *rc = 1;
            if (special == SPECIAL_SO_LINGER)
                *revents = EVT_RDHUP | EVT_HUP | EVT_EXC | EVT_ERR;
            else
                *revents = EVT_RDHUP;
            break;

        default:
            TEST_FAIL("Unexpected shutdown_how argument value "
                      "is requested");
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    who_t                   who;
    rpc_shut_how            shutdown_how;
    special_t               special;
    iomux_call_type         iomux;

    iomux_evt_fd            event;
    tarpc_timeval           timeout;
    int                     expected_rc;
    uint16_t                expected_revents;

    void                   *tx_buf = NULL;
    size_t                  tx_buf_len;
    tarpc_linger            linger_val;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(who, WHO_MAPPING_LIST);
    TEST_GET_SHUT_HOW(shutdown_how);
    TEST_GET_ENUM_PARAM(special, SPECIAL_MAPPING_LIST);
    TEST_GET_IOMUX_FUNC(iomux);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (special == SPECIAL_SO_LINGER && who == TST)
    {
        linger_val.l_onoff = 1;
        linger_val.l_linger = 0;
        rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER, &linger_val);
    }

    event.fd = iut_s;
    event.events = EVT_RDHUP;
    timeout.tv_usec = 0;

    expected_rc = 0;
    expected_revents = 0;
    IOMUX_CALL_AND_CHECK(0);

    IOMUX_CALL_DEFERRED(TIMEOUT);
    TAPI_WAIT_NETWORK;
    IOMUX_CALL_IMMEDIATELY(FALSE);

    if (who == IUT)
    {
        IOMUX_CALL_AND_CHECK(TIMEOUT);

        if (shutdown_how == RPC_SHUT_NONE)
            TEST_SUCCESS;
        else
            rpc_shutdown(pco_iut, iut_s, shutdown_how);
    }
    else
    {
        if (special == SPECIAL_MSG_MORE)
        {
            tx_buf = sockts_make_buf_stream(&tx_buf_len);
            RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, RPC_MSG_MORE);
        }

        if (shutdown_how == RPC_SHUT_NONE)
            RPC_CLOSE(pco_tst, tst_s);
        else
            rpc_shutdown(pco_tst, tst_s, shutdown_how);
    }
    TAPI_WAIT_NETWORK;

    if (who == IUT)
        expected_for_iut(shutdown_how, &expected_rc, &expected_revents);
    else
    {
        expected_for_tst(shutdown_how, special,
                         &expected_rc, &expected_revents);

        IOMUX_CALL_IMMEDIATELY(expected_rc != 0);
        IOMUX_CALL_AND_CHECK(TIMEOUT);
    }

    IOMUX_CALL_AND_CHECK(0);

    IOMUX_CALL_DEFERRED(TIMEOUT);
    TAPI_WAIT_NETWORK;
    IOMUX_CALL_IMMEDIATELY(expected_rc != 0);
    IOMUX_CALL_AND_CHECK(TIMEOUT);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);

    TEST_END;
}
