/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-rcvtimeo Usage of SO_RCVTIMEO socket option
 *
 * @objective Check that @c SO_RCVTIMEO option allows to place timeout on
 *            socket receive operations.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type     Socket type used in the test:
 *                      - @c SOCK_STREAM
 *                      - @c SOCK_DGRAM
 * @param func          Function used in the test:
 *                      - @ref arg_types_recv_func_with_sys
 * @param is_blocking   Whether we should test socket without or with
 *                      @c O_NONBLOCK flag set on it
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/rcvtimeo"

#include "sockapi-test.h"
#include "rcvtimeo.h"

/* Size of 'tx_buf' and 'rx_buf' buffers */
#define N 20

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    rpc_socket_type        sock_type;
    rpc_recv_f             func;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    tarpc_timeval          timeout;
    unsigned char          tx_buf[N];
    unsigned char          rx_buf[N * 2];
    uint64_t               expected;

    te_bool                is_blocking = FALSE;

    struct timeval         ts1, ts2, ts3, ts4;

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_RECV_FUNC(func);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_BOOL_PARAM(is_blocking);

    TEST_STEP("Create a connection of type @p sock_type between @p pco_iut "
              "and @p pco_tst.");
    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    TEST_STEP("Get current value of SO_RCVTIMEO socket option "
              "on @p iut_s socket, try to set another value, check that "
              "new value was set.");
    RCVTIMEO_GET_SET_CHECK(pco_iut, iut_s, timeout, sock_type);

    TEST_STEP("Set @c O_NONBLOCK flag on @p iut_s if @p is_blocking is @c FALSE.");
    if (!is_blocking)
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    pco_iut->timeout = pco_iut->def_timeout + TE_SEC2MS(timeout.tv_sec) +
                       TE_US2MS(timeout.tv_usec);

    TEST_STEP("Call @p func function on @p iut_s socket to get @p N bytes of data.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);

    TEST_STEP("Check that it returns @c -1 and sets @b errno to @c EAGAIN.");
    if (rc >= 0)
    {
        TEST_VERDICT("The first call of the tested function succeeded "
                     "instead of failing with EAGAIN");
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                    "Tested function called on 'iut_s' socket with "
                    "non zero SO_RCVTIMEO option value returned -1, but");

    TEST_STEP("Check that its duration is @p timeout if @c O_NONBLOCK was not set "
              "or @c 0 otherwise.");
    if (is_blocking)
        expected = timeout.tv_sec * 1000000 + timeout.tv_usec;
    else
        expected = 0;

    /* For Linux 4.8 and newer there is low accuracy in this special test,
     * so we use here @c TST_TIME_INACCURACY * 2 instead of fixing
     * @c TST_TIME_INACCURACY itself.
     */
    CHECK_REPORT_TIMEOUT(pco_iut->duration,
                         TST_TIME_INACCURACY * 2,
                         TST_TIME_INACCURACY_MULTIPLIER,
                         expected, expected, ERROR, TEST_VERDICT,
                         "Unexpected duration of the first tested "
                         "function call");
    TEST_STEP("End the test if @c O_NONBLOCK was set on socket.");
    if (!is_blocking)
        TEST_SUCCESS;

    TEST_STEP("Call @p func function on @p iut_s.");
    gettimeofday(&ts1, NULL);
    pco_iut->op = RCF_RPC_CALL;
    func(pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);
    gettimeofday(&ts2, NULL);

    TEST_STEP("Wait for a half of @p timeout interval.");
    MSLEEP((TE_SEC2MS(timeout.tv_sec) + TE_US2MS(timeout.tv_usec)) / 2);

    TEST_STEP("@b send() @p N bytes of @p tx_buf buffer from @p tst_s socket.");
    gettimeofday(&ts3, NULL);
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, sizeof(tx_buf), 0);
    gettimeofday(&ts4, NULL);

    TEST_STEP("Check that @p func function returns @p N and that its duration "
              "roughly is about a half of @p timeout.");
    pco_iut->timeout = pco_iut->def_timeout + TE_SEC2MS(timeout.tv_sec) +
                       TE_US2MS(timeout.tv_usec);
    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);

    if (rc < 0)
    {
        TEST_VERDICT("The second call of the tested function failed "
                     "with " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc != sizeof(tx_buf))
    {
        VERB("Tested function returned %d instead of %d", rc,
             sizeof(tx_buf));
        TEST_VERDICT("The second call of the tested function returned "
                     "unexpected value");
    }

    TEST_STEP("Check that @p tx_buf and @p rx_buf have the same content.");
    if (memcmp(tx_buf, rx_buf, sizeof(tx_buf)) != 0)
    {
        TEST_VERDICT("The second call of the tested function returned "
                     "unexpected data");
    }

    CHECK_REPORT_TIMEOUT(pco_iut->duration, TST_TIME_INACCURACY,
                         TST_TIME_INACCURACY_MULTIPLIER,
                         TIMEVAL_SUB(ts3, ts2), TIMEVAL_SUB(ts4, ts1),
                         ERROR, TEST_VERDICT,
                         "Unexpected duration of the second tested "
                         "function call");

    TEST_STEP("@b send() @p N bytes of @p tx_buf buffer from @p tst_s socket.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, sizeof(tx_buf), 0);

    TEST_STEP("Call @p func function on @p iut_s.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);

    /* Check that the function immediately returns @p N. */
    if (rc < 0)
    {
        TEST_VERDICT("The third call of the tested function failed "
                     "with " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc != sizeof(tx_buf))
    {
        VERB("Tested function called on 'iut_s' socket when there is "
             "%d bytes of data in its receive buffer returned %d "
             "instead of %d", sizeof(tx_buf), rc, sizeof(tx_buf));
        TEST_VERDICT("The third call of the tested function returned "
                     "unexpected value");
    }

    TEST_STEP("Check that data were not currupted.");
    if (memcmp(tx_buf, rx_buf, sizeof(tx_buf)) != 0)
    {
        TEST_VERDICT("The third call of the tested function returned "
                     "unexpected data");
    }

    CHECK_REPORT_TIMEOUT(pco_iut->duration, TST_TIME_INACCURACY,
                         TST_TIME_INACCURACY_MULTIPLIER,
                         0, 0, ERROR, TEST_VERDICT,
                         "Unexpected duration of the third tested "
                         "function call");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

