/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-rcvtimeo_accept Usage of SO_RCVTIMEO socket option with accept()
 *
 * @objective Check that @c SO_RCVTIMEO option allows to place timeout on
 *            @b accept() call.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_addr      Network address on IUT
 *
 * @par Test sequence:
 *
 * -# Create listening @p iut_s socket bound to @p iut_addr
 *    address on @p pco_iut and socket @p tst_s on @p pco_tst.
 * -# Get current value of @c SO_RCVTIMEO socket option
 *    on @p iut_s, try to set another value, check that
 *    new value was set.
 * -# Call @b accept() on @p iut_s, wait for termination
 *    due to timeout, check that time passed since
 *    calling @b accept() corresponds to new value of
 *    @c SO_RCVTIMEO socket option.
 * -# Call non-blocking @b accept() on @p iut_s, sleep for
 *    a half of new @c SO_RCVTIMEO socket option value,
 *    call @b connect(@p iut_addr) on @p tst_s, wait for
 *    accept() call will terminate, check that time passed
 *    since calling non-blocking accept() is about half of
 *    new @c SO_RCVTIMEO socket option value.
 * -# Close @p tst_s socket, create new @p tst_s socket.
 *    Call @b connect(@p iut_addr) on it, call @b accept() on
 *    @p iut_s, check that @b accept() call terminated
 *    immediately.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/rcvtimeo_accept"

#include "sockapi-test.h"
#include "rcvtimeo.h"

#define VERDICT_TEXT "Precision is too low"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             iut_s_connected = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    tarpc_timeval          timeout;
    uint64_t               expected;

    struct timeval         ts1, ts2, ts3, ts4;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, TRUE, iut_addr);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    RCVTIMEO_GET_SET_CHECK(pco_iut, iut_s, timeout, RPC_SOCK_STREAM);

    pco_iut->timeout = pco_iut->def_timeout + TE_SEC2MS(timeout.tv_sec) +
                       TE_US2MS(timeout.tv_usec);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_accept(pco_iut, iut_s, NULL, NULL);

    if (rc != -1)
    {
        TEST_FAIL("Tested function called on 'iut_s' socket with "
                  "non zero SO_RCVTIMEO option value returned %d "
                  "insteand of -1 ", rc);
    }
    expected = timeout.tv_sec * 1000000 + timeout.tv_usec;

    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                    "Tested function called on 'iut_s' socket with "
                    "non zero SO_RCVTIMEO option value returned -1, but");

    CHECK_REPORT_TIMEOUT(pco_iut->duration, TST_TIME_INACCURACY,
                         TST_TIME_INACCURACY_MULTIPLIER,
                         expected, expected, ERROR, TEST_VERDICT,
                         VERDICT_TEXT);

    gettimeofday(&ts1, NULL);
    pco_iut->op = RCF_RPC_CALL;
    rpc_accept(pco_iut, iut_s, NULL, NULL);
    gettimeofday(&ts2, NULL);

    SLEEP(timeout.tv_sec / 2);

    gettimeofday(&ts3, NULL);
    rpc_connect(pco_tst, tst_s, iut_addr);
    gettimeofday(&ts4, NULL);

    pco_iut->timeout = pco_iut->def_timeout + TE_SEC2MS(timeout.tv_sec) +
                       TE_US2MS(timeout.tv_usec);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    iut_s_connected = rpc_accept(pco_iut, iut_s, NULL, NULL);

    if (iut_s_connected < 0)
    {
        TEST_FAIL("accept() function called on 'iut_s' socket failed");
    }

    CHECK_REPORT_TIMEOUT(pco_iut->duration, TST_TIME_INACCURACY,
                         TST_TIME_INACCURACY_MULTIPLIER,
                         TIMEVAL_SUB(ts3, ts2), TIMEVAL_SUB(ts4, ts1),
                         ERROR, TEST_VERDICT, VERDICT_TEXT);

    rpc_close(pco_tst, tst_s);
    rpc_close(pco_iut, iut_s_connected);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, iut_addr);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    iut_s_connected = rpc_accept(pco_iut, iut_s, NULL, NULL);

    if (iut_s_connected < 0)
    {
        TEST_FAIL("accept() function called on 'iut_s' socket failed");
    }

    CHECK_REPORT_TIMEOUT(pco_iut->duration, TST_TIME_INACCURACY,
                         TST_TIME_INACCURACY_MULTIPLIER,
                         0, 0, ERROR, TEST_VERDICT, VERDICT_TEXT);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_connected);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

