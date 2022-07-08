/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-multiple_listen Multiple listen() calls
 *
 * @objective Check that listen() can be called multiple times on the same
 *            socket and it allows to change its backlog.
 *
 * @type use case
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on TESTER
 * @param iut_addr              Network address on IUT
 * @param tst_addr              Network address on TESTER
 * @param first_backlog         Backlog used for the first @b listen() call
 * @param second_backlog        Backlog used for the second @b listen()
 *                              call
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/multiple_listen"

#include "sockapi-test.h"
#include "tapi_sockets.h"
#include "tapi_mem.h"

/**
 * Maximum acceptable relative difference between
 * expected and measured backlogs.
 */
#define MAX_BACKLOG_DIFF             0.3
#define MAX_BACKLOG_DIFF_SIGNIFICANT 2.5

/** Will be set to TRUE to signal that the test failed. */
static te_bool test_failed = FALSE;

/**
 * Measure listen backlog and check that it matches expectation.
 *
 * @param pco_iut         RPC server on IUT.
 * @param iut_listener    Listener socket on IUT.
 * @param iut_addr        Network address on IUT.
 * @param pco_tst         RPC server on Tester.
 * @param tst_addr        Network address on Tester.
 * @param exp_backlog     Expected backlog.
 * @param log_msg         Message to print at the beginning of
 *                        log messages and verdicts.
 */
static void
check_listen_backlog(rcf_rpc_server *pco_iut, int iut_listener,
                     const struct sockaddr *iut_addr,
                     rcf_rpc_server *pco_tst,
                     const struct sockaddr *tst_addr,
                     int exp_backlog,
                     const char *log_msg)
{
    int     backlog = 0;

    backlog = sockts_tcp_measure_listen_backlog(pco_iut, iut_addr,
                                                iut_listener,
                                                pco_tst, tst_addr,
                                                exp_backlog, log_msg);

    RING("%s: expected backlog is %d, measured backlog is %d",
         log_msg, exp_backlog, backlog);

    if (backlog < exp_backlog)
    {
        ERROR_VERDICT("%s: measured backlog is less than expected",
                      log_msg, exp_backlog, backlog);
        test_failed = TRUE;
    }
    else if (((double)(backlog - exp_backlog)) / (double)exp_backlog >
                                            MAX_BACKLOG_DIFF_SIGNIFICANT)
    {
        ERROR_VERDICT("%s: measured backlog is significantly "
                      "more than expected", log_msg);
        test_failed = TRUE;
    }
    else if (((double)(backlog - exp_backlog)) / (double)exp_backlog >
                                                        MAX_BACKLOG_DIFF)
    {
        ERROR_VERDICT("%s: measured backlog is more than expected", log_msg);
        test_failed = TRUE;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *tst_addr = NULL;

    int                      first_backlog = 0;
    int                      second_backlog = 0;
    int                      iut_s_listener = -1;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(first_backlog);
    TEST_GET_INT_PARAM(second_backlog);

    TEST_STEP("Create TCP socket on IUT. Call listen() for it with backlog "
              "equal to @p first_backlog.");
    iut_s_listener =
        rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                   RPC_PROTO_DEF, FALSE, FALSE, iut_addr);
    rpc_listen(pco_iut, iut_s_listener, first_backlog);

    TEST_STEP("Check that if we initiate significantly more connections from "
              "the peer than @p first_backlog, only about @p first_backlog "
              "connections can be immediately returned by accept(). All connections "
              "will be closed before accept() to prevent establishing new "
              "connections after we start to call accept().");
    check_listen_backlog(pco_iut, iut_s_listener, iut_addr,
                         pco_tst, tst_addr, first_backlog,
                         "Measuring the first backlog");

    TEST_STEP("Call listen() the second time for the same socket, this time "
              "passing @p second_backlog to it.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_listen(pco_iut, iut_s_listener, second_backlog);
    if (rc < 0)
        TEST_VERDICT("The second listen() call failed with errno %r",
                     RPC_ERRNO(pco_iut));

    TEST_STEP("Check that if we initiate significantly more connections from "
              "the peer than @p second_backlog, only about @p second_backlog "
              "connections can be immediately returned by accept(). All connections "
              "will be closed before accept() to prevent establishing new "
              "connections after we start to call accept().");
    check_listen_backlog(pco_iut, iut_s_listener, iut_addr,
                         pco_tst, tst_addr, second_backlog,
                         "Measuring the second backlog");

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listener);

    TEST_END;
}
