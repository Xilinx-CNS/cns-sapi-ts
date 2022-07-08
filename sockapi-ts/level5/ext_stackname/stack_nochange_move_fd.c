/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-stack_nochange_move_fd Call @b onload_move_fd() that has no effect
 *
 * @objective Check that if we call @b onload_move_fd() on a socket that is
 *            already in a stack to which this function would move it,
 *            it always successes.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on TESTER
 * @param iut_addr             Network address on IUT
 * @param tst_addr             Network address on TESTER
 * @param sock_accepted        Whether a socket on which we test
 *                             funtions is returned by @b socket()
 *                             or @b accept()
 * @param not_def_stack        Whether we test socket from default
 *                             stack or set a new stack name before
 *                             creating it
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/stack_nochange_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME "foo"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    te_bool                 sock_accepted = FALSE;
    te_bool                 not_def_stack = FALSE;
    char                   *init_stack_name;
    te_bool                 restore_stack_name = FALSE;

    int                     iut_s = -1;
    int                     iut_s_listening = -1;
    int                     tst_s = -1;
    int                     tst_s_listening = -1;

    te_bool                 test_failed = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(sock_accepted);
    TEST_GET_BOOL_PARAM(not_def_stack);

    TEST_STEP("If required by @p not_def_stack, set stack name "
              "to @c STACK_NAME.");
    if (not_def_stack)
    {
        init_stack_name = tapi_onload_get_cur_stackname(pco_iut);
        tapi_rpc_onload_set_stackname_create(
                                          pco_iut, ONLOAD_ALL_THREADS,
                                          ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                          FALSE, NULL);
        restore_stack_name = TRUE;
    }

    TEST_STEP("Obtain @p iut_s socket fd ether from @b socket() or from @b "
              "accept(), accoding to @p sock_accepted parameter.");
    if (sock_accepted)
    {
        if (!gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                    pco_tst, tst_addr,
                                    TRUE, TRUE, FALSE, TRUE,
                                    &iut_s_listening, &iut_s,
                                    &tst_s, NULL))
            TEST_VERDICT("Failed to establish TCP connection");
    }
    else
        iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);

    TEST_STEP("Try to move socket to the stack it is already in the first time, "
              "check that it successes.");
    if (!tapi_rpc_onload_move_fd_check(
                                  pco_iut, iut_s,
                                  TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                  not_def_stack ? STACK_NAME : "",
                                  "The first onload_move_fd() call"))
    {
        ERROR_VERDICT("onload_move_fd() failed when moving socket to "
                      "the stack it is already in"); 
        test_failed = TRUE;
    }

    TEST_STEP("Try to move socket to the stack it is already in the second time, "
              "check that it successes.");
    if (!tapi_rpc_onload_move_fd_check(
                                  pco_iut, iut_s,
                                  FALSE, not_def_stack ? STACK_NAME : "",
                                  "The second onload_move_fd() call"))
    {
        ERROR_VERDICT("onload_move_fd() failed when moving socket "
                      "the second time to the stack it is already in");
        test_failed = TRUE;
    }

    TEST_STEP("Check that socket is still usable.");
    if (!sock_accepted)
    {
        if (!gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                    pco_tst, tst_addr,
                                    FALSE, TRUE, FALSE, FALSE,
                                    &iut_s, NULL,
                                    &tst_s_listening, &tst_s))
            TEST_STOP;
    }

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listening);

    TEST_END;
}
