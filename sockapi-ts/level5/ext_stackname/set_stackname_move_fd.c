/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Level5-specific test for Onload Extension API
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_move_fd Checking that @b onload_move_fd() works after calling @b onload_set_stackname() with various parameters
 *
 * @objective Check that @b onload_move_fd() succeeds after calling
 *  `         calling @b onload_set_stackname() with any parameters
 *            (if access to the stack we are trying to move a socket
 *            is permitted)
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on TESTER
 * @param iut_addr             Network address on IUT
 * @param tst_addr             Network address on TESTER
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME "foo"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     iut_s_listening = -1;
    int                     iut_s_aux = -1;
    int                     tst_s = -1;
    tarpc_onload_stat       ostat;

    te_bool   existing_stack = FALSE;
    te_bool   all_threads = FALSE;
    int       scope;
    te_bool   test_failed = FALSE;
    te_bool   restore_stack_name = FALSE;
    char     *init_stack_name;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(existing_stack);
    TEST_GET_BOOL_PARAM(all_threads);
    TEST_GET_ONLOAD_STACK_SCOPE(scope);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Establish a TCP connection between sockets on IUT and TESTER, "
              "so that @p iut_s is a socket returned by @b accept() on "
              "@p pco_iut.");
    if (!gen_tcp_conn_with_sock(pco_iut, iut_addr, pco_tst, tst_addr,
                                TRUE, TRUE, FALSE, TRUE,
                                &iut_s_listening, &iut_s,
                                &tst_s, NULL))
        TEST_VERDICT("Failed to establish TCP connection");

    TEST_STEP("Call @b onload_set_stackname() with @p who parameter set according "
              "to @p all_threads, @p scope and @c STACK_NAME.");
    rpc_onload_set_stackname(pco_iut,
                             all_threads ? ONLOAD_ALL_THREADS :
                                           ONLOAD_THIS_THREAD,
                             scope,
                             STACK_NAME);

    restore_stack_name = TRUE;

    TEST_STEP("If @p existing_stack, create a socket on @p pco_iut to ensure "
              "that the stack to which we move the socket exists before "
              "the call of @b onload_move_fd().");
    if (existing_stack)
    {
        iut_s_aux = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_onload_fd_stat(pco_iut, iut_s_aux, &ostat);
        if (!ostat_stack_name_match_str(&ostat, STACK_NAME))
            TEST_VERDICT("Failed to set stack name on pco_iut properly");
    }
      
    TEST_STEP("Try to move a TCP socket returned by @b accept(), "
              "check that it successes.");
    if (!tapi_rpc_onload_move_fd_check(pco_iut, iut_s,
                                       TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                       STACK_NAME,
                                       "Moving a socket"))
        test_failed = TRUE;

    TEST_STEP("Check that connection can still be used.");
    sockts_test_connection(pco_iut, iut_s,
                           pco_tst, tst_s);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
