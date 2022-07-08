/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-listen_move_fd Try to call @b onload_move_fd() on a listening socket
 *
 * @objective Check that calling @b onload_move_fd() on a listening socket
 *            fails.
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

#define TE_TEST_NAME  "level5/ext_stackname/listen_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

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
    int                     tst_s = -1;
    tarpc_onload_stat       ostat1;
    tarpc_onload_stat       ostat2;
    te_bool                 test_failed = FALSE;
    char                   *init_stack_name;
    te_bool                 restore_stack_name = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Create a listening TCP socket on IUT side.");
    iut_s_listening = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                                 RPC_PROTO_DEF, FALSE,
                                                 FALSE, iut_addr);
    rpc_listen(pco_iut, iut_s_listening, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Set stack name to @c STACK_NAME.");
    rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_PROCESS, STACK_NAME);

    restore_stack_name = TRUE;

    TEST_STEP("Try to move listening socket to a different Onload stack and "
              "check that it fails.");
    rpc_onload_fd_stat(pco_iut, iut_s_listening, &ostat1);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_move_fd(pco_iut, iut_s_listening);
    if (rc < 0)
    {
        rpc_onload_fd_stat(pco_iut, iut_s_listening, &ostat2);
        if (!ostat_stack_names_match(&ostat1, &ostat2))
        {
            ERROR_VERDICT("onload_move_fd() failed but stack name changed");
            test_failed = TRUE;
        }
    }
    else
    {
        ERROR_VERDICT("Moving listening socket to a different Onload stack "
                      "successeed");
        test_failed = TRUE;

        rpc_onload_fd_stat(pco_iut, iut_s_listening, &ostat2);
        if (ostat_stack_names_match(&ostat1, &ostat2))
        {
            ERROR_VERDICT("onload_move_fd() successeed but stack "
                          "name remained the same");
            test_failed = TRUE;
        }
        else if (!ostat_stack_name_match_str(&ostat2, STACK_NAME))
        {
            ERROR_VERDICT("onload_move_fd() successeed but stack "
                          "name has unexpected value");
            test_failed = TRUE;
        }
    }

    TEST_STEP("Check that listening socket can still be used to establish "
              "TCP connection.");
    tst_s = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE,
                                       FALSE, tst_addr);
    rpc_connect(pco_tst, tst_s, iut_addr);
    iut_s = rpc_accept(pco_iut, iut_s_listening, NULL, NULL);

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
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
