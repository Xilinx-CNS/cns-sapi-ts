/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-sock_ping_pong Moving a socket to a different stack several times
 *
 * @objective Check that moving socket to different stack several times
 *            works only on @c SOCK_STREAM socket returned by @b socket().
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param sock_accepted        Whether we test a socket returned by
 *                             @b accept() or by @b socket()
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/sock_ping_pong"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME1 "foo"
#define STACK_NAME2 "bar"
#define STACK_NAME3 "baz"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     iut_s_listening = -1;
    int                     tst_s_listening = -1;

    te_bool                 sock_accepted = FALSE;
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
    TEST_GET_BOOL_PARAM(sock_accepted);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Obtain TCP socket returned ether by @b socket() or by @b accept(), "
              "according to @p sock_accepted parameter.");
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

    TEST_STEP("Try to move @p iut_s to a different stack; "
              "check that it successes.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME1,
                                         FALSE, NULL);

    restore_stack_name = TRUE;

    if (!tapi_rpc_onload_move_fd_check(pco_iut, iut_s,
                                       TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                       STACK_NAME1,
                                       "Calling onload_move_fd() "
                                       "the first time"))
        test_failed = TRUE;

    TEST_STEP("Try to move @p iut_s to a different stack the second time; "
              "check that it successes only in case when socket was returned from "
              "@b socket().");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME2,
                                         FALSE, NULL);

    if (!tapi_rpc_onload_move_fd_check(
                          pco_iut, iut_s,
                          sock_accepted ? TAPI_MOVE_FD_FAILURE_EXPECTED :
                                          TAPI_MOVE_FD_SUCCESS_EXPECTED,
                          STACK_NAME2,
                          "Calling onload_move_fd() "
                          "the second time"))
        test_failed = TRUE;


    TEST_STEP("Try to move @p iut_s to a different stack the third time; "
              "check that it successes only in case when socket was returned from "
              "@b socket().");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME3,
                                         FALSE, NULL);

    if (!tapi_rpc_onload_move_fd_check(
                          pco_iut, iut_s,
                          sock_accepted ? TAPI_MOVE_FD_FAILURE_EXPECTED :
                                          TAPI_MOVE_FD_SUCCESS_EXPECTED,
                          STACK_NAME3,
                          "Calling onload_move_fd() "
                          "the third time"))
        test_failed = TRUE;

    TEST_STEP("Check that socket is still usable.");
    if (!sock_accepted)
    {
        if (!gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                    pco_tst, tst_addr,
                                    FALSE, TRUE,
                                    FALSE, FALSE,
                                    &iut_s, NULL,
                                    &tst_s_listening, &tst_s))
            TEST_VERDICT("Failed to establish TCP connection with a socket "
                         "moved to a different stack previously");
    }

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

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
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listening);

    TEST_END;
}
