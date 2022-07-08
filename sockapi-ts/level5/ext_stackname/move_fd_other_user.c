/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Level5-specific test for Onload Extension API
 * 
 * $Id$
 */

/** @page ext_stackname-move_fd_other_user Try move socket fd to the stack owned by another user
 *
 * @objective Check that calling @b onload_move_fd() fails when we try
 *            to move socket fd to the stack owned by another user so
 *            that we have no access persmissions to use this stack
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

#define TE_TEST_NAME  "level5/ext_stackname/move_fd_other_user"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif
#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME "foo"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_iut_fork = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    int                     iut_s = -1;
    int                     iut_s_listening = -1;
    int                     iut_s_aux = -1;
    int                     tst_s = -1;

    tarpc_onload_stat       ostat;
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

    TEST_STEP("Fork @b pco_iut (getting @b pco_iut_fork)");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_fork", &pco_iut_fork));

    TEST_STEP("Set non-root UID on @p pco_iut_fork (we assume that @p pco_iut "
              "is run under root UID initially)");
    sockts_server_change_uid(pco_iut_fork);

    TEST_STEP("Set stack name on @p pco_iut to @c STACK_NAME, "
              "with @c ONLOAD_SCOPE_GLOBAL scope.");
    rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL, STACK_NAME);

    restore_stack_name = TRUE;

    TEST_STEP("Create a socket on @p pco_iut to ensure that global-scope stack "
              "named @c STACK_NAME is created and owned by root user.");
    iut_s_aux = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_onload_fd_stat(pco_iut, iut_s_aux, &ostat);
    if (!ostat_stack_name_match_str(&ostat, STACK_NAME))
        TEST_VERDICT("Failed to set stack name on pco_iut properly");

    TEST_STEP("Establish a TCP connection between sockets on IUT and TESTER, "
              "so that @p iut_s is a socket on @p pco_iut_fork returned by "
              "@b accept().");
    if (!gen_tcp_conn_with_sock(pco_iut_fork, iut_addr, pco_tst, tst_addr,
                                TRUE, TRUE, FALSE, TRUE,
                                &iut_s_listening, &iut_s,
                                &tst_s, NULL))
        TEST_VERDICT("Failed to establish TCP connection");

    TEST_STEP("Set stack name on @p pco_iut_fork in the same way as it was "
              "done on @p pco_iut.");
    rpc_onload_set_stackname(pco_iut_fork, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL, STACK_NAME);

    TEST_STEP("Try to move a TCP socket returned by @b accept() in "
              "@p pco_iut_fork to the current stack, check that it fails.");
    if (!tapi_rpc_onload_move_fd_check(pco_iut_fork, iut_s,
                                       TAPI_MOVE_FD_FAILURE_EXPECTED,
                                       STACK_NAME,
                                       "Moving socket in a child process"))
        test_failed = TRUE;

    TEST_STEP("Check that connection can still be used.");
    sockts_test_connection(pco_iut_fork, iut_s,
                           pco_tst, tst_s);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut_fork, iut_s_listening);
    CLEANUP_RPC_CLOSE(pco_iut_fork, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_fork));

    TEST_END;
}
