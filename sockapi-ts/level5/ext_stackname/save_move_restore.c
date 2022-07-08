/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-save_move_restore Using @b onload_move_fd() together with @b onload_stackname_restore()
 *
 * @objective Check the following sequence: @b onload_stackname_save();
 *            @b onload_set_stackname(); @b onload_move_fd();
 *            @b onload_stackname_restore().
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on TESTER
 * @param iut_addr             Network address on @p pco_iut
 * @param tst_addr             Network address on @p pco_tst
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/save_move_restore"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME1 "foo"
#define STACK_NAME2 "bar"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr    *iut_addr = NULL;
    const struct sockaddr    *tst_addr = NULL;
    struct sockaddr_storage   iut_addr2;
    struct sockaddr_storage   tst_addr2;
    int                       iut_s1 = -1;
    int                       iut_s_listening1 = -1;
    int                       tst_s1 = -1;
    int                       iut_s2 = -1;
    int                       iut_s_listening2 = -1;
    int                       tst_s2 = -1;

    te_bool                 test_failed = FALSE;
    te_bool                 restore_stack_name = FALSE;
    char                   *init_stack_name;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Obtain two sockets on @p pco_iut - @p iut_s1 and @p iut_s2, "
              "returned by @b accept().");
    if (!gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                pco_tst, tst_addr,
                                TRUE, TRUE, FALSE, TRUE,
                                &iut_s_listening1, &iut_s1,
                                &tst_s1, NULL))
        TEST_VERDICT("Failed to establish TCP connection 1");

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr,
                                 &iut_addr2));
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                 &tst_addr2));
                                 
    if (!gen_tcp_conn_with_sock(pco_iut, SA(&iut_addr2),
                                pco_tst, SA(&tst_addr2),
                                TRUE, TRUE, FALSE, TRUE,
                                &iut_s_listening2, &iut_s2,
                                &tst_s2, NULL))
        TEST_VERDICT("Failed to establish TCP connection 2");

    TEST_STEP("Call @b onload_set_stackname(@c STACK_NAME1).");
    rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_PROCESS, STACK_NAME1);

    restore_stack_name = TRUE;

    TEST_STEP("Call @b onload_stackname_save().");
    rpc_onload_stackname_save(pco_iut);

    TEST_STEP("Call @b onload_set_stackname(@c STACK_NAME2).");
    rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_PROCESS, STACK_NAME2);

    TEST_STEP("Move @p iut_s1 to @c STACK_NAME2; check that it works.");
    if (!tapi_rpc_onload_move_fd_check(pco_iut, iut_s1,
                                       TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                       STACK_NAME2,
                                       "Calling onload_move_fd() "
                                       "on a TCP socket"))
        test_failed = TRUE;

    TEST_STEP("Call @b onload_stackname_restore().");
    rpc_onload_stackname_restore(pco_iut);

    TEST_STEP("Move @p iut_s2 to @c STACK_NAME1; check that it works.");
    if (!tapi_rpc_onload_move_fd_check(pco_iut, iut_s2,
                                       TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                       STACK_NAME1,
                                       "Calling onload_move_fd() "
                                       "on a TCP socket after "
                                       "onload_stackname_restore()"))
        test_failed = TRUE;

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    TEST_END;
}

