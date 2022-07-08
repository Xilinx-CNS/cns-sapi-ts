/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-bind_move_fd Call @b onload_move_fd() on a socket after @b bind()
 *
 * @objective Check that calling @b onload_move_fd() does not change
 *            an address the socket is bound to.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param iut_addr             Network address on IUT
 * @param existing_stack1      Whether Onload stack should already exist
 *                             or not when we try to move a socket fd to it
 *                             firstly
 * @param existing_stack2      Whether Onload stack should already exist
 *                             or not when we try to move a socket fd to it
 *                             secondly

 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/bind_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME1 "foo"
#define STACK_NAME2 "bar"

/* Check whether the address to which a socket was bound
 * remained the same or not */
static inline te_bool
check_bound_address(rcf_rpc_server *rpcs,
                    int s,
                    const struct sockaddr *exp_addr,
                    socklen_t exp_addr_len,
                    const char *error_message)
{
    struct sockaddr_storage   addr;
    socklen_t                 addr_len;

    addr_len = sizeof(addr);
    rpc_getsockname(rpcs, s, (struct sockaddr *)&addr,
                    &addr_len);
    if (addr_len != exp_addr_len ||
        memcmp(&addr, exp_addr, addr_len) != 0)
    {
        ERROR_VERDICT(error_message);
        return FALSE;
    }

    return TRUE;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *tst_addr = NULL;
    te_bool                 existing_stack1 = FALSE;
    te_bool                 existing_stack2 = FALSE;
    te_bool                 restore_stack_name = FALSE;
    char                   *init_stack_name;

    int                     iut_s = -1;
    int                     iut_s_aux = -1;
    int                     tst_s = -1;
    int                     iut_s_accepted = -1;
    te_bool                 test_failed = FALSE;
    te_bool                 bool_rc;

    struct sockaddr_storage   bound_addr;
    socklen_t                 bound_addr_len = 0;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(existing_stack1);
    TEST_GET_BOOL_PARAM(existing_stack2);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Create and bind TCP socket.");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE,
                                       FALSE, iut_addr);

    bound_addr_len = sizeof(bound_addr);
    rpc_getsockname(pco_iut, iut_s, (struct sockaddr *)&bound_addr,
                    &bound_addr_len);

    TEST_STEP("Move the socket to a different Onload stack and "
              "check that it successes.");

    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME1,
                                         existing_stack1, &iut_s_aux);
    restore_stack_name = TRUE;
    bool_rc = tapi_rpc_onload_move_fd_check(
                                    pco_iut, iut_s,
                                    TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                    STACK_NAME1,
                                    "The first call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that the address the socket is bound to was not changed.");
    bool_rc = check_bound_address(
                          pco_iut, iut_s, (struct sockaddr *)&bound_addr,
                          bound_addr_len,
                          "Address the socket is bound to was changed "
                          "as a result of onload_move_fd() call");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Try to move a socket the second time to a different stack.");

    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME2,
                                         existing_stack2, &iut_s_aux);
    bool_rc = tapi_rpc_onload_move_fd_check(
                                    pco_iut, iut_s,
                                    TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                    STACK_NAME2,
                                    "The second call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that the address the socket is bound to was not changed.");
    bool_rc = check_bound_address(
                            pco_iut, iut_s, (struct sockaddr *)&bound_addr,
                            bound_addr_len,
                            "Address the socket is bound to was changed "
                            "as a result of the second onload_move_fd() "
                            "call");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that the socket is still usable.");
    bool_rc = 
           gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                  pco_tst, tst_addr,
                                  FALSE, FALSE, FALSE, TRUE,
                                  &iut_s, &iut_s_accepted,
                                  &tst_s, NULL);
    if (!bool_rc)
        TEST_STOP;

    sockts_test_connection(pco_iut, iut_s_accepted, pco_tst, tst_s);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_accepted);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
