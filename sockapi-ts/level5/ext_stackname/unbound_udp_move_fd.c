/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-unbound_udp_move_fd Call @b onload_move_fd() on an unbound UDP socket fd
 *
 * @objective Check that if we call @b onload_move_fd() on an unbound UDP
 *            socket, it successes
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/unbound_udp_move_fd"

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
    int                     iut_s_aux = -1;
    int                     tst_s = -1;
    te_bool                 existing_stack = FALSE;
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
    TEST_GET_BOOL_PARAM(existing_stack);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Create a UDP socket but not @c bind() it.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Try to move the socket to a new stack; check that it successes.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                         existing_stack, &iut_s_aux);

    restore_stack_name = TRUE;

    if (!tapi_rpc_onload_move_fd_check(
                                  pco_iut, iut_s,
                                  TAPI_MOVE_FD_SUCCESS_EXPECTED, STACK_NAME,
                                  "Calling onload_move_fd() on an unbound "
                                  "UDP socket"))
        test_failed = TRUE;

    TEST_STEP("Check that UDP socket is usable.");
    rpc_bind(pco_iut, iut_s, iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_connect(pco_iut, iut_s, tst_addr);
    rpc_connect(pco_tst, tst_s, iut_addr);
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
