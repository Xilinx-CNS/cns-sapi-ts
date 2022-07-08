/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-tcp_overfill_queue_move_fd Try to call @b onload_move_fd() on a TCP socket with ovefilled send or receive queue
 *
 * @objective Check that after establishing a TCP connection a socket
 *            fd can be moved to a different stack when its send or
 *            receive queue is overfilled.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param overfill_send_queue  Whether send or receive queue should be
 *                             overfilled
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/tcp_overfill_queue_move_fd"

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
    te_bool                 overfill_send_queue = FALSE;
    tarpc_onload_stat       ostat1;
    tarpc_onload_stat       ostat2;
    char                   *init_stack_name;
    te_bool                 test_failed = FALSE;
    te_bool                 restore_stack_name = FALSE;
    uint64_t                sent;
    uint64_t                received;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(overfill_send_queue);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Establish TCP connection between @p iut_s and @p tst_s "
              "(passively for IUT socket).");
    iut_s_listening = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                                 RPC_PROTO_DEF, FALSE,
                                                 FALSE, iut_addr);
    rpc_listen(pco_iut, iut_s_listening, SOCKTS_BACKLOG_DEF);
    tst_s = rpc_socket(pco_tst,
                       rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_connect(pco_tst, tst_s, iut_addr);
    iut_s = rpc_accept(pco_iut, iut_s_listening, NULL, NULL);

    TEST_STEP("Overfill send or receive buffers for @p iut_s, "
              "according to @p overfill_send_queue parameter.");
    if (overfill_send_queue)
        rpc_overfill_buffers(pco_iut, iut_s, &sent);
    else
        rpc_overfill_buffers(pco_tst, tst_s, &sent);

    TEST_STEP("Set stack name to @c STACK_NAME.");
    rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL, STACK_NAME);

    restore_stack_name = TRUE;

    TEST_STEP("Try to move the IUT socket to the new stack.");
    rpc_onload_fd_stat(pco_iut, iut_s, &ostat1);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_move_fd(pco_iut, iut_s);
    if (rc < 0)
    {
        ERROR_VERDICT("Failed to move IUT socket "
                      "to a new Onload stack");
        test_failed = TRUE;

        rpc_onload_fd_stat(pco_iut, iut_s, &ostat2);
        if (!ostat_stack_names_match(&ostat1, &ostat2))
            ERROR_VERDICT("onload_move_fd() failed but stack name changed");
    }
    else
    {
        rpc_onload_fd_stat(pco_iut, iut_s, &ostat2);
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

    TEST_STEP("Check that all the data sent can still be received.");
    if (overfill_send_queue)
        rpc_simple_receiver(pco_tst, tst_s, 0, &received);
    else
        rpc_simple_receiver(pco_iut, iut_s, 0, &received);
    if (received != sent)
        TEST_VERDICT("Some data was lost");

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
