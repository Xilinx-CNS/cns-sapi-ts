/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-sighandler_move_fd Calling @b onload_move_fd() from a sigal handler
 *
 * @objective Check that calling @b onload_move_fd() from a signal handler
 *            works correctly or at least does not cause a kernel crash.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param sock_accepted        Whether we test a socket returned by
 *                             @b accept() or by @b socket()
 * @param receive_data         Receive some data while calling @b kill()
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/sighandler_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME "foo"

#define TIME2RUN_SENDER 3

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut_child = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     iut_s_listening = -1;
    int                     tst_s_listening = -1;

    pid_t                   pco_iut_pid;
    int                     iut_int_size;
    uint64_t                iut_int_val;
    int                     move_fd_rc;
    tarpc_onload_stat       ostat1;
    tarpc_onload_stat       ostat2;
    uint64_t                received;
    uint64_t                sent;
    char                   *init_stack_name;
    te_bool                 restore_stack_name = FALSE;

    te_bool                 sock_accepted = FALSE;
    te_bool                 receive_data = FALSE;
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
    TEST_GET_BOOL_PARAM(receive_data);

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

    TEST_STEP("Create a child process @p pco_iut_child to be used for "
              "calling @b kill(). Set signal handler for @c SIGUSR1 that "
              "calls @b onload_move_fd().");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_child",
                                 &pco_iut_child));
    rpc_signal(pco_iut, RPC_SIGUSR1, "sighandler_onload_move_fd");

    iut_int_size = rpc_get_sizeof(pco_iut, "int");
    iut_int_val = iut_s;
    rpc_set_var(pco_iut, "onload_move_fd_fd", iut_int_size,
                iut_int_val);

    TEST_STEP("Set a new stack name.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                         FALSE, NULL);

    restore_stack_name = TRUE;

    rpc_onload_fd_stat(pco_iut, iut_s, &ostat1);
    pco_iut_pid = rpc_getpid(pco_iut);

    TEST_STEP("If required by @p receive_data, start sending data from @p tst_s "
              "and receiving it from @p iut_s.");
    if (receive_data)
    {
        sent = 0;
        received = 0;
        pco_tst->op = RCF_RPC_CALL;
        rpc_iomux_flooder(pco_tst, &tst_s, 1, NULL, 0, 1000,
                          TIME2RUN_SENDER, 1, FUNC_POLL, &sent, NULL);
        pco_iut->op = RCF_RPC_CALL;
        rpc_iomux_flooder(pco_iut, NULL, 0, &iut_s, 1, 1000,
                          TIME2RUN_SENDER, 1, FUNC_POLL, NULL, &received);
    }

    TEST_STEP("Send @c SIGUSR1 signal.");
    rpc_kill(pco_iut_child, pco_iut_pid, RPC_SIGUSR1);
    MSLEEP(500);

    TEST_STEP("Stop data transmitting, if it was initiated previously.");
    if (receive_data)
    {
        SLEEP(TIME2RUN_SENDER + 1);
        if (!rcf_rpc_server_is_alive(pco_iut))
        {
            ERROR_VERDICT("pco_iut is dead as a result of kill(SIGUSR1) "
                         "called when it received some data");
            test_failed = TRUE;
        }

        pco_tst->op = RCF_RPC_WAIT;
        rpc_iomux_flooder(pco_tst, &tst_s, 1, NULL, 0, 1000,
                          TIME2RUN_SENDER, 1, FUNC_POLL, &sent, NULL);
        if (test_failed)
            TEST_STOP;
        pco_iut->op = RCF_RPC_WAIT;
        rpc_iomux_flooder(pco_iut, NULL, 0, &iut_s, 1, 1000,
                          TIME2RUN_SENDER, 1, FUNC_POLL, NULL, &received);
        if (sent != received)
        {
            ERROR_VERDICT("sent does not match received");
            test_failed = TRUE;
        }
    }
    
    TEST_STEP("Check that @b onload_move_fd() called from a signal "
              "handler terminated successfully.");

    iut_int_val = rpc_get_var(pco_iut, "onload_move_fd_rc",
                              iut_int_size);
    if (iut_int_size == 4)
        move_fd_rc = (int32_t)iut_int_val;
    else if (iut_int_size == 8)
        move_fd_rc = (int64_t)iut_int_val;
    else
        TEST_FAIL("Strange int size %d", iut_int_size);

    rpc_onload_fd_stat(pco_iut, iut_s, &ostat2);
    if (move_fd_rc >= 0)
    {
        RING_VERDICT("onload_move_fd() succeeded when called from "
                     "a signal handler");

        if (ostat_stack_names_match(&ostat1, &ostat2))
        {
            ERROR_VERDICT("onload_move_fd succeeded but stack name "
                          "remained the same");
            test_failed = TRUE;
        }
        else if (!ostat_stack_name_match_str(&ostat2, STACK_NAME))
        {
            ERROR_VERDICT("onload_move_fd succeeded but stack name "
                          "is set to unexpected value");
            test_failed = TRUE;
        }
    }
    else
    {
        ERROR_VERDICT("onload_move_fd() failed when called "
                      "from a signal handler"); 
        test_failed = TRUE;

        if (!ostat_stack_names_match(&ostat1, &ostat2))
            ERROR_VERDICT("onload_move_fd() failed "
                          "but stack name changed");
    }

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

    if (rcf_rpc_server_is_alive(pco_iut))
    {
        if (restore_stack_name)
            rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                     ONLOAD_SCOPE_GLOBAL, init_stack_name);

        CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    }
    else
        rcf_rpc_server_restart(pco_iut);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listening);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_child));

    TEST_END;
}
