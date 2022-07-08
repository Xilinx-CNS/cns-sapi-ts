/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-shutdown_move_fd Try to call @b onload_move_fd() on a TCP socket after connection shutdown
 *
 * @objective Check that after closing TCP connection a socket can
 *            be moved to a new Onload stack
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param passive_open         Whether TCP connection should be opened
 *                             passively or actively from the IUT side
 * @param shutdown_ends        Whether we should @b shutdown(@c RDWR)
 *                             both ends of connection, IUT end or
 *                             TESTER end before trying to move a
 *                             socked fd to the different Onload stack
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

#define TE_TEST_NAME  "level5/ext_stackname/shutdown_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

enum {
    SHUTDOWN_BOTH,
    SHUTDOWN_IUT,
    SHUTDOWN_TST,
};

#define SHUTDOWN_ENDS \
    {"both", SHUTDOWN_BOTH},  \
    {"iut", SHUTDOWN_IUT},    \
    {"tst", SHUTDOWN_TST}

#define STACK_NAME1 "foo"
#define STACK_NAME2 "bar"
#define MSL_VALUE 1

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
    te_bool                 passive_open = FALSE;
    int                     shutdown_ends = SHUTDOWN_BOTH;
    te_bool                 existing_stack1 = FALSE;
    te_bool                 existing_stack2 = FALSE;
    tarpc_onload_stat       ostat1;
    tarpc_onload_stat       ostat2;
    char                   *init_stack_name;
    te_bool                 test_failed = FALSE;
    te_bool                 restore_stack_name = FALSE;

    te_bool       ef_msl_existed = FALSE;
    int           ef_msl_old_val;
    rpc_shut_how  shutdown_how = RPC_SHUT_RDWR;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(passive_open);
    TEST_GET_ENUM_PARAM(shutdown_ends, SHUTDOWN_ENDS);
    TEST_GET_SHUT_HOW(shutdown_how);
    TEST_GET_BOOL_PARAM(existing_stack1);
    TEST_GET_BOOL_PARAM(existing_stack2);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("If @p shutdown_ends = @c SHUTDOWN_BOTH, set EF_TCP_TCONST_MSL "
              "environment variable to one to reduce time required to move "
              "from TIME_WAIT to CLOSED state.");
    if (shutdown_ends == SHUTDOWN_BOTH)
    {
        CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_TCP_TCONST_MSL",
                                          MSL_VALUE, TRUE, &ef_msl_existed,
                                          &ef_msl_old_val));
    }

    TEST_STEP("Open a TCP connection, taking into account @p passive_open "
              "parameter.");
    if (passive_open)
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &iut_s, &tst_s);
    else
        GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                       tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("@b shutdown() TCP connection accordign to @p shutdown_ends.");
    switch (shutdown_ends)
    {
        case SHUTDOWN_BOTH:
            rpc_shutdown(pco_iut, iut_s, shutdown_how);
            rpc_shutdown(pco_tst, tst_s, shutdown_how);
            break;
        case SHUTDOWN_IUT:
            rpc_shutdown(pco_iut, iut_s, shutdown_how);
            break;
        case SHUTDOWN_TST:
            rpc_shutdown(pco_tst, tst_s, shutdown_how);
            break;
    }

    TEST_STEP("Set stack name to @c STACK_NAME1; create a new socket "
              "to create a stack with this name if @p existing stack1 is set.");
    rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL, STACK_NAME1);
    restore_stack_name = TRUE;
    if (existing_stack1)
    {
        iut_s_aux = rpc_socket(pco_iut, RPC_AF_INET,
                               RPC_SOCK_STREAM, RPC_PROTO_DEF); 
        rpc_onload_fd_stat(pco_iut, iut_s_aux, &ostat1);
        if (!ostat_stack_name_match_str(&ostat1, STACK_NAME1))
            TEST_FAIL("Failed to set a new stack name properly");
    }

    TEST_STEP("If @p shutdown_ends = @c SHUTDOWN_BOTH, try to move IUT socket "
              "to a different stack while it is not in the CLOSED state yet. "
              "Check that it fails; then wait for moving socket to CLOSED state.");
    if (shutdown_ends == SHUTDOWN_BOTH)
    {
        rpc_onload_fd_stat(pco_iut, iut_s, &ostat1);
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_onload_move_fd(pco_iut, iut_s);
        if (rc == 0)
        {
            ERROR_VERDICT("onload_move_fd() successeed when a socket "
                          "is not in CLOSED state yet");
            test_failed = TRUE;
            rpc_onload_fd_stat(pco_iut, iut_s, &ostat2);
            if (ostat_stack_names_match(&ostat1, &ostat2))
                ERROR_VERDICT("Stack name did not change as a result of "
                              "the successful second call of "
                              "onload_move_fd() when socket was not in "
                              "CLOSED state yet");
            else if (!ostat_stack_name_match_str(&ostat2, STACK_NAME2))
                ERROR_VERDICT("Stack name was not changed correctly as "
                              "a result of the successful call of "
                              "onload_move_fd() when socket was not in "
                              "CLOSED state yet");
        }

        MSLEEP(2500);
    }

    TEST_STEP("Try to move the IUT socket to the new stack, check "
              "that it successes in case of @p shutdown_ends = @c SHUTDOWN_BOTH, "
              "and fails in other cases.");
    rpc_onload_fd_stat(pco_iut, iut_s, &ostat1);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_move_fd(pco_iut, iut_s);
    if (rc < 0)
    {
        if (shutdown_ends == SHUTDOWN_BOTH)
        {
            ERROR_VERDICT("Failed to move iut_s to a new Onload stack");
            test_failed = TRUE;
        }

        rpc_onload_fd_stat(pco_iut, iut_s, &ostat2);
        if (!ostat_stack_names_match(&ostat1, &ostat2))
        {
            ERROR_VERDICT("onload_move_fd() failed but stack name changed");
            test_failed = TRUE;
        }
    }
    else
    {
        if (shutdown_ends != SHUTDOWN_BOTH)
        {
            ERROR_VERDICT("onload_move_fd() successed on a socket not in "
                          "CLOSED state");
            test_failed = TRUE;
        }
        rpc_onload_fd_stat(pco_iut, iut_s, &ostat2);
        if (ostat_stack_names_match(&ostat1, &ostat2))
        {
            ERROR_VERDICT("onload_move_fd() successeed but stack "
                          "name remained the same");
            test_failed = TRUE;
        }
        else if (!ostat_stack_name_match_str(&ostat2, STACK_NAME1))
        {
            ERROR_VERDICT("onload_move_fd() successeed but stack "
                          "name has unexpected value");
            test_failed = TRUE;
        }
    }

    TEST_STEP("Change stack name a second time, create a new socket to "
              "create a new stack with this name if @p existing_stack2 is set.");
    rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL, STACK_NAME2);
    if (existing_stack2)
    {
        if (iut_s_aux != -1)
        {
            rpc_close(pco_iut, iut_s_aux);
            iut_s_aux = -1;
        }
        iut_s_aux = rpc_socket(pco_iut, RPC_AF_INET,
                               RPC_SOCK_STREAM, RPC_PROTO_DEF); 
        rpc_onload_fd_stat(pco_iut, iut_s_aux, &ostat1);
        if (!ostat_stack_name_match_str(&ostat1, STACK_NAME2))
            TEST_FAIL("Failed to set a second stack name properly");
    }

    TEST_STEP("Try to move IUT socket to a different stack the second time "
              "and check that it fails.");
    rpc_onload_fd_stat(pco_iut, iut_s, &ostat1);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_move_fd(pco_iut, iut_s);
    if (rc == 0)
    {
        if (shutdown_ends == SHUTDOWN_BOTH)
            RING_VERDICT("The second call of onload_move_fd() successeed");
        else 
        {
            ERROR_VERDICT("The second call of onload_move_fd() successeed "
                          "when a socket is not in CLOSED state");
            test_failed = TRUE;
        }

        rpc_onload_fd_stat(pco_iut, iut_s, &ostat2);
        if (ostat_stack_names_match(&ostat1, &ostat2))
        {
            ERROR_VERDICT("Stack name did not change as a result of "
                          "the successful second call of onload_move_fd()");
            test_failed = TRUE;
        }
        else if (!ostat_stack_name_match_str(&ostat2, STACK_NAME2))
        {
            ERROR_VERDICT("Stack name was not changed correctly as "
                          "a result of the successful second call of "
                          "onload_move_fd()");
            test_failed = TRUE;
        }
    }

    TEST_STEP("Check that we can still close IUT socket properly.");
    switch (shutdown_ends)
    {
        case SHUTDOWN_BOTH:
            break;
        case SHUTDOWN_IUT:
            if (shutdown_how == RPC_SHUT_RD)
                rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
            rpc_shutdown(pco_tst, tst_s, RPC_SHUT_RDWR);
            break;
        case SHUTDOWN_TST:
            rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);
            break;
    }

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:
    if (restore_stack_name)
    {
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);
    }

    if (shutdown_ends == SHUTDOWN_BOTH)
    {
        CLEANUP_CHECK_RC(
            tapi_sh_env_rollback_int(pco_iut, "EF_TCP_TCONST_MSL",
                                     ef_msl_existed, ef_msl_old_val, FALSE));
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
