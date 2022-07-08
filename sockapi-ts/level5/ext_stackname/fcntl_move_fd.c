/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-fcntl_move_fd Call @b onload_move_fd() on a socket after @b fcntl()
 *
 * @objective Check that calling @b onload_move_fd() does not change
 *            a flag or option set by @b fcntl() before the call.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on TESTER
 * @param iut_addr             Network address on IUT
 * @param tst_addr             Network address on TESTER
 * @param sock_accepted        Whether a socket on which we test
 *                             funtions is returned by @b socket()
 *                             or @b accept()
 * @param fcntl_test           Determines which @b fcntl() flag or
 *                             option we test
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

#define TE_TEST_NAME  "level5/ext_stackname/fcntl_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME1 "foo"
#define STACK_NAME2 "bar"

enum {
    FD_CLOEXEC_TEST,
    O_ASYNC_TEST,
    O_NONBLOCK_TEST,
    F_SETOWN_TEST,
    F_SETOWN_EX_TEST,
    F_SETSIG_TEST,
};

#define FCNTL_TESTS \
    { "FD_CLOEXEC", FD_CLOEXEC_TEST }, \
    { "O_ASYNC", O_ASYNC_TEST }, \
    { "O_NONBLOCK", O_NONBLOCK_TEST }, \
    { "F_SETOWN", F_SETOWN_TEST }, \
    { "F_SETOWN_EX", F_SETOWN_EX_TEST }, \
    { "F_SETSIG", F_SETSIG_TEST }

static inline void
check_fcntl(rcf_rpc_server *rpcs,
            int s,
            int fcntl_test,
            te_bool cloexec_expected,
            int flags_expected,
            pid_t owner_expected,
            struct rpc_f_owner_ex *owner_ex_expected,
            int signum_expected,
            const char *msg,
            te_bool *test_failed)
{
    te_bool                 cloexec;
    int                     flags;
    pid_t                   owner;
    struct rpc_f_owner_ex   owner_ex;
    int                     signum;

    switch (fcntl_test)
    {
        case FD_CLOEXEC_TEST:
            cloexec = rpc_fcntl(rpcs, s, RPC_F_GETFD, 0);
            if (cloexec != cloexec_expected)
            {
                ERROR_VERDICT("FD_CLOEXEC flag setting changed after "
                              "%s", msg);
                *test_failed = TRUE;
            }
            break;

        case O_ASYNC_TEST:
        case O_NONBLOCK_TEST:
            flags = rpc_fcntl(rpcs, s, RPC_F_GETFL, 0);
            if (flags != flags_expected)
            {
                ERROR_VERDICT("File status flags changed after "
                              "%s", msg);
                *test_failed = TRUE;
            }
            break;

        case F_SETOWN_TEST:
            owner = rpc_fcntl(rpcs, s, RPC_F_GETOWN, 0);
            if (owner != owner_expected)
            {
                ERROR_VERDICT("Socket owner changed after "
                              "%s", msg);
                *test_failed = TRUE;
            }
            break;

        case F_SETOWN_EX_TEST:
            memset(&owner_ex, 0, sizeof(owner_ex));
            rpc_fcntl(rpcs, s, RPC_F_GETOWN_EX, &owner_ex);
            if (memcmp(&owner_ex, owner_ex_expected,
                       sizeof(owner_ex)) != 0)
            {
                ERROR_VERDICT("F_GETOWN_EX value changed after "
                              "%s", msg);
                *test_failed = TRUE;
            }
            break;

        case F_SETSIG_TEST:
            signum = rpc_fcntl(rpcs, s, RPC_F_GETSIG, 0);
            if (signum != signum_expected)
            {
                ERROR_VERDICT("F_GETSIG value changed after "
                              "%s", msg);
                *test_failed = TRUE;
            }
            break;

        default:
            TEST_VERDICT("Unknown fcntl_test parameter value");
    }

}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_child = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    int                     fcntl_test;
    te_bool                 existing_stack1 = FALSE;
    te_bool                 existing_stack2 = FALSE;
    te_bool                 sock_accepted = FALSE;
    char                   *init_stack_name;
    te_bool                 restore_stack_name = FALSE;

    int                     iut_s = -1;
    int                     iut_s_listening = -1;
    int                     iut_s_aux = -1;
    int                     tst_s = -1;
    int                     tst_s_listening = -1;
    te_bool                 cloexec = FALSE;
    te_bool                 cloexec_old = FALSE;
    te_bool                 cloexec_new = FALSE;
    int                     flags = 0;
    int                     flags_old = 0;
    int                     flags_new = 0;
    pid_t                   owner = 0;
    pid_t                   owner_old = 0;
    pid_t                   owner_new = 0;
    struct rpc_f_owner_ex   owner_ex;
    struct rpc_f_owner_ex   owner_ex_old;
    struct rpc_f_owner_ex   owner_ex_new;
    int                     signum;
    int                     signum_old;
    int                     signum_new;
    te_bool                 test_failed = FALSE;
    te_bool                 bool_rc;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(sock_accepted);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(fcntl_test, FCNTL_TESTS);
    TEST_GET_BOOL_PARAM(existing_stack1);
    TEST_GET_BOOL_PARAM(existing_stack2);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Obtain TCP socket returned ether by @b socket() or by @b accept(), "
              "according to @p sock_accepted parameter.");
    if (sock_accepted)
    {
        bool_rc = 
            gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                   pco_tst, tst_addr,
                                   TRUE, TRUE, FALSE, TRUE,
                                   &iut_s_listening, &iut_s,
                                   &tst_s, NULL);
        if (!bool_rc)
            TEST_STOP;
    }
    else
        iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);

    /* Change fcntl() flag or option determined by @p fcntl_test
     * parameter. */
    switch (fcntl_test)
    {
        case FD_CLOEXEC_TEST:
            cloexec_old = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFD, 0);
            if (cloexec_old)
                cloexec = FALSE;
            else
                cloexec = TRUE;
            rpc_fcntl(pco_iut, iut_s, RPC_F_SETFD, cloexec);
            cloexec_new = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFD, 0);
            if (cloexec_new == cloexec_old)
                TEST_VERDICT("Failed to change FD_CLOEXEC flag setting");
            break;

        case O_ASYNC_TEST:
        case O_NONBLOCK_TEST:
            {
                int flag = (fcntl_test == O_ASYNC_TEST) ?
                                            RPC_O_ASYNC : RPC_O_NONBLOCK;
                flags_old = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, 0);
                if (flags_old & flag)
                    flags = (flags_old & (~flag));
                else
                    flags = (flags_old | flag);
                rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, flags);
                flags_new = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, 0);
                if (flags_new == flags_old)
                    TEST_VERDICT("Failed to change file status flags");
            }
            break;

        case F_SETOWN_TEST:
            owner_old = rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN, 0);
            CHECK_RC(rcf_rpc_server_fork(pco_iut,
                                         "pco_iut_child", &pco_iut_child));
            owner = rpc_getpid(pco_iut_child);
            rpc_fcntl(pco_iut, iut_s, RPC_F_SETOWN, owner);
            owner_new = rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN, 0);
            if (owner_new == owner_old)
                TEST_VERDICT("Failed to change F_GETOWN value");
            break;

        case F_SETOWN_EX_TEST:
            memset(&owner_ex_old, 0, sizeof(owner_ex_old));
            rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN_EX, &owner_ex_old);
            CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                                  "pco_iut_child",
                                                  &pco_iut_child));
            owner_ex.pid = rpc_gettid(pco_iut_child);
            owner_ex.type = F_OWNER_TID;
            rpc_fcntl(pco_iut, iut_s, RPC_F_SETOWN_EX, &owner_ex);
            memset(&owner_ex_new, 0, sizeof(owner_ex_new));
            rpc_fcntl(pco_iut, iut_s, RPC_F_GETOWN_EX, &owner_ex_new);
            if (memcmp(&owner_ex_new, &owner_ex_old,
                       sizeof(owner_ex_old)) == 0)
                TEST_VERDICT("Failed to change F_GETOWN_EX value");
            break;

        case F_SETSIG_TEST:
            signum_old = rpc_fcntl(pco_iut, iut_s, RPC_F_GETSIG, 0);
            if (signum_old == RPC_SIGIO)
                signum = RPC_SIGUSR1;
            else
                signum = RPC_SIGIO;

            rpc_fcntl(pco_iut, iut_s, RPC_F_SETSIG, signum);
            signum_new = rpc_fcntl(pco_iut, iut_s, RPC_F_GETSIG, 0);
            if (signum_new == signum_old)
                TEST_VERDICT("Failed to change F_GETSIG value");

            break;
        default:
            TEST_VERDICT("Unknown fcntl_test parameter value");
    }

    TEST_STEP("Move TCP socket to a new stack.");

    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME1,
                                         existing_stack1, &iut_s_aux);

    restore_stack_name = TRUE;

    bool_rc = tapi_rpc_onload_move_fd_check(
                              pco_iut, iut_s,
                              TAPI_MOVE_FD_SUCCESS_EXPECTED, STACK_NAME1,
                              "The first call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that fcntl() flag or option remained the same.");
    check_fcntl(pco_iut, iut_s, fcntl_test, cloexec_new, flags_new,
                owner_new, &owner_ex_new, signum_new,
                "moving socket to a different stack",
                &test_failed);

    TEST_STEP("Try to move TCP socket to a new stack the second time; "
              "check that it fails.");

    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME2,
                                         existing_stack2, &iut_s_aux);

    bool_rc = tapi_rpc_onload_move_fd_check(
                            pco_iut,iut_s,
                            sock_accepted ? TAPI_MOVE_FD_FAILURE_EXPECTED :
                                            TAPI_MOVE_FD_SUCCESS_EXPECTED,
                            STACK_NAME2,
                            "The second call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that fcntl() flag or option remained the same.");
    check_fcntl(pco_iut, iut_s, fcntl_test, cloexec_new, flags_new,
                owner_new, &owner_ex_new, signum_new,
                "moving socket to a different stack the second time",
                &test_failed);

    TEST_STEP("Check that socket is still usable.");
    if (!sock_accepted)
    {
        bool_rc = 
             gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                    pco_tst, tst_addr,
                                    FALSE, TRUE,
                                    (fcntl_test == O_NONBLOCK_TEST &&
                                     (flags_new & RPC_O_NONBLOCK)),
                                    FALSE,
                                    &iut_s, NULL,
                                    &tst_s_listening, &tst_s);
        if (!bool_rc)
            TEST_STOP;
    }

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listening);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_child));

    TEST_END;

}
