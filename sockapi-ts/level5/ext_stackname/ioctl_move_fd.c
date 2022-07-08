/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */


/** @page ext_stackname-ioctl_move_fd Call @b onload_move_fd() on a socket after @b ioctl()
 *
 * @objective Check that calling @b onload_move_fd() does not change
 *            whatever set by ioctl() before the call.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on TESTER
 * @param iut_addr             Network address on IUT
 * @param tst_addr             Network address on TESTER
 * @param sock_accepted        Whether a socket on which we test
 *                             funtions is returned by @b socket()
 *                             or @b accept().
 * @param req                  @b ioctl() request to be tested
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

#define TE_TEST_NAME  "level5/ext_stackname/ioctl_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME1 "foo"
#define STACK_NAME2 "bar"

static inline void
check_ioctl(rcf_rpc_server *rpcs,
            int s,
            rpc_ioctl_code req,
            int flag,
            te_bool ioctl_flag_expected,
            int req_val_expected,
            const char *msg,
            te_bool *test_failed)
{
    int     flags;
    te_bool ioctl_flag;
    int     req_val;

    switch (req)
    {
        case RPC_FIOASYNC:
        case RPC_FIONBIO:

            flags = rpc_fcntl(rpcs, s, RPC_F_GETFL, 0);
            ioctl_flag = ((flags & flag) ? TRUE : FALSE);
            if (ioctl_flag != ioctl_flag_expected)
            {
                ERROR_VERDICT("File status flag changed after %s",
                              msg);
                *test_failed = TRUE;
            }

            break;

        case RPC_SIOCSPGRP:

            rpc_ioctl(rpcs, s, RPC_SIOCGPGRP, &req_val);
            if (req_val != req_val_expected)
            {
                ERROR_VERDICT("SIOCGPGRP value changed after %s",
                              msg);
                *test_failed = TRUE;
            }

            break;

        default:
            TEST_VERDICT("Unexpected ioctl() request");
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
    rpc_ioctl_code          req;
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

    te_bool                 test_failed = FALSE;
    te_bool                 bool_rc;

    int         flag;
    int         flags;
    int         req_val_old;
    int         req_val;
    int         req_val_new;
    te_bool     ioctl_flag_old = FALSE;
    te_bool     ioctl_flag = FALSE;
    te_bool     ioctl_flag_new = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOCTL_REQ(req);
    TEST_GET_BOOL_PARAM(sock_accepted);
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

    switch (req)
    {
        case RPC_FIOASYNC:
        case RPC_FIONBIO:

            flag = ((req == RPC_FIOASYNC) ? RPC_O_ASYNC : RPC_O_NONBLOCK);
            flags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, 0);

            ioctl_flag_old = ((flags & flag) ? TRUE : FALSE);
            ioctl_flag = !ioctl_flag_old;
            req_val = ioctl_flag ? 1 : 0;
            rpc_ioctl(pco_iut, iut_s, req, &req_val);

            flags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, 0);
            ioctl_flag_new = ((flags & flag) ? TRUE : FALSE);
            if (ioctl_flag_new == ioctl_flag_old)
                TEST_VERDICT("Failed to change file status flag with "
                             "ioctl()");

            break;

        case RPC_SIOCSPGRP:

            rpc_ioctl(pco_iut, iut_s, RPC_SIOCGPGRP, &req_val_old);
            CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                                  "pco_iut_child",
                                                  &pco_iut_child));
            req_val = rpc_getpid(pco_iut_child);
            rpc_ioctl(pco_iut, iut_s, RPC_SIOCSPGRP, &req_val);
            rpc_ioctl(pco_iut, iut_s, RPC_SIOCGPGRP, &req_val_new);
            if (req_val_old == req_val_new)
                TEST_VERDICT("Failed to change SIOCGPGRP value");

            break;

        default:
            TEST_VERDICT("Unexpected ioctl() request");
    }


    TEST_STEP("Move TCP socket to a new stack.");

    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME1,
                                         existing_stack1, &iut_s_aux);

    bool_rc = tapi_rpc_onload_move_fd_check(
                              pco_iut, iut_s,
                              TAPI_MOVE_FD_SUCCESS_EXPECTED, STACK_NAME1,
                              "The first call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that what was set with @b ioctl(@p req), did not change.");
    check_ioctl(pco_iut, iut_s, req,
                flag, ioctl_flag_new, req_val_new,
                "moving socket to a different stack",
                &test_failed);

    TEST_STEP("Try to move TCP socket to a new stack the second time; "
              "check that it fails.");

    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME2,
                                         existing_stack2, &iut_s_aux);

    restore_stack_name = TRUE;

    bool_rc = tapi_rpc_onload_move_fd_check(
                            pco_iut,iut_s,
                            sock_accepted ? TAPI_MOVE_FD_FAILURE_EXPECTED :
                                            TAPI_MOVE_FD_SUCCESS_EXPECTED,
                            STACK_NAME2,
                            "The second call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Check that what was set with @b ioctl(@p req), did not change.");
    check_ioctl(pco_iut, iut_s, req,
                flag, ioctl_flag_new, req_val_new,
                "moving socket to a different stack the second time",
                &test_failed);

    TEST_STEP("Check that socket is still usable.");
    if (!sock_accepted)
    {
        bool_rc =
            gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                   pco_tst, tst_addr,
                                   FALSE, TRUE,
                                   (req == RPC_FIONBIO &&
                                    ioctl_flag_new) ? TRUE : FALSE,
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
