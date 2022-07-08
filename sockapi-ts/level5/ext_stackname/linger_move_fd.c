/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Call @b onload_move_fd() on TCP socket with enabled SO_LINGER
 */

/**
 * @page ext_stackname-linger_move_fd Call @b onload_move_fd() on TCP socket with enabled SO_LINGER
 *
 * @objective Check that SO_LINGER works after moving TCP socket to another
 *            stack.
 *
 * @param env                      Testing environment:
 *      - @ref arg_types_env_peer2peer
 * @param active                   Establish connection actively for IUT if @c
 *                                 TRUE, else - passively.
 * @param linger_before_connection Set @c SO_LINGER option before connection
 *                                 establishing if @c TRUE.
 * @param linger_val               l_linger value to set with @c SO_LINGER:
 *      - @c 0
 *      - @c 1
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/ext_stackname/linger_move_fd"

#include "sockapi-test.h"
#include "onload.h"
#include "move_fd_helpers.h"

#define STACK_NAME "foo"

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *tst_addr = NULL;
    const struct if_nameindex   *tst_if = NULL;

    int                    iut_s = -1;
    int                    tst_s = -1;
    rcf_rpc_server        *srv_pco = NULL;
    rcf_rpc_server        *clnt_pco = NULL;
    const struct sockaddr *srv_addr = NULL;
    const struct sockaddr *clnt_addr = NULL;
    int                   *srv_s = NULL;
    int                   *clnt_s = NULL;
    te_bool                active = FALSE;
    te_bool                linger_before_connection = FALSE;
    int                    linger_val = 0;
    tarpc_linger           opt_linger_val = {0};
    int                    acc_socket = -1;
    char                  *init_stack_name = NULL;
    te_bool                restore_stack_name = FALSE;
    int                    tmp;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_BOOL_PARAM(linger_before_connection);
    TEST_GET_INT_PARAM(linger_val);

    clnt_pco = active ? pco_iut : pco_tst;
    clnt_addr = active ? iut_addr : tst_addr;
    clnt_s = active ? &iut_s : &tst_s;
    srv_pco = active ? pco_tst : pco_iut;
    srv_addr = active ? tst_addr : iut_addr;
    srv_s = active ? &tst_s : &iut_s;

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    opt_linger_val.l_onoff  = 1;
    opt_linger_val.l_linger = linger_val;

    TEST_STEP("Create and bind TCP socket on IUT and tester accrording to "
              "@p active parameter.");
    *srv_s = rpc_stream_server(srv_pco, RPC_IPPROTO_TCP, FALSE, srv_addr);
    *clnt_s = rpc_stream_client(clnt_pco, RPC_PF_INET,
                                RPC_IPPROTO_TCP, clnt_addr);

    if (*srv_s < 0)
        TEST_VERDICT("Cannot create listening socket.");

    if (*clnt_s < 0)
        TEST_VERDICT("Cannot create client socket.");

    TEST_STEP("If @p linger_before_connection = @c TRUE set @c SO_LINGER with "
              "value @p linger_val here.");
    if (linger_before_connection)
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_linger_val);

    TEST_STEP("Establish TCP connection.");
    srv_pco->op = RCF_RPC_CALL;
    rpc_accept(srv_pco, *srv_s, NULL, NULL);

    TEST_STEP("If @p active is @c TRUE - set new Onload stack before @b connect().");
    if (active)
    {
        tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                             ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                             FALSE, NULL);
        restore_stack_name = TRUE;
    }
    rpc_connect(clnt_pco, *clnt_s, srv_addr);
    tmp = rpc_accept(srv_pco, *srv_s, NULL, NULL);

    /* Swap listening and accepted sockets. */
    acc_socket = *srv_s;
    *srv_s = tmp;

    TEST_STEP("If @p linger_before_connection = @c FALSE set @c SO_LINGER with "
              "value @p linger_val here. "
              "It makes sence only with @p active = @c FALSE.");
    if (!linger_before_connection)
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_linger_val);

    TEST_STEP("If @p active is @c FALSE, move IUT socket to another "
              "Onload stack using @b onload_move_fd().");
    if (!active)
    {
        tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                             ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                             FALSE, NULL);
        restore_stack_name = TRUE;
        if (tapi_rpc_onload_move_fd_check(pco_iut, iut_s,
                                  TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                  STACK_NAME, NULL) == FALSE)
            TEST_VERDICT("Moving iut socket to another stack was failed");
    }

    TEST_STEP("Check data transmission in both directions.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("Close IUT socket and check linger using function @ref "
              "sockts_close_check_linger().");
    if (sockts_close_check_linger(pco_iut, pco_tst, NULL, &iut_s, tst_s,
                                  tst_if->if_name, iut_addr, &opt_linger_val,
                                  TRUE, CL_SHUTDOWN, TRUE) != 0)
        TEST_VERDICT("Check linger failed");

    TEST_SUCCESS;

cleanup:
    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);
    CLEANUP_RPC_CLOSE(srv_pco, acc_socket);
    CLEANUP_RPC_CLOSE(srv_pco, *srv_s);
    CLEANUP_RPC_CLOSE(clnt_pco, *clnt_s);
    TEST_END;
}
