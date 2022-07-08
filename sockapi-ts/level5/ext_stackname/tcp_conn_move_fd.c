/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-tcp_conn_move_fd Try to call @b onload_move_fd() on a socket just after TCP connection establishment
 *
 * @objective Check that after establishing a TCP connection but without
 *            any normal data read or pending, an Onload socket can be
 *            moved to a different stack.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param active               Whether TCP connection should be opened
 *                             passively or actively from the IUT side
 * @param existing_stack1      Whether Onload stack should already exist
 *                             or not when we try to move a socket fd to it
 *                             firstly
 * @param existing_stack1      Whether Onload stack should already exist
 *                             or not when we try to move a socket fd to it
 *                             secondly
 * @param close_listening      Whether we should close the listening socket
 *                             before @b onload_move_fd() call or not
 * @param tst_sends_data       Determines whether we should send some data
 *                             from the TESTER side of connection before
 *                             moving the IUT socket or not. Can be "none",
 *                             "plain" (just send some data) and
 *                             "oob" (send out-of-band data).
 * @param iut_sends_data       Determines the same as @p tst_sends_data but
 *                             for IUT socket.
 * @param cache_socket         If @c TRUE, create cached socket to be reused.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/tcp_conn_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME1 "foo"
#define STACK_NAME2 "bar"

enum {
    TRANSMIT_NONE,
    TRANSMIT_PLAIN,
    TRANSMIT_OOB,
};

#define DATA_TRANSMIT_MODE \
    { "none", TRANSMIT_NONE }, \
    { "plain", TRANSMIT_PLAIN }, \
    { "oob", TRANSMIT_OOB }

#define DATA_SIZE 1024

static inline void
gen_tcp_connection(rcf_rpc_server *pco_iut, int *iut_s,
                   const struct sockaddr *iut_addr,
                   rcf_rpc_server *pco_tst, int *tst_s,
                   const struct sockaddr *tst_addr, int *listening_s,
                   te_bool active, te_bool cache_socket)
{
    rcf_rpc_server        *server = pco_iut;
    int                   *server_s_accepted = iut_s;
    const struct sockaddr *server_addr = iut_addr;
    rcf_rpc_server        *client = pco_tst;
    int                   *client_s_connected = tst_s;
    const struct sockaddr *client_addr = tst_addr;

    if (active)
    {
        server = pco_tst;
        server_s_accepted = tst_s;
        server_addr = tst_addr,
        client = pco_iut;
        client_s_connected = iut_s;
        client_addr = iut_addr;
    }

    *listening_s = rpc_create_and_bind_socket(server, RPC_SOCK_STREAM,
                                              RPC_PROTO_DEF, FALSE,
                                              FALSE, server_addr);
    rpc_listen(server, *listening_s, SOCKTS_BACKLOG_DEF);

    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr,
                                *listening_s, active, cache_socket);

    *client_s_connected = rpc_socket(client,
                                     rpc_socket_domain_by_addr(client_addr),
                                     RPC_SOCK_STREAM,
                                     RPC_PROTO_DEF);
    rpc_bind(client, *client_s_connected, client_addr);
    rpc_connect(client, *client_s_connected, server_addr);
    *server_s_accepted = rpc_accept(server, *listening_s,
                                    NULL, NULL);
}

static inline void
receive_all_check(rcf_rpc_server *rpcs, int s,
                  te_bool oob_sent, const char *send_buf)
{
    ssize_t rc;

    char recv_buf[DATA_SIZE];

    rc = rpc_recv(rpcs, s, recv_buf, DATA_SIZE,
                  oob_sent ? RPC_MSG_OOB : 0);

    if ((!oob_sent &&
         (rc != DATA_SIZE ||
          memcmp(send_buf, recv_buf, DATA_SIZE) != 0)) ||
        (oob_sent &&
         (rc != 1 || recv_buf[0] != send_buf[DATA_SIZE - 1])))
        TEST_FAIL("Data received by %s is corrupted",
                  rpcs->name);
    if (oob_sent)
    {
        rc = rpc_recv(rpcs, s, recv_buf, DATA_SIZE, 0);
        if (rc != DATA_SIZE - 1 ||
            memcmp(send_buf, recv_buf, DATA_SIZE - 1) != 0)
            TEST_FAIL("Remained OOB data received by %s is corrupted",
                      rpcs->name);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    int                     iut_s = -1;
    int                     iut_s_listening = -1;
    int                     iut_s_aux = -1;
    int                     tst_s = -1;
    int                     tst_s_listening = -1;
    te_bool                 active = FALSE;
    te_bool                 existing_stack1 = FALSE;
    te_bool                 existing_stack2 = FALSE;
    int                     tst_sends_data = TRANSMIT_NONE;
    int                     iut_sends_data = TRANSMIT_NONE;
    te_bool                 test_failed = FALSE;
    te_bool                 bool_rc;
    te_bool                 close_listening = FALSE;
    char                    send_buf[DATA_SIZE];
    char                   *init_stack_name;
    te_bool                 restore_stack_name = FALSE;
    te_bool                 cache_socket = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_BOOL_PARAM(existing_stack1);
    TEST_GET_BOOL_PARAM(existing_stack2);
    TEST_GET_BOOL_PARAM(close_listening);
    TEST_GET_BOOL_PARAM(cache_socket);
    TEST_GET_ENUM_PARAM(tst_sends_data, DATA_TRANSMIT_MODE);
    TEST_GET_ENUM_PARAM(iut_sends_data, DATA_TRANSMIT_MODE);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Open a TCP connection, taking into account @p active "
              "parameter.");
    gen_tcp_connection(pco_iut, &iut_s, iut_addr, pco_tst, &tst_s, tst_addr,
                       active ? &tst_s_listening : &iut_s_listening,
                       active, cache_socket);

    TEST_STEP("If @p close_listening, close IUT listening socket before we call "
              "@b onload_move_fd().");
    if (close_listening && iut_s_listening != -1)
    {
        rpc_close(pco_iut, iut_s_listening);
        iut_s_listening = -1;
    }

    TEST_STEP("If required, send some data through the connection according to "
              "@p tst_sends_data and @p iut_sends_data parameters.");
    te_fill_buf(send_buf, DATA_SIZE); 
    if (tst_sends_data == TRANSMIT_PLAIN || tst_sends_data == TRANSMIT_OOB)
        RPC_SEND(rc, pco_tst, tst_s, send_buf, DATA_SIZE,
                 tst_sends_data == TRANSMIT_OOB ? RPC_MSG_OOB : 0);
    if (iut_sends_data == TRANSMIT_PLAIN || iut_sends_data == TRANSMIT_OOB)
        RPC_SEND(rc, pco_iut, iut_s, send_buf, DATA_SIZE,
                 iut_sends_data == TRANSMIT_OOB ? RPC_MSG_OOB : 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Set stack name to @c STACK_NAME1; create a new socket "
              "to create a stack with this name if @p existing_stack1 is set.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_GLOBAL, STACK_NAME1,
                                         existing_stack1, &iut_s_aux);

    restore_stack_name = TRUE;

    TEST_STEP("Try to move the IUT socket to the new stack, check "
              "that it successes if TCP connection was opened passively "
              "on IUT and cached socket reusing was not used, fails otherwise.");
    bool_rc = tapi_rpc_onload_move_fd_check(
                          pco_iut, iut_s,
                          (active || cache_socket) ?
                              TAPI_MOVE_FD_FAILURE_EXPECTED :
                              TAPI_MOVE_FD_SUCCESS_EXPECTED,
                          STACK_NAME1,
                          "The first call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    TEST_STEP("Set stack name to @c STACK_NAME2; create a new socket "
              "to create a stack with this name if @p existing_stack2 is set.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_GLOBAL, STACK_NAME2,
                                         existing_stack2, &iut_s_aux);

    TEST_STEP("Try to move IUT socket to a different stack the second time "
              "and check that it fails.");
    bool_rc = tapi_rpc_onload_move_fd_check(
                                    pco_iut, iut_s,
                                    TAPI_MOVE_FD_FAILURE_EXPECTED,
                                    STACK_NAME2,
                                    "The second call of onload_move_fd()");
    test_failed = test_failed || !bool_rc;

    if (tst_sends_data == TRANSMIT_PLAIN || tst_sends_data == TRANSMIT_OOB)
        receive_all_check(pco_iut, iut_s, tst_sends_data == TRANSMIT_OOB,
                          send_buf);
    if (iut_sends_data == TRANSMIT_PLAIN || iut_sends_data == TRANSMIT_OOB)
        receive_all_check(pco_tst, tst_s, iut_sends_data == TRANSMIT_OOB,
                          send_buf);

    TEST_STEP("Check that connection can still be used.");
    sockts_test_connection(pco_iut, iut_s,
                           pco_tst, tst_s);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);
    if (iut_s_aux != -1)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    if (iut_s_listening != -1)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
    if (tst_s_listening != -1)
        CLEANUP_RPC_CLOSE(pco_tst, tst_s_listening);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
