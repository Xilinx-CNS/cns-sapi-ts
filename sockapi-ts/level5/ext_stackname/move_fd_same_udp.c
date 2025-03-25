/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright Oktet, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 *
 */

/** @page ext_stackname-move_fd_same_udp Move UDP socket to the same stack (@b onload_move_fd())
 *
 * @objective Check that moving socket to the same stack does not spoil socket.
 *
 * @param env                  Testing environment:
 *                             - @ref arg_types_env_peer2peer
 * @param bind_before          Bind socket on IUT before calling
 *                             @b onload_move_fd():
 *                             - @c TRUE
 *                             - @c FALSE
 * @param connect_socket       When to connect socket on IUT (relative to the
 *                             @b onload_move_fd() call):
 *                             - before
 *                             - after
 *                             - none
 *
 * @par Scenario:
 *
 * @author Boris Shleyfman <bshleyfman@oktet.co.il>
 */

#define TE_TEST_NAME  "level5/ext_stackname/move_fd_same_udp"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"
#include "iomux.h"

/** Length of sent and received buffers */
#define DATA_BULK  200

/**
 * When and whether to connect socket on IUT.
 */
typedef enum {
    CONNECT_BEFORE,               /** connect before calling onload_move_fd() */
    CONNECT_AFTER,                /** connect after calling onload_move_fd() */
    NOT_CONNECT,                  /** do not connect socket */
} connect_socket_t;

#define SOCKET_CONNECT_LIST  \
    { "before",    CONNECT_BEFORE },      \
    { "after",     CONNECT_AFTER },       \
    { "none",      NOT_CONNECT }

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;
    tarpc_onload_stat       ostat_before;
    tarpc_onload_stat       ostat_after;

    te_bool                 bind_before = FALSE;
    connect_socket_t        connect_socket;
    te_bool                 same_stack;

    unsigned char          *tx_buf = NULL;
    unsigned char          *rx_buf = NULL;
    size_t                  buf_len = DATA_BULK;
    int                     len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(bind_before);
    TEST_GET_ENUM_PARAM(connect_socket, SOCKET_CONNECT_LIST);

    if (!bind_before && connect_socket == CONNECT_BEFORE)
        TEST_FAIL("Invalid combination of test parameters");

    CHECK_NOT_NULL(tx_buf = te_make_buf_by_len(buf_len));
    CHECK_NOT_NULL(rx_buf = te_make_buf_by_len(buf_len));

    TEST_STEP("Create datagram sockets on @p pco_iut and @p pco_tst.");
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Call @b rpc_onload_fd_stat() on @p iut_s. Check that socket "
              "is accelerated.");
    rc = rpc_onload_fd_stat(pco_iut, iut_s, &ostat_before);
    if (rc != 1)
        ERROR_VERDICT("Failed to create accelerated socket on IUT.");

    TEST_STEP("Bind and connect the socket on TST. Depending on parameter "
              "values, bind and connect socket on IUT.");
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_connect(pco_tst, tst_s, iut_addr);
    if (bind_before)
    {
        rpc_bind(pco_iut, iut_s, iut_addr);
        if (connect_socket == CONNECT_BEFORE)
            rpc_connect(pco_iut, iut_s, tst_addr);
    }

    TEST_STEP("Call @b onload_move_fd(): move the socket @p iut_s to the same "
              "stack.");
    tapi_rpc_onload_move_fd_check(pco_iut, iut_s,
                                  TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                  ostat_before.stack_name,
                                  "Call onload_move_fd()");

    TEST_STEP("Depending on parameter values, bind and connect socket on IUT.");
    if (!bind_before)
        rpc_bind(pco_iut, iut_s, iut_addr);
    if (connect_socket == CONNECT_AFTER)
        rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("Call @b rpc_onload_fd_stat() again, check the return "
              "value. Check that the stack remains the same.");
    rc = rpc_onload_fd_stat(pco_iut, iut_s, &ostat_after);
    if (rc != 1)
        ERROR_VERDICT("The socket on IUT is not accelerated.");
    if (ostat_before.stack_id != ostat_after.stack_id)
    {
        ERROR_VERDICT("The socket @p iut_s is in another stack after the call "
                      "@b rpc_onload_fd_stat().");
    }

    TEST_STEP("Check that @p iut_s functions normally: check connection "
              "between IUT and TST.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);

    len = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, buf_len, len);
    TAPI_WAIT_NETWORK;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
