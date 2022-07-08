/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-unsupp_socket_move_fd Call @b onload_move_fd() on an unsupported socket fd
 *
 * @objective Check that if we call @b onload_move_fd() on an UDP socket or
 *            system socket fd, it fails and socket still works OK.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param sock_type            @c RPC_SOCK_STREAM or @c RPC_SOCK_DGRAM
 * @param system_fd            Whether we should to call
 *                             @b onload_move_fd() on an Onload socket fd
 *                             or system one
 * @param af_unix              Whether we should test sockets from
 *                             @c AF_UNIX or @c AF_INET domains
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/unsupp_socket_move_fd"

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
    int                     iut_s_listening = -1;
    int                     tst_s = -1;
    int                     fd_pair[2] = { -1, -1 };
    rpc_socket_type         sock_type;
    te_bool                 system_fd = FALSE;
    te_bool                 af_unix = FALSE;

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
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(system_fd);
    TEST_GET_BOOL_PARAM(af_unix);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Create a pair of connected sockets of type @p sock_type "
              "and family selected according to @p af_unix.");
    if (system_fd)
        pco_iut->use_libc = TRUE;
    if (af_unix)
        rpc_socketpair(pco_iut, RPC_AF_UNIX, sock_type,
                       RPC_PROTO_DEF, fd_pair);
    else
    {
        if (sock_type == RPC_SOCK_STREAM)
        {
            if (!gen_tcp_conn_with_sock(pco_iut, iut_addr,
                                        pco_tst, tst_addr,
                                        TRUE, TRUE, FALSE, TRUE,
                                        &iut_s_listening, &iut_s,
                                        &tst_s, NULL))
                TEST_STOP;
        }
        else
            GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM,
                           RPC_PROTO_DEF, iut_addr, tst_addr, &iut_s,
                           &tst_s);
    }
    if (system_fd)
        pco_iut->use_libc = FALSE;

    TEST_STEP("Try to move a socket to a new stack; check that it fails.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                         FALSE, NULL);

    restore_stack_name = TRUE;

    if (!tapi_rpc_onload_move_fd_check(
                                  pco_iut, af_unix ? fd_pair[0] : iut_s,
                                  TAPI_MOVE_FD_FAILURE_EXPECTED, STACK_NAME,
                                  "Calling onload_move_fd() on a socket fd "
                                  "of unsupported type"))
        test_failed = TRUE;

    TEST_STEP("Check that socket is still usable.");
    sockts_test_connection(pco_iut, af_unix ? fd_pair[0] : iut_s,
                           af_unix ? pco_iut : pco_tst,
                           af_unix ? fd_pair[1] : tst_s);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, fd_pair[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fd_pair[1]);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
