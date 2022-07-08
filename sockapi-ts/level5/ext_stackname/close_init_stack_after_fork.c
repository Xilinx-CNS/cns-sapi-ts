/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page ext_stackname-close_init_stack_after_fork Check that initial Onload stack is closed after fork()
 *
 * @objective Check that initial Onload stack is closed in time when
 *            all sockets are closed after fork() and it's not default stack
 *            for anyone.
 *
 * @type use case
 *
 * @param pco_iut         PCO on IUT
 * @param reuseport       Set SO_REUSEPORT for the socket
 * @param exec            Whether exec() should be called after @b fork() call
 *
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/close_init_stack_after_fork"

#include "sockapi-test.h"

#include "onload.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_child = NULL;
    const struct sockaddr  *iut_addr = NULL;

    int                     sock;
    int                     iut_aux_sock;
    int                     iut_child_aux_sock;
    int                     init_stack_id;
    tarpc_onload_stat       ostat;
    rpc_stat                file_st_buf;
    te_bool                 reuseport;
    te_bool                 exec;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(reuseport);
    TEST_GET_BOOL_PARAM(exec);

    TEST_STEP("Create TCP socket and check that it's accelerated.");
    sock = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    if (rpc_onload_fd_stat(pco_iut, sock, &ostat) != 1)
        TEST_FAIL("Socket is not accelerated.");

    init_stack_id = ostat.stack_id;

    if (reuseport)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (rpc_setsockopt_int(pco_iut, sock, RPC_SO_REUSEPORT, 1) != 0)
            TEST_VERDICT("Failed to set SO_REUSEPORT option: %r",
                         RPC_ERRNO(pco_iut));

        CHECK_RC(rpc_bind(pco_iut, sock, iut_addr));
    }

    TEST_STEP("Call @b fork() on @p pco_iut and then @b exec() depending on the @p exec "
              "to obtain @p pco_iut_child RPC server.");
    if (exec)
        CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, "iut_child",
                                          &pco_iut_child));
    else
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "iut_child", &pco_iut_child));

    TEST_STEP("Close sockets on parent and child processes. "
              "Check that sockets are really closed.");
    CHECK_RC(rpc_close(pco_iut, sock));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (rpc_fstat(pco_iut, sock, &file_st_buf) != -1)
        TEST_VERDICT("Socket is not closed after 'fork' on parent proccess.");

    CHECK_RC(rpc_close(pco_iut_child, sock));
    RPC_AWAIT_IUT_ERROR(pco_iut_child);
    if (rpc_fstat(pco_iut_child, sock, &file_st_buf) != -1)
        TEST_VERDICT("Socket is not closed after 'fork' on child proccess.");

    TEST_STEP("Check that the initial stack is not the default stack "
              "for parent process.");
    iut_aux_sock = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM,
                              RPC_PROTO_DEF);
    if (rpc_onload_fd_stat(pco_iut, iut_aux_sock, &ostat) != 1)
        TEST_FAIL("Socket is not accelerated after opening on parent process.");

    if (init_stack_id == ostat.stack_id)
    {
        TEST_VERDICT("Initital stack is default stack for"
                     " parent proccess after fork.");
    }

    TEST_STEP("Check that the initial stack is not the default stack "
              "for child process.");
    iut_child_aux_sock = rpc_socket(pco_iut_child, RPC_AF_INET, RPC_SOCK_STREAM,
                                    RPC_PROTO_DEF);
    if (rpc_onload_fd_stat(pco_iut_child, iut_child_aux_sock, &ostat) != 1)
        TEST_FAIL("Socket is not accelerated after opening on child process.");

    if (init_stack_id == ostat.stack_id)
    {
        TEST_VERDICT("Initital stack is default stack for"
                     " child proccess after fork.");
    }

    /* Check that initial Onload stack is closed. */
    if (tapi_onload_stack_exists(pco_iut, init_stack_id) == TRUE)
        TEST_VERDICT("The initial stack was not closed.");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_aux_sock);
    CLEANUP_RPC_CLOSE(pco_iut_child, iut_child_aux_sock);

    rcf_rpc_server_destroy(pco_iut_child);

    TEST_END;
}
