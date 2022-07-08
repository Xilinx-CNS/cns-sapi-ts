/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */


/** @page basic-vfork_check_hang Check that parent process hangs after vfork()
 *
 * @objective Check that parent process hangs after vfork() untill child
 *            performs @b execve() or _exit()
 *
 *
 * @type conformance
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_only
 * @param use_exec  Perform @b execve() if @c TRUE, else - @b _exit().
 * @param vfork_mode    Set Onload environment @c EF_VFORK_MODE to:
 *                      0: replace vfork() with fork();
 *                      1: replace vfork() with fork() and block parent till
 *                         child exits/execs;
 *                      2: replace vfork() with vfork().
 * @param domain        Protocol domain to be used for socket creation:
 *                      - PF_INET
 *                      - PF_INET6
 *
 * @par Test sequence:
 *
 * -# Create pipe.
 * -# Call @b vfork(); parent proccess should write data to the write end
 *    of the pipe when vfork() is unblocked.
 * -# Call @b sleep() in child process.
 * -# Use @b poll() in child process to check that there is no read event.
 * -# Call @b _exit() or @b execve() in child process according to
 *    @c use_exec.
 * -# Check that the parrent is unblocked.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/vfork_check_hang"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    te_bool                use_exec = FALSE;
    int                    iut_s = -1;
    rpc_socket_domain      domain;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(use_exec);
    TEST_GET_DOMAIN(domain);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_vfork_pipe_exec(pco_iut, use_exec);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
