/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */


/** @page basic-vfork_open_close_exec open()/close()/dup() after vfork() but before execve()
 *
 * @objective Check behaviour of open()/close()/dup() after vfork()
 *            but before execve().
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param func  Function to be tested:
 *              - close
 *              - open
 *              - dup
 *              - dup2
 *              - dup3
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
 * -# Call @b vfork() in @p pco_iut to create @p pco_child.
 * -# Call @b func in @p pco_child, check its return value.
 * -# Call execve() in @p pco_child and terminate it.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/vfork_open_close_exec"

#include "sockapi-test.h"

enum {
    FUNC_CLOSE = 1,
    FUNC_OPEN,
    FUNC_DUP,
    FUNC_DUP2,
    FUNC_DUP3
};

#define FUNC_MAPPING_LIST \
    {"close", FUNC_CLOSE},      \
    {"open", FUNC_OPEN},        \
    {"dup", FUNC_DUP},          \
    {"dup2", FUNC_DUP2},        \
    {"dup3", FUNC_DUP3}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_child = NULL;
    vfork_thread_data      data;
    pthread_t              thread_id;
    int                    func;
    int                    iut_s;
    int                    iut_s_aux;
    int                    fd = -1;
    te_bool                is_failed = FALSE;
    rpc_socket_domain      domain;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ENUM_PARAM(func, FUNC_MAPPING_LIST);
    TEST_GET_DOMAIN(domain);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut_s_aux = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    data.rpcs = pco_iut;
    data.name = "iut_child";
    /* 
     * This wait may be not necessary - it is done to prevent
     * parent and child from executing simultaneously in case
     * of vfork() not blocking parent until exec().
     */
    data.time_to_wait = 3000;

    CHECK_RC(rcf_rpc_server_vfork_in_thread(&data, &thread_id,
                                            &pco_child));

    RPC_AWAIT_IUT_ERROR(pco_child);
    if (func == FUNC_CLOSE)
        rc = rpc_close(pco_child, iut_s);
    else if (func == FUNC_OPEN)
        rc = fd = rpc_open(pco_child, "/dev/zero", RPC_O_RDONLY, 0);
    else if (func == FUNC_DUP)
        rc = fd = rpc_dup(pco_child, iut_s);
    else if (func == FUNC_DUP2)
        rc = fd = rpc_dup2(pco_child, iut_s, iut_s_aux);
    else if (func == FUNC_DUP3)
        rc = fd = rpc_dup3(pco_child, iut_s, iut_s_aux, 0);

    if (rc < 0)
    {
        ERROR_VERDICT("Function failed in child process with errno %s",
                      errno_rpc2str(RPC_ERRNO(pco_child)));
        is_failed = TRUE;
    }

    rcf_rpc_server_exec(pco_child);

    if (fd >= 0)
    {
        RPC_AWAIT_IUT_ERROR(pco_child);
        rc = rpc_close(pco_child, fd);
        if (rc != 0)
        {
            ERROR_VERDICT("Attempt to close fd opened before execve () "
                          "failed with errno %s",
                          errno_rpc2str(RPC_ERRNO(pco_child)));
            is_failed = TRUE;
        }
    }

    rcf_rpc_server_destroy(pco_child);
    pthread_join(thread_id, NULL);

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);

    TEST_END;
}
