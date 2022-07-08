/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */


/** @page basic-vfork_func_exec Async-safe function after vfork() but before execve()
 *
 * @objective Check behaviour of async-safe function after @b vfork().
 *            but before @b execve().
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_ipv6
 * @param func  Function to be tested:
 *              - send
 *              - recv
 *              - pipe
 *              - socket
 *              - accept
 * @param vfork_mode    Set Onload environment @c EF_VFORK_MODE to:
 *                      0: replace vfork() with fork();
 *                      1: replace vfork() with fork() and block parent till
 *                         child exits/execs;
 *                      2: replace vfork() with vfork().
 *
 * @par Test sequence:
 *
 * -# Call @b vfork() in @p pco_iut to create @p pco_child.
 * -# Call @b func in @p pco_child, check its return value.
 * -# Call execve() in @p pco_child and terminate it.
 * -# Call @b func in @p pco_iut, check its return value.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/vfork_func_exec"

#include "sockapi-test.h"

enum {
    FUNC_SEND = 1,
    FUNC_RECV,
    FUNC_PIPE,
    FUNC_SOCKET,
    FUNC_ACCEPT
};

#define FUNC_MAPPING_LIST \
    {"send", FUNC_SEND},     \
    {"recv", FUNC_RECV},     \
    {"pipe", FUNC_PIPE},     \
    {"socket", FUNC_SOCKET}, \
    {"accept", FUNC_ACCEPT}

#define BUF_MAX 1024

/** Make test action */
static void
test_vfork_exec_func(rcf_rpc_server *rpcs, rcf_rpc_server *pco_tst,
                     const struct sockaddr *tst_addr,
                     int iut_s, int tst_s, const struct sockaddr *iut_addr,
                     int func)
{
    int     fds[2];
    char    buf[BUF_MAX];
    int     aux_s = -1;

    RPC_AWAIT_IUT_ERROR(rpcs);

    if (func == FUNC_SEND)
        rpc_send(rpcs, iut_s, "test message", 12, 0);
    else if (func == FUNC_RECV)
    {
        rpc_send(pco_tst, tst_s, "test message", 12, 0);
        rpc_recv(rpcs, iut_s, buf, BUF_MAX, 0);
    }
    else if (func == FUNC_SOCKET)
    {
        aux_s = rpc_socket(rpcs, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    }
    else if (func == FUNC_PIPE)
        rpc_pipe(rpcs, fds);
    else if (func == FUNC_ACCEPT)
    {
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s, iut_addr);
        aux_s = rpc_accept(rpcs, iut_s, NULL, NULL);
        RPC_CLOSE(pco_tst, tst_s);
    }

    if (aux_s != -1)
        RPC_CLOSE(rpcs, aux_s);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    rcf_rpc_server        *pco_child = NULL;
    vfork_thread_data      data;
    pthread_t              thread_id;
    int                    func;
    int                    iut_s = -1;
    int                    tst_s = -1;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(func, FUNC_MAPPING_LIST);

    if (func == FUNC_SEND || func == FUNC_RECV)
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                       iut_addr, tst_addr, &iut_s, &tst_s);
    else if (func == FUNC_ACCEPT)
    {
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s, iut_addr);
        rpc_listen(pco_iut, iut_s, 2);
    }

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

    test_vfork_exec_func(pco_child, pco_tst, tst_addr, iut_s, tst_s,
                         iut_addr, func);

    rcf_rpc_server_exec(pco_child);

    SLEEP(1);

    rcf_rpc_server_destroy(pco_child);
    pthread_join(thread_id, NULL);

    test_vfork_exec_func(pco_iut, pco_tst, tst_addr, iut_s, tst_s, iut_addr,
                         func);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (tst_s != -1)
        CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
