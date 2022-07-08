/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-threaded_udp  Datagrams transmission with loaded threads
 *
 * @objective  Perform datagrams transmission while child threads repeatedly
 *             call an iomux function.
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func  Tested function which should be called in threads:
 *              - poll
 *              - epoll
 *              - select
 * @param threads_num   Threads number:
 *                      - 10
 * @param length        Data length to use in send() calls:
 *                      - 1000
 * @param connect_iut   Call connect() on IUT socket if @c TRUE.
 * @param bind_iut      Bind IUT socket if @c TRUE.
 * @param wildcard      Bind IUT socket to @c INADDR_ANY if @c TRUE, it makes
 *                      sense only if @p bind_iut is @c TRUE.
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/threaded_udp"

#include "sockapi-test.h"

/* Duration of data transmission. */
#define DURATION 2000

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server        **pco_iut_thr = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    struct sockaddr_storage wcard_addr;
    int                     threads_num;
    te_bool                 wildcard;
    te_bool                 bind_iut;
    const char             *func;
    int                     length;
    te_bool                 connect_iut;

    char name[32];
    int fdflags;
    int iut_s = -1;
    int tst_s = -1;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(length);
    TEST_GET_INT_PARAM(threads_num);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_BOOL_PARAM(bind_iut);
    TEST_GET_BOOL_PARAM(wildcard);

    if (wildcard)
    {
        tapi_sockaddr_clone_exact(iut_addr, SS(&wcard_addr));
        te_sockaddr_set_wildcard(SA(&wcard_addr));
    }

    TEST_STEP("Create TCP or UDP socket on tester and bind it.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Create TCP or UDP socket on IUT.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind it if @p bind_iut is @c TRUE to @c INADDR_ANY address "
              "if @p wildcard is @c TRUE.");
    if (bind_iut)
    {
        rpc_connect(pco_tst, tst_s, iut_addr);
        rpc_bind(pco_iut, iut_s, wildcard ? SA(&wcard_addr) : iut_addr);
    }

    TEST_STEP("Connect IUT socket if @p connect_iut is @c TRUE.");
    if (connect_iut)
        rpc_connect(pco_iut, iut_s, tst_addr);
    else if (!bind_iut)
    {
        fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, fdflags | RPC_O_NONBLOCK);
    }

    pco_iut_thr = te_calloc_fill(threads_num, sizeof(*pco_iut_thr), 0);

    TEST_STEP("Start @p threads_num new threads.");
    for (i = 0; i < threads_num; i++)
    {
        snprintf(name, sizeof(name), "thread%d", i);
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, name, &pco_iut_thr[i]));
    }

    TEST_STEP("Repeatedly call function @p func.");
    for (i = 0; i < threads_num; i++)
    {
        pco_iut_thr[i]->op = RCF_RPC_CALL;
        rpc_multiple_iomux(pco_iut_thr[i], iut_s, str2iomux(func),
                           RPC_POLLIN | RPC_POLLOUT, -1, -1, 1,
                           NULL, NULL, NULL);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Send packets from IUT if @p bind_iut is @c FALSE, else receive "
              "packets on IUT.");
    if (bind_iut || !connect_iut)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_many_recv(pco_iut, iut_s, length, -1, DURATION - 300, NULL, 0, TRUE, NULL);
        rpc_many_send_num(pco_tst, tst_s, length, -1, DURATION, TRUE, TRUE, NULL);
        rpc_many_recv(pco_iut, iut_s, length, -1, DURATION, NULL, 0, TRUE, NULL);
    }
    else
    {
        pco_tst->op = RCF_RPC_CALL;
        rpc_many_recv(pco_tst, tst_s, length, -1, DURATION - 300, NULL, 0, TRUE, NULL);
        rpc_many_send_num(pco_iut, iut_s, length, -1, DURATION, TRUE, TRUE, NULL);
        rpc_many_recv(pco_tst, tst_s, length, -1, DURATION, NULL, 0, TRUE, NULL);
    }

    TEST_SUCCESS;

cleanup:
    TEST_STEP("Stop child threads.");
    for (i = 0; i < threads_num; i++)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thr[i]));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(pco_iut_thr);

    /* It's a temporary solution to avoid problems due to resource leak
     * after thread cancellation in reuse_pco mode (Bug 9286) */
    rcf_rpc_server_restart(pco_iut);

    TEST_END;
}
