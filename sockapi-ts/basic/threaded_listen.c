/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-threaded_listen  Open passive connection with charged multithreading
 *
 * @objective  Perform listen and continue passive connection opening while
 *             child threads repeatedly call an iomux function.
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
 * @param bind_iut      Bind IUT socket if @c TRUE.
 * @param wildcard      Bind IUT socket to @c INADDR_ANY if @c TRUE, it makes
 *                      sense only if @p bind_iut is @c TRUE.
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/threaded_listen"

#include "sockapi-test.h"

/* Duration of data transmission. */
#define DURATION 5000

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

    char name[32];
    int iut_s = -1;
    int tst_s = -1;
    int iut_aux = -1;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(threads_num);
    TEST_GET_BOOL_PARAM(wildcard);
    TEST_GET_BOOL_PARAM(bind_iut);

    if (wildcard)
    {
        tapi_sockaddr_clone_exact(iut_addr, SS(&wcard_addr));
        te_sockaddr_set_wildcard(SA(&wcard_addr));
    }

    TEST_STEP("Create TCP socket on tester and bind it.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Create TCP socket on IUT.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Bind it if @p bind_iut is @c TRUE to @c INADDR_ANY address "
              "if @p wildcard is @c TRUE.");
    if (bind_iut)
    {
        rpc_bind(pco_iut, iut_s, wildcard ? CONST_SA(&wcard_addr) :
                                            iut_addr);
    }

    pco_iut_thr = te_calloc_fill(threads_num, sizeof(*pco_iut_thr), 0);

    TEST_STEP("Start @p threads_num new threads.");
    for (i = 0; i < threads_num; i++)
    {
        snprintf(name, sizeof(name), "thread%d", i);
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, name, &pco_iut_thr[i]));
    }

    TEST_STEP("Repeatedly call function @p func in child threads.");
    for (i = 0; i < threads_num; i++)
    {
        pco_iut_thr[i]->op = RCF_RPC_CALL;
        rpc_multiple_iomux(pco_iut_thr[i], iut_s, str2iomux(func),
                           RPC_POLLIN | RPC_POLLOUT, -1, -1, 1,
                           NULL, NULL, NULL);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Call listen() on IUT.");
    rpc_listen(pco_iut, iut_s, -1);

    TEST_STEP("Try to connect from tester.");
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst_s, iut_addr);
    if (!bind_iut)
    {
        if (rc != -1 || RPC_ERRNO(pco_tst) != RPC_ECONNREFUSED)
            TEST_VERDICT("Connection attempt must fail");
    }
    else if (rc == -1)
        TEST_VERDICT("Connection attempt unexpectedly failed with %r",
                     RPC_ERRNO(pco_iut));
    else
    {
        TEST_STEP("Transmit data packet in both directions if connection is "
                  "established.");
        iut_aux = rpc_accept(pco_iut, iut_s, NULL, NULL);
        sockts_test_connection(pco_iut, iut_aux, pco_tst, tst_s);
    }

    TEST_STEP("Stop child threads.");
    for (i = 0; i < threads_num; i++)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thr[i]));

    if (bind_iut)
        sockts_test_connection(pco_iut, iut_aux, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_aux);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(pco_iut_thr);

    /* It's a temporary solution to avoid problems due to resource leak
     * after thread cancellation in reuse_pco mode (Bug 9286) */
    rcf_rpc_server_restart(pco_iut);

    TEST_END;
}
