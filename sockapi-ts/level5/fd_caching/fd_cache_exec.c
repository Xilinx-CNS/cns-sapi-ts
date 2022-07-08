/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * FD caching
 * 
 * $Id$
 */

/** @page fd_caching-fd_cache_exec FD caching through execve
 *
 * @objective  Check cached FD handling through execve.
 *
 * @type conformance
 *
 * @param pco_iut       RPC server on iut node
 * @param pco_tst       RPC server on tester node
 *
 * @par Test sequence:
 *
 * @ref See bug 49048 for details.
 * 
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cache_exec"

#include "sockapi-test.h"
#include "fd_cache.h"

#define ACCEPT_NUM 10

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;

    te_bool close_after_exec;
    te_bool cloexec;
    int msl_timeout;
    int sockcache_contention;

    te_bool cached = TRUE;
    int iut_s = -1;
    int *tst_s = NULL;
    int *iut_acc = NULL;
    int i;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(cloexec);
    TEST_GET_BOOL_PARAM(close_after_exec);

    domain = rpc_socket_domain_by_addr(iut_addr);

    iut_acc = te_calloc_fill(ACCEPT_NUM, sizeof(*iut_acc), -1);
    tst_s = te_calloc_fill(ACCEPT_NUM, sizeof(*tst_s), -1);

    CHECK_RC(tapi_sh_env_get_int(pco_iut, "EF_TCP_TCONST_MSL", &msl_timeout));

    TEST_STEP("Open TCP socket.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    sockcache_contention = tapi_onload_get_stats_val(
                               pco_iut2,  "sockcache_contention");

    TEST_STEP("Bind it and move to the listening state.");
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, -1);

    TEST_STEP("Accept the connection request on the IUT side.");
    for (i = 0; i < ACCEPT_NUM; i++)
    {
        TEST_STEP("Open TCP socket on tester and connect it to IUT.");
        tst_s[i] = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s[i], iut_addr);

        iut_acc[i] = rpc_accept(pco_iut, iut_s, NULL, NULL);
        if (cloexec ? RPC_O_CLOEXEC : 0)
            rpc_fcntl(pco_iut, iut_acc[i], RPC_F_SETFD, FD_CLOEXEC, 1);
    }

    TEST_STEP("Close the accepted sockets now if @p close_after_exec "
              "is @c FALSE.");
    if (!close_after_exec)
    {
        for (i = 0; i < ACCEPT_NUM; i++)
        {
            sockts_pair_close_check(pco_iut, pco_tst, iut_acc[i], tst_s[i]);
            tst_s[i] = -1;
            cached &= tapi_onload_socket_is_cached(pco_iut, iut_acc[i]);
        }

        if (!tapi_onload_check_sockcache_contention(
                pco_iut2, sockcache_contention))
        {
            TEST_STOP;
        }

        if (!cached)
            TEST_VERDICT("One of accepted sockets was not cached");
    }

    TEST_STEP("Call execve().");
    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    TEST_STEP("Close the accepted sockets after execve if  @p close_after_exec "
              "is @c TRUE.");
    if (!cloexec && close_after_exec)
    {
        for (i = 0; i < ACCEPT_NUM; i++)
        {
            sockts_pair_close_check(pco_iut, pco_tst, iut_acc[i], tst_s[i]);
            tst_s[i] = -1;
        }
    }

    if (!tapi_onload_check_sockcache_contention(
            pco_iut2, sockcache_contention))
    {
        TEST_STOP;
    }

    TEST_STEP("Check that closed sockets will be cached.");
    cached = TRUE;

    for (i = 0; i < ACCEPT_NUM; i++)
        cached &= tapi_onload_socket_is_cached(pco_iut, iut_acc[i]);

    if (!cloexec && !close_after_exec)
    {
        if (!cached)
            TEST_VERDICT("At least one socket was not cached after exec");
    }
    else if (cached)
        TEST_VERDICT("At least one socket was cached after exec");

    TEST_STEP("Check that new accepted sockets will be cached.");
    cached = TRUE;
    for (i = 0; i < ACCEPT_NUM; i++)
    {
        tst_s[i] = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s[i], iut_addr);

        iut_acc[i] = rpc_accept(pco_iut, iut_s, NULL, NULL);
        sockts_pair_close_check(pco_iut, pco_tst, iut_acc[i], tst_s[i]);

        cached &= tapi_onload_socket_is_cached(pco_iut, iut_acc[i]);
        iut_acc[i] = -1;
        tst_s[i] = -1;
        if (!cached)
            break;
    }

    if (!tapi_onload_check_sockcache_contention(
            pco_iut2, sockcache_contention))
    {
        TEST_STOP;
    }

    if (!cached)
        TEST_VERDICT("At least one socket was not cached after exec");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    clean_sockets(pco_iut, iut_acc, ACCEPT_NUM);
    clean_sockets(pco_tst, tst_s, ACCEPT_NUM);

    TEST_END;
}
