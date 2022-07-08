/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * FD caching
 */

/** @page fd_caching-fd_cache_shutdown_reuse Shutdown socket and try reuse it
 *
 * @objective  Try to reuse socket after calling shutdown().
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer_two_iut
 *                          - @ref arg_types_env_peer2peer_two_iut_ipv6
 * @param shutdown_how      Action which should be performed by @b shutdown():
 *                          - SHUT_RD
 *                          - SHUT_WR
 *                          - SHUT_RDWR
 * @param close_tst         Close tester socket after shutdown if @c TRUE
 * @param close_iut         Close IUT socket after shutdown if @c TRUE
 * @param close_iut_later   Close IUT socket after 2*MSL seconds after
 *                          shutdown if @C TRUE
 * @param cache_socket      Create cached socket to be reused if @c TRUE
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "fd_caching/fd_cache_shutdown_reuse"

#include "sockapi-test.h"
#include "fd_cache.h"

int
main(int argc, char *argv[])
{
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rpc_shut_how shutdown_how;
    te_bool cache_socket;
    te_bool close_tst;
    te_bool close_iut;
    te_bool close_iut_later;
    te_bool cached;
    int msl_timeout;
    int sockcache_contention;

    char buf[1];

    int iut_s = -1;
    int iut_l = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SHUT_HOW(shutdown_how);
    TEST_GET_BOOL_PARAM(close_tst);
    TEST_GET_BOOL_PARAM(close_iut);
    TEST_GET_BOOL_PARAM(close_iut_later);
    TEST_GET_BOOL_PARAM(cache_socket);

    TEST_STEP("Create TCP listener on IUT.");
    iut_l = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_l, iut_addr);
    rpc_listen(pco_iut, iut_l, -1);

    sockcache_contention = tapi_onload_get_stats_val(
                               pco_iut2,  "sockcache_contention");

    CHECK_RC(tapi_sh_env_get_int(pco_iut, "EF_TCP_TCONST_MSL", &msl_timeout));

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, iut_l,
                                FALSE, cache_socket);

    TEST_STEP("Connect from the tester and receive connection on IUT");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, iut_addr);
    iut_s = rpc_accept(pco_iut, iut_l, NULL, NULL);

    TEST_STEP("Shutdown IUT socket.");
    rpc_shutdown(pco_iut, iut_s, shutdown_how);

    TEST_STEP("Close tester socket if @p close_tst is @c TRUE");
    if (close_tst)
        RPC_CLOSE(pco_tst, tst_s);

    TEST_STEP("Close IUT socket now or later in dependence on @p close_iut_later "
              "and if @p close_iut is @c TRUE.");
    if (close_iut && !close_iut_later)
    {
        if (close_tst && rpc_read(pco_iut, iut_s, buf, 1) != 0)
        {
            TEST_FAIL("read() call returned non-zero value after"
                      "peer socket closing");
        }

        rpc_close(pco_iut, iut_s);
    }

    TEST_STEP("Sleep (2MSL + 1) seconds while  IUT socket can be in TIME_WAIT "
              "state.");
    SLEEP(msl_timeout * 2 + 1);

    TEST_STEP("Close IUT socket now if both @p close_iut_later and @p close_iut "
              "are @c TRUE.");
    if (close_iut && close_iut_later)
        rpc_close(pco_iut, iut_s);

    TEST_STEP("Check if the socket was cached or not.");
    cached = tapi_onload_socket_is_cached(pco_iut, iut_s);

    if (close_iut &&
        !(close_iut_later && close_tst &&
          (shutdown_how == RPC_SHUT_WR || shutdown_how == RPC_SHUT_RDWR)))
    {
        if(!cached)
            RING_VERDICT("Socket was not cached");
    }
    else if (cached)
        RING_VERDICT("Socket was unexpectedly cached");

    TEST_STEP("Try to reuse socket if it was cached.");
    if (!close_iut && !close_tst)
    {
        sockts_pair_close_check(pco_iut, pco_tst, iut_s, tst_s);
        sockts_tcp_check_cache_reuse(pco_iut, pco_iut2, pco_tst, iut_addr, tst_addr,
                                     iut_l, iut_s, FALSE);
        iut_s = -1;
        tst_s = -1;
    }
    else
        sockts_tcp_check_cache_reuse(pco_iut, pco_iut2, pco_tst, iut_addr, tst_addr,
                                     iut_l, -1, FALSE);

    if (!tapi_onload_check_sockcache_contention(
            pco_iut2, sockcache_contention))
    {
        TEST_STOP;
    }

    TEST_SUCCESS;

cleanup:
    RPC_AWAIT_IUT_ERROR(pco_iut);
    RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
