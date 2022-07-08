/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Inheritance of fd flags after socket reincarnation
 */

/**
 * @page level5-fd_caching-fd_cache_inherit_flag Inheritance of fd flags after socket reincarnation
 *
 * @objective Check that reused active open socket does not inherit flags.
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer_two_iut
 *      - @ref arg_types_env_peer2peer_two_iut_ipv6
 * @param sock_flag Socket flag to set on IUT socket:
 *      - O_NONBLOCK
 *      - FD_CLOEXEC
 *
 * @par Scenario:
 *
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/fd_caching/fd_cache_inherit_flag"

#include "sockapi-test.h"
#include "fd_cache.h"


int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_iut2 = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rpc_socket_domain      domain;

    const char  *sock_flag;
    int          old_flags;

    int tst_s = -1;
    int iut_s = -1;
    int listener = -1;
    int reused_number;
    int sockcache_contention;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(sock_flag);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Generate active open TCP connection.");
    listener = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM,
                          RPC_PROTO_DEF);
    rpc_bind(pco_tst, listener, tst_addr);
    rpc_listen(pco_tst, listener, SOCKTS_BACKLOG_DEF);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_iut, iut_s, tst_addr);

    tst_s = rpc_accept(pco_tst, listener, NULL, NULL);

    sockcache_contention = tapi_onload_get_stats_val(
                               pco_iut2,  "sockcache_contention");

    TEST_STEP("Set @sock_flag to IUT socket.");
    if (strcmp(sock_flag, "O_NONBLOCK") == 0)
    {
        old_flags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, old_flags | RPC_O_NONBLOCK);
        if (!(rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK) &
              RPC_O_NONBLOCK))
            TEST_FAIL("Could not set O_NONBLOCK flag.");
    }
    else if (strcmp(sock_flag, "FD_CLOEXEC") == 0)
    {
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFD, 1);
        if (!rpc_fcntl(pco_iut, iut_s, RPC_F_GETFD, 0))
            TEST_FAIL("Could not set FD_CLOEXEC flag.");
    }
    else
    {
        TEST_FAIL("Incorrect value of 'sock_flag' parameter");
    }

    TEST_STEP("Close TCP connection and check that socket on IUT was cached.");
    reused_number = tapi_onload_get_stats_val(pco_iut2, "activecache_hit");

    sockts_pair_close_check(pco_iut, pco_tst, iut_s, tst_s);

    if (!tapi_onload_check_socket_caching(pco_iut, iut_s, pco_iut2,
                                          sockcache_contention))
    {
        RING_VERDICT("IUT socket was not cached");
    }

    TEST_STEP("Generate one more TCP connection.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_iut, iut_s, tst_addr);

    tst_s = rpc_accept(pco_tst, listener, NULL, NULL);

    TEST_STEP("Check that socket on IUT was reused.");
    if (tapi_onload_get_stats_val(
            pco_iut2, "activecache_hit") != (reused_number + 1))
    {
        RING_VERDICT("IUT socket was not reused after creating"
                     "the second connection.");
    }

    TEST_STEP("Check that IUT socket did not inherit flag from the first "
              "cached socket.");
    if (strcmp(sock_flag, "O_NONBLOCK") == 0)
    {
        if (rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK) &
            RPC_O_NONBLOCK)
            TEST_VERDICT("O_NONBLOCK flag is inherited by cached "
                         "socket.");
    }
    else if (rpc_fcntl(pco_iut, iut_s, RPC_F_GETFD, 0))
    {
        TEST_VERDICT("FD_CLOEXEC flag is inherited by cached socket.");
    }

    TEST_STEP("Close the TCP connection and check that socket now is cached.");
    sockts_pair_close_check(pco_iut, pco_tst, iut_s, tst_s);

    if (!tapi_onload_check_socket_caching(pco_iut, iut_s, pco_iut2,
                                          sockcache_contention))
    {
        TEST_VERDICT("Reused socket was not cached");
    }

    iut_s = -1;
    tst_s = -1;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, listener);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
