/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * FD caching
 */

/** @page fd_caching-fd_cache_nonblock_sync Sync of nonblocking state through cache
 *
 * @objective  Check that Onload retains knowledge of nonblock sync state after
 *             trip through cache.
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer_two_iut
 *                        - @ref arg_types_env_peer2peer_two_iut_ipv6
 * @param use_libc        Whether to use the libc to call a test function
 * @param check_first     Check nonblocking state after first trip through cache
 * @param nonblock_func   Function to set nonblocking state:
 *                        - @b accept4()
 *                        - @b fcntl()
 *                        - @b ioctl()
 * @param nonblock_first  Whether to set nonblocking state first:
 *                        - @c TRUE:  Set nonblocking before caching
 *                        - @c FALSE: Request nonblocking socket on @b accept4()
 *                                    to get it from the cache
 * @param func            Name of function to be tested:
 *                        - read()
 *                        - readv()
 *                        - write()
 *                        - writev()
 *
 * @par Scenario:
 *
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/fd_caching/fd_cache_nonblock_sync"

#include "sockapi-test.h"
#include "fd_cache.h"

/** Number of trips through cache to check sync */
#define INTER_NUM 3

/** Size of data to transmit */
#define DATA_SIZE 1024

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_iut2 = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rpc_socket_domain      domain;
    void                  *func = NULL;
    te_bool                is_send = FALSE;
    te_bool                use_libc;
    te_bool                check_first;
    te_bool                nonblock_first;

    int  tst_s = -1;
    int  iut_s = -1;
    int  listener = -1;
    int  sockcache_contention;
    int  reused_number;
    int  i;

    fdflag_set_func_type_t nonblock_func = UNKNOWN_SET_FDFLAG;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_FDFLAG_SET_FUNC(nonblock_func);
    TEST_GET_BOOL_PARAM(use_libc);
    TEST_GET_BOOL_PARAM(check_first);
    TEST_GET_BOOL_PARAM(nonblock_first);
    TEST_GET_FUNC(func, is_send);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Generate passive open TCP connection.");
    listener = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM,
                          RPC_PROTO_DEF);
    rpc_bind(pco_iut, listener, iut_addr);
    rpc_listen(pco_iut, listener, SOCKTS_BACKLOG_DEF);

    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Accept a connection and make the socket non-blocking "
              "if @p nonblock_first.");
    if ((nonblock_func == ACCEPT4_SET_FDFLAG) && nonblock_first)
        iut_s = rpc_accept4(pco_iut, listener, NULL, NULL, RPC_SOCK_NONBLOCK);
    else
        iut_s = rpc_accept(pco_iut, listener, NULL, NULL);

    sockcache_contention = tapi_onload_get_stats_val(
                               pco_iut2, "sockcache_contention");

    if ((nonblock_func == IOCTL_SET_FDFLAG) && nonblock_first)
    {
        int nblock = 1;

        rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &nblock);
    }
    else if ((nonblock_func == FCNTL_SET_FDFLAG) && nonblock_first)
    {
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);
    }

    TEST_STEP("Generate and close @c INTER_NUM connections to "
              "check blocking state of reused sockets.");
    for (i = 0; i < INTER_NUM; i++)
    {
        TEST_SUBSTEP("Close previous TCP connection and check that socket "
                     "on IUT was cached.");
        reused_number = tapi_onload_get_stats_val(pco_iut2,
                                                  "sockcache_hit");

        sockts_pair_close_check(pco_iut, pco_tst, iut_s, tst_s);

        if (!tapi_onload_check_socket_caching(pco_iut, iut_s, pco_iut2,
                                              sockcache_contention))
        {
           RING_VERDICT("IUT socket was not cached");
        }

        TEST_SUBSTEP("Generate one more passive TCP connection.");
        tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s, iut_addr);

        TEST_SUBSTEP("Get nonblocking accepted socket if @p nonblock_func "
                     "is @b accept4() and @p nonblock_first is @c FALSE.");
        if ((nonblock_func == ACCEPT4_SET_FDFLAG) && !nonblock_first)
            iut_s = rpc_accept4(pco_iut, listener, NULL, NULL, RPC_SOCK_NONBLOCK);
        else
            iut_s = rpc_accept(pco_iut, listener, NULL, NULL);

        TEST_SUBSTEP("Check that socket on IUT was reused.");
        if (tapi_onload_get_stats_val(
               pco_iut2, "sockcache_hit") != (reused_number + 1))
        {
           RING_VERDICT("IUT socket was not reused after creating "
                        "the new connection.");
        }

        TEST_SUBSTEP("Check blocking state of the socket from cache using "
                     "@b func depending on iter number and @p check_first.");
        if (check_first || (i > 0))
        {
            if (is_send)
                rpc_overfill_buffers(pco_iut, iut_s, NULL);

            pco_iut->use_libc = use_libc;
            sockts_check_blocking(pco_iut, pco_tst, func, is_send, iut_s,
                                  tst_s, nonblock_first, DATA_SIZE,
                                  "Socket was reused %d times", i + 1);
            pco_iut->use_libc = FALSE;

            if (is_send && !nonblock_first)
                rpc_drain_fd_simple(pco_tst, tst_s, NULL);
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, listener);

    TEST_END;
}

