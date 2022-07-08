/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * FD caching
 */

/** @page fd_caching-fd_cache_limits Onload FD caching limits
 *
 * @objective  Exercise Onload FD caching limits which can be set with env
 *             EF_PER_SOCKET_CACHE_MAX and EF_SOCKET_CACHE_MAX, check that
 *             cached sockets number cannot exceed FD table size.
 *
 * @type conformance
 *
 * @param pco_iut                 PCO on IUT
 * @param pco_tst                 PCO on TESTER
 * @param ef_socket_cache_max     Set value to EF_SOCKET_CACHE_MAX if not @c -1
 * @param ef_per_socket_cache_max Set value to EF_PER_SOCKET_CACHE_MAX if not @c -1
 * @param hard_rlimit             Set value to EF_FDTABLE_SIZE if not @c -1
 * @param soft_rlimit             Set socket RLIMIT if not @c -1
 * @param open_way                Way to open socket for testing
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/fd_caching/fd_cache_limits"

#include "sockapi-test.h"
#include "fd_cache.h"


/** Determines active, passive or both connection opening ways */
typedef enum {
    ACTIVE = 0,      /**< Only active open */
    PASSIVE,         /**< Only passive open */
    BOTH,            /**< Passive and active open */
} opening;

#define SHARED_LOCAL_PORTS_EXCESS 10

#define OPENING_WAY  \
    { "active", ACTIVE },      \
    { "passive", PASSIVE },    \
    { "both", BOTH }

#define AWAIT_LIMIT_ERROR  \
    do {                                            \
        if (rlimit != -1 && rlimit < total_limit)   \
            RPC_AWAIT_IUT_ERROR(pco_iut);           \
    } while (0)

#define CHECK_FD_LIMIT(count, i, function, ...) \
    do {                                                             \
        if (RPC_ERRNO(pco_iut) != RPC_EMFILE)                        \
            TEST_VERDICT("%s() failed with unexpected errno %r",     \
                         #function, RPC_ERRNO(pco_iut));             \
                                                                     \
        rpc_close(pco_iut, iut_s[count]);                            \
        if (tst_s[i] != -1)                                          \
            RPC_CLOSE(pco_tst, tst_s[i]);                            \
                                                                     \
        if (tapi_onload_socket_is_cached(pco_iut, iut_s[count]))     \
            (count)++;                                               \
                                                                     \
        RPC_AWAIT_IUT_ERROR(pco_iut);                                \
        iut_s[i] = (function)(__VA_ARGS__);                          \
                                                                     \
        if (iut_s[i] != -1 || RPC_ERRNO(pco_iut) != RPC_EMFILE)      \
            TEST_VERDICT("FD table limit was achieved, %s() "        \
                         "must fail with EMFILE", #function);        \
    } while (0)

#define CHECK_FD_INCREASE(fd, prev_fd) \
    do {                                                            \
        if ((fd) < (prev))                                          \
            RING_VERDICT("Previous socket number is greater than "  \
                         "current one");                            \
                                                                    \
        (prev_fd) = (fd);                                           \
    } while (0)

int
main(int argc, char *argv[])
{
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int ef_socket_cache_max;
    int ef_per_socket_cache_max;
    int soft_rlimit;
    int hard_rlimit;

    tarpc_rlimit rlim;

    int *iut_s = NULL;
    int *tst_s = NULL;
    int  iut_ls = -1;
    int  tst_ls = -1;
    int  prev = 0;
    int  i = 0;
    int  num;
    int  active_limit = 0;
    int  passive_limit = 0;
    int  total_limit = 0;
    int  rlimit;
    int  count = 0;

    opening open_way;
    int iut_aux_s = -1;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(ef_socket_cache_max);
    TEST_GET_INT_PARAM(ef_per_socket_cache_max);
    TEST_GET_INT_PARAM(soft_rlimit);
    TEST_GET_INT_PARAM(hard_rlimit);
    TEST_GET_ENUM_PARAM(open_way, OPENING_WAY);

    domain = rpc_socket_domain_by_addr(iut_addr);

    if (ef_socket_cache_max == -1 && ef_per_socket_cache_max == -1)
    {
        TEST_FAIL("Iterations with such arguments are not supported");
    }
    else if (ef_socket_cache_max != -1)
    {
        if (open_way != PASSIVE)
            active_limit = ef_socket_cache_max;

        if (open_way != ACTIVE)
        {
            passive_limit = (ef_per_socket_cache_max == -1) ?
                             ef_socket_cache_max :
                             get_low_value(ef_socket_cache_max,
                                           ef_per_socket_cache_max);
        }
    }

    total_limit = active_limit + passive_limit;
    TEST_STEP("When @p ef_socket_cache_max is @c -1, make interations number "
              "equal to @c 2.to make sure that caching is disabled. "
              "In other cases make iterations number large enough "
              "to exceed the total fd cache limit.");
    num = total_limit == 0 ? 2 : total_limit * 2;

    rlimit = get_low_value(hard_rlimit, soft_rlimit);

    iut_s = te_calloc_fill(num, sizeof(*iut_s), -1);
    tst_s = te_calloc_fill(num, sizeof(*tst_s), -1);

    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_FDS_MT_SAFE", 1, TRUE, FALSE));

    TEST_STEP("Set FD table size in dependence on parameters @p hard_rlimit and "
              "@p soft_rlimit.");
    if (hard_rlimit != -1)
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_FDTABLE_SIZE",
                                     hard_rlimit, TRUE, FALSE));

    TEST_STEP("Set FD caching limit with env @c EF_SOCKET_CACHE_MAX equal to "
              "parameter @p ef_socket_cache_max value.");
    if (ef_socket_cache_max != -1)
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_SOCKET_CACHE_MAX",
                                     ef_socket_cache_max, TRUE, FALSE));
    else
        tapi_sh_env_unset(pco_iut, "EF_SOCKET_CACHE_MAX", TRUE, FALSE);

    TEST_STEP("Set FD caching limit per socket with env @c EF_PER_SOCKET_CACHE_MAX "
              "equal to parameter @p ef_per_socket_cache_max value.");
    if (ef_per_socket_cache_max != -1)
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_PER_SOCKET_CACHE_MAX",
                                     ef_per_socket_cache_max, TRUE, FALSE));
    else
        tapi_sh_env_unset(pco_iut, "EF_PER_SOCKET_CACHE_MAX", TRUE, FALSE);

    if (active_limit != 0)
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_TCP_SHARED_LOCAL_PORTS",
                                     active_limit + SHARED_LOCAL_PORTS_EXCESS,
                                     TRUE, false));
    rcf_rpc_server_restart(pco_iut);

    TEST_STEP("Open listening TCP sockets.");
    if (open_way != ACTIVE)
        iut_ls = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    if (open_way != PASSIVE)
        tst_ls = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Set RLIMITs in accordance to @p soft_rlimit and @p hard_rlimit.");
    if (soft_rlimit != -1)
    {
        memset(&rlim, 0, sizeof(rlim));
        rlim.rlim_max = hard_rlimit == -1 ? (soft_rlimit + 50) : hard_rlimit;
        rlim.rlim_cur = soft_rlimit;
        rpc_setrlimit(pco_iut, RPC_RLIMIT_NOFILE, &rlim);
    }

    TEST_STEP("Call @b bind() and @b listen() on the IUT and tester "
              "in accordance with @p open_way");
    if (open_way != ACTIVE)
    {
        rpc_bind(pco_iut, iut_ls, iut_addr);
        rpc_listen(pco_iut, iut_ls, -1);
    }
    if (open_way != PASSIVE)
    {
        rpc_bind(pco_tst, tst_ls, tst_addr);
        rpc_listen(pco_tst, tst_ls, -1);
    }

    TEST_STEP("Generate TCP conections in accordance with @p open_way "
              "Iterations number is enough to achieve the cache or FD table limit.");
    while (i < num)
    {
        TEST_STEP("Cached sockets number must not exceeed FD table size and "
                  "should be monotonically increased.");
        if (open_way != ACTIVE)
        {
            tst_s[i] = rpc_socket(pco_tst, domain,
                                  RPC_SOCK_STREAM, RPC_PROTO_DEF);
            rpc_connect(pco_tst, tst_s[i], iut_addr);

            AWAIT_LIMIT_ERROR;
            iut_s[i] = rpc_accept(pco_iut, iut_ls, NULL, NULL);

            if (iut_s[i] < 0)
            {
                CHECK_FD_LIMIT(count, i, rpc_accept, pco_iut, iut_ls,
                               NULL, NULL);
                break;
            }

            CHECK_FD_INCREASE(iut_s[i], prev);

            i++;
        }

        if (open_way != PASSIVE)
        {
            AWAIT_LIMIT_ERROR;
            iut_s[i] = rpc_socket(pco_iut, domain,
                                  RPC_SOCK_STREAM, RPC_PROTO_DEF);
            if (iut_s[i] < 0)
            {
                CHECK_FD_LIMIT(count, i, rpc_socket, pco_iut, domain,
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
                break;
            }

            AWAIT_LIMIT_ERROR;
            if (rpc_connect(pco_iut, iut_s[i], tst_addr) < 0)
            {
                CHECK_FD_LIMIT(count, i, rpc_connect, pco_iut, iut_s[i],
                               tst_addr);
                break;
            }
            tst_s[i] = rpc_accept(pco_tst, tst_ls, NULL, NULL);

            CHECK_FD_INCREASE(iut_s[i], prev);

            i++;
        }
    }
    num = i;

    TEST_STEP("Close the sockets on IUT and calculate how many of them was "
              "cached.");
    for (i = 0; i < num; i++)
    {
        sockts_pair_close_check(pco_iut, pco_tst, iut_s[i], tst_s[i]);
        if (tapi_onload_socket_is_cached(pco_iut, iut_s[i]))
            count++;
    }

    RING("Cached sockets number %d, total limit %d, rlimit %d,"
         " total conections %d", count, total_limit, rlimit, num);

    if (rlimit != -1 && rlimit < total_limit)
    {
        if (count > rlimit)
            TEST_VERDICT("Cached sockets number %d exceeds FD table "
                         "size %d", count, rlimit);

        TEST_STEP("Try to open a new socket and make sure it is successful.");
        RPC_AWAIT_IUT_ERROR(pco_iut);
        iut_aux_s = rpc_socket(pco_iut, domain,
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
        if (iut_aux_s < 0)
        {
            TEST_VERDICT("Failed to create a new socket after closing"
                         " all the others");
        }
        RPC_CLOSE(pco_iut, iut_aux_s);
    }
    else if (count != total_limit)
        TEST_VERDICT("Cached sockets number is %d instead of %d, total "
                     "conections number %d", count, total_limit, num);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_ls);
    CLEANUP_RPC_CLOSE(pco_iut, iut_aux_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_ls);

    free(iut_s);
    free(tst_s);

    TEST_END;
}
