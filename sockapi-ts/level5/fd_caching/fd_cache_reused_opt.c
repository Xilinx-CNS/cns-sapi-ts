/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * FD caching
 */

/** @page fd_caching-fd_cache_reused_opt Socket option inheritance after reincarnation
 *
 * @objective  Check that reused accepted socket inherits correct socket
 *             option value.
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer_two_iut
 *      - @ref arg_types_env_peer2peer_two_iut_ipv6
 * @param opt_name Socket option to set on IUT socket:
 *      - SO_KEEPALIVE
 *      - TCP_KEEPCNT
 *      - TCP_KEEPIDLE
 *      - TCP_KEEPINTVL
 *      - SO_LINGER
 *
 * @par Scenario:
 *
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cache_reused_opt"

#include "sockapi-test.h"
#include "tapi_mem.h"
#include "fd_cache.h"

#define MAX_LINGER 10
#define MAX_OPT_LEN IFNAMSIZ

#define SOCKOPT \
    {"SO_BINDTODEVICE", RPC_SO_BINDTODEVICE},   \
    {"SO_KEEPALIVE", RPC_SO_KEEPALIVE},         \
    {"TCP_KEEPCNT", RPC_TCP_KEEPCNT},           \
    {"TCP_KEEPIDLE", RPC_TCP_KEEPIDLE},         \
    {"TCP_KEEPINTVL", RPC_TCP_KEEPINTVL},       \
    {"TCP_MAXSEG", RPC_TCP_MAXSEG},             \
    {"SO_LINGER_ZERO", RPC_SO_LINGER},          \
    {"SO_LINGER_NON_ZERO", RPC_SO_LINGER}

/**
 * Get value of @p opt_name socket option and compare it with
 * given value.
 *
 * @param rpcs          RPC server
 * @param s             Socket to get option
 * @param opt_name      Tested option
 * @param value         Value to compare
 * @param value_len     Length of value to compare
 *
 * @return @c TRUE if values are equal, @c FALSE otherwise
 */
static te_bool
get_compare_opt_value(rcf_rpc_server *rpcs, int s, rpc_sockopt opt_name,
                      const void *value, socklen_t value_len)
{
    void    *opt_val = NULL;
    te_bool  result = FALSE;

    socklen_t opt_val_len = MAX_OPT_LEN;

    opt_val = te_calloc_fill(1, MAX_OPT_LEN, 0);

    if (opt_name == RPC_SO_BINDTODEVICE)
        rpc_getsockopt_raw(rpcs, s, opt_name, opt_val, &opt_val_len);
    else
        rpc_getsockopt(rpcs, s, opt_name, opt_val);

    switch (opt_name)
    {
        case RPC_SO_KEEPALIVE:
        case RPC_TCP_KEEPCNT:
        case RPC_TCP_KEEPIDLE:
        case RPC_TCP_KEEPINTVL:
        case RPC_TCP_MAXSEG:
            result = (*(int *)opt_val == *(int *)value) ? TRUE : FALSE;
            break;
        case RPC_SO_LINGER:
            result = ((*(tarpc_linger *)opt_val).l_onoff ==
                      (*(tarpc_linger *)value).l_onoff) &&
                      ((*(tarpc_linger *)opt_val).l_linger ==
                      (*(tarpc_linger *)value).l_linger) ? TRUE : FALSE;
            break;
        case RPC_SO_BINDTODEVICE:
            if (value_len == opt_val_len &&
                memcmp(opt_val, value, opt_val_len) == 0)
            {
                result = TRUE;
            }
            else
            {
                result = FALSE;
            }
            break;

        default:
            TEST_FAIL("Test does not support option %s",
                      sockopt_rpc2str(opt_name));
    }

    free(opt_val);

    return result;
}

/**
 * Get value of @p opt_name socket option and set a new value
 * different from the first one.
 *
 * @param rpcs              RPC server
 * @param iut_if            IUT interface name, if it's necessary
 * @param s                 Socket to get option
 * @param opt_name          Tested option
 * @param val               Auxiliary value, if it's necessary
 * @param[out] optval_len   New option value length
 */
static void *
change_opt_value(rcf_rpc_server *rpcs, const struct if_nameindex *iut_if,
                 int s, rpc_sockopt opt_name, int val, socklen_t *optval_len)
{
    void *opt_val = NULL;
    void *old_opt_val = NULL;

    socklen_t opt_val_len = MAX_OPT_LEN;
    socklen_t old_opt_val_len = MAX_OPT_LEN;

    opt_val = te_calloc_fill(1, MAX_OPT_LEN, 0);
    old_opt_val = te_calloc_fill(1, MAX_OPT_LEN, 0);

    switch (opt_name)
    {
        case RPC_SO_KEEPALIVE:
        case RPC_TCP_KEEPCNT:
        case RPC_TCP_KEEPIDLE:
        case RPC_TCP_KEEPINTVL:
        case RPC_TCP_MAXSEG:
            rpc_getsockopt(rpcs, s, opt_name, old_opt_val);
            *(int *)opt_val = *(int *)old_opt_val + 1;
            break;
        case RPC_SO_LINGER:
                (*(tarpc_linger *)opt_val).l_onoff = 1;
                if (val == 0)
                    (*(tarpc_linger *)opt_val).l_linger = 0;
                else
                    (*(tarpc_linger *)opt_val).l_linger = rand_range(
                        1, MAX_LINGER);
            break;
        case RPC_SO_BINDTODEVICE:
            rpc_getsockopt_raw(rpcs, s, opt_name, old_opt_val,
                               &old_opt_val_len);
            if (old_opt_val_len == 0)
            {
                strcpy(opt_val, iut_if->if_name);
                opt_val_len = strlen((const char *)opt_val) + 1;
            }
            else
            {
                opt_val_len = 0;
            }
            *optval_len = opt_val_len;
            break;

        default:
            TEST_FAIL("Test does not support option %s",
                      sockopt_rpc2str(opt_name));
    }

    if (opt_name == RPC_SO_BINDTODEVICE)
        rpc_setsockopt_raw(rpcs, s, opt_name, opt_val, opt_val_len);
    else
        rpc_setsockopt(rpcs, s, opt_name, opt_val);

    free(old_opt_val);

    return opt_val;
}

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_iut2 = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rpc_sockopt            opt_name;
    rpc_socket_domain      domain;

    const struct if_nameindex *iut_if;

    int   tst_s = -1;
    int   iut_s = -1;
    int   listener = -1;
    int   reused_number;
    int   aux_val = 0;
    void *val = NULL;
    int sockcache_contention;

    socklen_t val_len = MAX_OPT_LEN;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_ENUM_PARAM(opt_name, SOCKOPT);

    domain = rpc_socket_domain_by_addr(iut_addr);

    if (opt_name == RPC_SO_LINGER)
    {
        const char *opt_name;
        TEST_GET_STRING_PARAM(opt_name);

        if (strcmp(opt_name, "SO_LINGER_NON_ZERO") == 0)
            aux_val = 1;
    }

    TEST_STEP("Generate active open TCP connection.");
    listener = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM,
                          RPC_PROTO_DEF);
    rpc_bind(pco_tst, listener, tst_addr);
    rpc_listen(pco_tst, listener, SOCKTS_BACKLOG_DEF);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_iut, iut_s, tst_addr);

    sockcache_contention = tapi_onload_get_stats_val(
                               pco_iut2,  "sockcache_contention");

    tst_s = rpc_accept(pco_tst, listener, NULL, NULL);

    TEST_STEP("Set socket option @p opt_name.");
    val = change_opt_value(pco_iut, iut_if, iut_s, opt_name, aux_val,
                           &val_len);

    TEST_STEP("Close TCP connection and check that socket on IUT was cached.");
    reused_number = tapi_onload_get_stats_val(pco_iut2, "activecache_hit");

    sockts_pair_close_check(pco_iut, pco_tst, iut_s, tst_s);

    /*
     * There is no reason to continue the test in case the
     * socket isn't cached.
     */
    if (!tapi_onload_check_socket_caching(pco_iut, iut_s, pco_iut2,
                                          sockcache_contention))
    {
        TEST_VERDICT("IUT socket was not cached");
    }

    TEST_STEP("Generate one more open TCP connection.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_iut, iut_s, tst_addr);

    tst_s = rpc_accept(pco_tst, listener, NULL, NULL);

    TEST_STEP("Check that socket on IUT was reused.");
    if (tapi_onload_get_stats_val(
            pco_iut2, "activecache_hit") != (reused_number + 1))
    {
        RING_VERDICT("IUT socket was not reused after creating"
                     " the second connection");
    }

    TEST_STEP("Check that IUT socket did not inherit option value from "
              "the first cached socket.");
    if (get_compare_opt_value(pco_iut, iut_s, opt_name, val, val_len))
        RING_VERDICT("Socket option value is inherited from cached socket");

    TEST_STEP("Close the TCP conection.");
    sockts_pair_close_check(pco_iut, pco_tst, iut_s, tst_s);

    if (!tapi_onload_check_socket_caching(pco_iut, iut_s, pco_iut2,
                                          sockcache_contention))
    {
        RING_VERDICT("Reused socket was not cached");
    }

    iut_s = -1;
    tst_s = -1;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, listener);

    free(val);

    TEST_END;
}
