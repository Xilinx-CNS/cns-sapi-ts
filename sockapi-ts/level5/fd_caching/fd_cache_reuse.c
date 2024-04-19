/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * FD caching
 */

/** @page fd_caching-fd_cache_reuse  Exercise cached sockets reusing
 *
 * @objective  Accept and close TCP sockets many times with a few listeners,
 *             total opened/closed sockets number should be at least greater
 *             than EF_SOCKET_CACHE_MAX.
 *
 * @type conformance
 *
 * @param pco_iut                    PCO on IUT
 * @param pco_tst                    PCO on TESTER
 * @param thread_process             Create listener sockets in defferent thread or
 *                                   process
 * @param listener_num               Listener sockets number
 * @param ef_socket_cache_max        Set value to EF_SOCKET_CACHE_MAX if not @c -1
 * @param ef_per_socket_cache_max    Set value to EF_PER_SOCKET_CACHE_MAX if not @c -1
 * @param iter_num                   Iterations number
 * @param active                     Way to open socket for testing
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/fd_caching/fd_cache_reuse"

#include "sockapi-test.h"
#include "fd_cache.h"

/* FD table size, the value has to be big enough taking in to account
 * values of the prologue arguments @b ef_socket_cache_max and
 * @b ef_per_socket_cache_max. */
#define FD_TABLE    25100

/**
 * Use different process or thread for the socket
 */
typedef enum {
    TP_NONE = 0,        /**< Sockets in single thread */
    TP_THREAD,          /**< Sockets in different threads */
    TP_PROCESS,         /**< Sockets in different processes */
} thread_process_type;

#define THREAD_PROCESS  \
    { "none", TP_NONE },       \
    { "thread", TP_THREAD },   \
    { "process", TP_PROCESS }


typedef struct server_ctx {
    rcf_rpc_server  *rpcs;
    struct sockaddr *addr;
    rpc_ptr          handle;
    int              listener;
    int              num;
} server_ctx;

typedef struct client_ctx {
    rcf_rpc_server  *rpcs;
    rpc_ptr          handle;
} client_ctx;


/**
 * Close sockets array and free it.
 * 
 * @param sock  Pointer to the sockets array
 * @param num   Sockets number
 */
static void
clean_server_ctx(struct server_ctx *server_ctx, int num)
{
    int i;

    if (server_ctx == NULL)
        return;

    for (i = 0; i < num; i++)
    {
        if (server_ctx[i].rpcs == NULL)
            break;
        rpc_close(server_ctx[i].rpcs, server_ctx[i].listener);
    }

    free(server_ctx);
}

/**
 * Get @b sockcache_contention value from Onload stackdump.
 *
 * @param rpcs  RPC server
 *
 * @return @b sockcache_contention value
 */
static int
get_sockcache_contention(rcf_rpc_server *rpcs)
{
    int num = 0;
    char *buf = NULL;
    char *ptr;

    rpc_shell_get_all(rpcs, &buf, "te_onload_stdump lots | grep sockcache_contention", -1);
    if (buf != NULL)
    {
        RING("%s", buf);
        if ((ptr = strchr(buf, ' ')) == NULL)
            TEST_FAIL("Couldn't parse sockcache_contention value");

        num = atoi(ptr);
        free(buf);
    }
    else
        TEST_VERDICT("Failed to get sockcache_contention value");

    return num;
}

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    struct sockaddr       *addr = NULL;
    rcf_rpc_server        *pco_iut = NULL;

    /* FIXME: Remove pco_iut2 when debug is finished. */
    rcf_rpc_server     *pco_iut2 = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    thread_process_type thread_process = TP_NONE;
    rpc_socket_domain   domain;

    te_bool active;
    int     ef_socket_cache_max;
    int     ef_per_socket_cache_max;
    int     msl_timeout;
    int     listener_num = 0;
    int     iter_num;

    client_ctx *client = NULL;
    server_ctx *server = NULL;
    char proc_name[32] = {0};
    int aux_s = -1;
    int aux_acc_s = -1;

    int cached;
    int total = 0;
    int total_i = 0;
    int limit;
    int iter;
    int num;
    int i;

    te_bool disable_caching;

    const char     *ef_poll_usec = getenv("EF_POLL_USEC");
    const char     *ef_int_driven = getenv("EF_INT_DRIVEN");
    te_bool         int_or_non_spin = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(ef_socket_cache_max);
    TEST_GET_INT_PARAM(ef_per_socket_cache_max);
    TEST_GET_INT_PARAM(listener_num);
    TEST_GET_INT_PARAM(iter_num);
    TEST_GET_ENUM_PARAM(thread_process, THREAD_PROCESS);
    TEST_GET_BOOL_PARAM(disable_caching);
    TEST_GET_BOOL_PARAM(active);

    domain = rpc_socket_domain_by_addr(iut_addr);

    if (ef_poll_usec == NULL)
        int_or_non_spin = TRUE;
    else if (ef_int_driven != NULL && strcmp(ef_int_driven, "1") == 0)
        int_or_non_spin = TRUE;

    if (active)
        limit = ef_socket_cache_max;
    else
        limit = get_low_value(ef_socket_cache_max, ef_per_socket_cache_max);
    /*
     * In case of int-driven Onload it may fail to cache sockets because of
     * stack lock contention, see sockcache_contention value in stackdump.
     * It is OK from the test's point of view, so we create more sockets to
     * occupy all the available cache entries.
     */
    if (int_or_non_spin)
        num = limit * 5;
    else
        num = limit + 100;

    client = te_calloc_fill(listener_num, sizeof(*client), 0);
    server = te_calloc_fill(listener_num, sizeof(*server), 0);
    addr = te_calloc_fill(listener_num, sizeof(struct sockaddr_storage), 0);

    CHECK_RC(tapi_sh_env_get_int(pco_iut, "EF_TCP_TCONST_MSL", &msl_timeout));

    /* If @p disable_caching is @c TRUE - disable fd caching. */
    if (disable_caching)
    {
        CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_SOCKET_CACHE_MAX", FALSE,
                                   FALSE));
        CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_PER_SOCKET_CACHE_MAX", FALSE,
                                   FALSE));
    }
    else
    {
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_SOCKET_CACHE_MAX",
                                     ef_socket_cache_max, TRUE, FALSE));
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_PER_SOCKET_CACHE_MAX",
                                     ef_per_socket_cache_max, TRUE, FALSE));
    }

    if (active)
    {
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_TCP_SHARED_LOCAL_PORTS_MAX",
                                     3 * num, TRUE, FALSE));
    }
    else if (cfg_find_fmt(NULL, "/agent:%s/env:EF_CLUSTER_NAME",
                          pco_iut->ta) == 0)
    {
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                     listener_num, TRUE, FALSE));
    }

    TEST_STEP("Increase FD table size to avoid overfilling.");
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_MAX_ENDPOINTS",
                                 FD_TABLE, TRUE, FALSE));
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_FDTABLE_SIZE",
                                 FD_TABLE, TRUE, TRUE));

    sockts_inc_rlimit(pco_iut, RPC_RLIMIT_NOFILE, FD_TABLE);
    sockts_inc_rlimit(pco_tst, RPC_RLIMIT_NOFILE, FD_TABLE);

    TAPI_SYS_LOGLEVEL_DEBUG(pco_iut2, NULL);

    TEST_STEP("Create new threads or processes according to @p thread_process");
    for (i = 0; i < listener_num; i++)
    {
        if (thread_process == TP_NONE)
        {
            server[i].rpcs = active ? pco_tst : pco_iut;
            client[i].rpcs = active ? pco_iut : pco_tst;
        }
        else
        {
            snprintf(proc_name, sizeof(proc_name), "pco_%s_child%d",
                     active ? "tst" : "iut", i);

            if (thread_process == TP_THREAD)
                CHECK_RC(rcf_rpc_server_thread_create(
                    active ? pco_tst : pco_iut, proc_name, &server[i].rpcs));
            else
                CHECK_RC(rcf_rpc_server_fork(
                    active ? pco_tst : pco_iut, proc_name, &server[i].rpcs));

            client[i].rpcs = active ? pco_iut : pco_tst;
        }
    }


    TEST_STEP("Open the number @p listener_num listener sockets in the single "
              "thread, different threads or different processes in dependence "
              "on @p thread_process.");
    for (i = 0; i < listener_num; i++)
    {
        server[i].listener = rpc_socket(server[i].rpcs, domain,
                                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

        server[i].addr = SA(SS(addr) + i);
        tapi_sockaddr_clone_exact(active ? tst_addr : iut_addr,
                                  SS(server[i].addr));
        TAPI_SET_NEW_PORT(server[i].rpcs, server[i].addr);

        rpc_bind(server[i].rpcs, server[i].listener, server[i].addr);
        rpc_listen(server[i].rpcs, server[i].listener, -1);
    }

    TEST_STEP("Repeat the following action @p iter_num iterations:");
    for (iter = 0; iter < iter_num; iter++)
    {
        total_i = 0;
        TEST_STEP("Generate a lot of connections (more than cache limit) on the "
                  "opened listener sockets.");
        for (i = 0; i < listener_num; i++)
        {
            server[i].rpcs->timeout = 100000;
            server[i].rpcs->op = RCF_RPC_CALL;
            rpc_many_accept(server[i].rpcs, server[i].listener, num,
                            1, 128, NULL, NULL, &server[i].handle);

            client[i].rpcs->timeout = 300000;
            RPC_AWAIT_ERROR(client[i].rpcs);
            rc = rpc_many_connect(client[i].rpcs, server[i].addr, num, 1, 128,
                                  NULL, NULL, &client[i].handle);
            if (rc < 0)
            {
                ERROR("Listener #%d: many_connect() failed: %r", i,
                      RPC_ERRNO(client[i].rpcs));
                TEST_VERDICT("many_connect() call failed with error %r",
                             RPC_ERRNO(client[i].rpcs));
            }

            server[i].num = rpc_many_accept(server[i].rpcs,
                server[i].listener, num, 1, 128, NULL, NULL,
                &server[i].handle);
            if (server[i].num != num)
                TEST_FAIL("Opened sockets number is less than requested one");
        }

        TEST_STEP("Close the connections and calculate how much sockets were "
                  "cached.");
        for (i = 0; i < listener_num; i++)
        {
            rpc_many_close_cache(
                active ? client[i].rpcs : server[i].rpcs,
                active ? client[i].handle : server[i].handle,
                num, &cached);
            total_i += cached;
            server[i].num = 0;
            rpc_many_close(
                active ? server[i].rpcs : client[i].rpcs,
                active ? server[i].handle : client[i].handle, num);
            server[i].handle = RPC_NULL;
            client[i].handle = RPC_NULL;
        }

        if (!disable_caching && total_i < ef_socket_cache_max)
            RING_VERDICT("Not all sockets were cached");

        total += total_i;

        TEST_STEP("Try to generate one more TCP connection. Socket on IUT must "
                  "not be cached, since the cache space is already exhausted, "
                  "but the closed sockets still are in the TIME_WAIT state "
                  "(during 2*MSL seconds).");
        aux_s = rpc_socket(client[0].rpcs, domain, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);
        rpc_connect(client[0].rpcs, aux_s, server[0].addr);
        aux_acc_s = rpc_accept(server[0].rpcs, server[0].listener, NULL, NULL);

        if (active)
        {
            rpc_close(client[0].rpcs, aux_s);
            RPC_CLOSE(server[0].rpcs, aux_acc_s);
        }
        else
        {
            rpc_close(server[0].rpcs, aux_acc_s);
            RPC_CLOSE(client[0].rpcs, aux_s);
        }

        if (tapi_onload_socket_is_cached(
                active ? client[0].rpcs : server[0].rpcs,
                active ? aux_s : aux_acc_s))
            RING_VERDICT("New socket is cached, but all cached sockets still "
                         "must be in the TIME_WAIT state");

        /* FIXME: Remove logging after debug. */
        rpc_system(pco_iut2, "te_onload_stdump lots | grep cache");
        usleep(20000);

        SLEEP(msl_timeout * 2 + 1);
        /* FIXME: Remove logging after debug. */
        rpc_system(pco_iut2, "te_onload_stdump lots | grep cache");
        usleep(20000);
    }

    RING("Total opened sockets number %d, cached %d",
         iter_num * listener_num * num, total);

    if (disable_caching && get_sockcache_contention(pco_iut2) > 0)
        TEST_VERDICT("Onload stackdump showed non-zero "
                     "sockcache_contention");

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < listener_num; i++)
    {
        if (server[i].handle != RPC_NULL)
        {
            rpc_many_close(server[i].rpcs, server[i].handle, num);
            rpc_many_close(client[i].rpcs, client[i].handle, num);
        }
    }

    clean_server_ctx(server, listener_num);

    free(client);
    free(addr);

    TEST_END;
}
