/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * FD caching
 */

/** @page fd_caching-fd_cache_ipv4_ipv6 Reusing IPv4 sockets as IPv6 sockets and vice versa
 *
 * @objective  Check that IPv6 sockets can be cached and later reused as
 *             IPv4 sockets and vice versa.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_p2p_ip4_ip6
 * @param sockets_num   How many TCP connections to open.
 * @param active        If @c TRUE, open connections actively from IUT,
 *                      otherwise open them passively.
 * @param first_ipv4    If @c TRUE, the first group of sockets should be
 *                      IPv4, else IPv6.
 * @param second_ipv4   If @c TRUE, the second group of sockets should be
 *                      IPv4, else IPv6.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cache_ipv4_ipv6"

#include "sockapi-test.h"
#include "fd_cache.h"
#include "tapi_mem.h"

/**
 * Establish TCP connections and check data transmission over them.
 *
 * @param pco_clnt      RPC server from which @b connect() is called.
 * @param pco_srv       RPC server where listener resides.
 * @param conn_addr     Address for @b connect().
 * @param clnt_socks    Where to save actively connected sockets.
 * @param srv_socks     Where to save accepted sockets.
 * @param sockets_num   Number of connections to establish.
 * @param listener      Listener socket.
 * @param msg           Message to print in verdicts.
 */
static void
establish_check_conns(rcf_rpc_server *pco_clnt,
                      rcf_rpc_server *pco_srv,
                      const struct sockaddr *conn_addr,
                      int *clnt_socks, int *srv_socks, int sockets_num,
                      int listener, const char *msg)
{
    te_bool clnt_silent = pco_clnt->silent_default;
    te_bool srv_silent = pco_srv->silent_default;
    int     i;
    int     rc;

    pco_clnt->silent = pco_clnt->silent_default = FALSE;
    pco_srv->silent = pco_srv->silent_default = FALSE;

    for (i = 0; i < sockets_num; i++)
    {
        clnt_socks[i] = rpc_socket(
                            pco_clnt,
                            rpc_socket_domain_by_addr(conn_addr),
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);

        RPC_AWAIT_ERROR(pco_clnt);
        rc = rpc_connect(pco_clnt, clnt_socks[i], conn_addr);
        if (rc < 0)
        {
            TEST_VERDICT("%s: connect() unexpectedly failed with errno %r",
                         msg, RPC_ERRNO(pco_clnt));
        }

        srv_socks[i] = rpc_accept(pco_srv, listener, NULL, NULL);
    }

    for (i = 0; i < sockets_num; i++)
    {
        sockts_test_connection(pco_clnt, clnt_socks[i],
                               pco_srv, srv_socks[i]);
    }

    pco_clnt->silent = pco_clnt->silent_default = clnt_silent;
    pco_srv->silent = pco_srv->silent_default = srv_silent;
}

/**
 * Close TCP connections so that on IUT closed sockets do not hang in
 * @c TIME_WAIT state.
 *
 * @param pco_clnt      RPC server from which @b connect() was called.
 * @param pco_srv       RPC server where listener resides.
 * @param clnt_socks    Sockets which were actively connected.
 * @param srv_socks     Sockets which were accepted.
 * @param sockets_num   Number of connections.
 * @param iut_active    If @c TRUE, @p pco_clnt is on IUT, otherwise
 *                      @p pco_srv is on IUT.
 */
static void
close_conns(rcf_rpc_server *pco_clnt,
            rcf_rpc_server *pco_srv,
            int *clnt_socks, int *srv_socks, int sockets_num,
            te_bool iut_active)
{
    te_bool clnt_silent = pco_clnt->silent_default;
    te_bool srv_silent = pco_srv->silent_default;
    int     i;

    pco_clnt->silent = pco_clnt->silent_default = FALSE;
    pco_srv->silent = pco_srv->silent_default = FALSE;

    for (i = 0; i < sockets_num; i++)
    {
        if (iut_active)
        {
            sockts_pair_close_check(pco_clnt, pco_srv,
                                    clnt_socks[i], srv_socks[i]);
        }
        else
        {
            sockts_pair_close_check(pco_srv, pco_clnt,
                                    srv_socks[i], clnt_socks[i]);
        }
    }

    pco_clnt->silent = pco_clnt->silent_default = clnt_silent;
    pco_srv->silent = pco_srv->silent_default = srv_silent;
}

/**
 * Check whether all connected IUT sockets are accelerated, print
 * verdict if this is not true.
 *
 * @param pco_clnt      RPC server from which @b connect() was called.
 * @param pco_srv       RPC server where listener resides.
 * @param clnt_socks    Sockets which were actively connected.
 * @param srv_socks     Sockets which were accepted.
 * @param sockets_num   Number of connections.
 * @param iut_active    If @c TRUE, @p pco_clnt is on IUT, otherwise
 *                      @p pco_srv is on IUT.
 * @param msg           Verdict prefix.
 */
static void
check_onload_fds(rcf_rpc_server *pco_clnt,
                 rcf_rpc_server *pco_srv,
                 int *clnt_socks, int *srv_socks, int sockets_num,
                 te_bool iut_active, const char *msg)
{
    tarpc_onload_stat ostat;
    int               onload_fds = 0;
    int               i;
    int               rc;

    for (i = 0; i < sockets_num; i++)
    {
        if (iut_active)
            pco_clnt->silent = TRUE;
        else
            pco_srv->silent = TRUE;

        rc = rpc_onload_fd_stat((iut_active ? pco_clnt : pco_srv),
                                (iut_active ? clnt_socks[i] : srv_socks[i]),
                                &ostat);
        if (rc == 1)
            onload_fds++;
    }

    if (onload_fds == 0)
    {
        ERROR_VERDICT("%s: all connected IUT sockets are not accelerated",
                      msg);
    }
    else if (onload_fds < sockets_num)
    {
        ERROR_VERDICT("%s: some connected IUT sockets are not accelerated",
                      msg);
    }
}

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    const struct sockaddr *iut_addr6;
    const struct sockaddr *tst_addr6;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_iut2 = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr *srv_addr;
    const struct sockaddr *srv_addr6;
    rcf_rpc_server        *pco_clnt = NULL;
    rcf_rpc_server        *pco_srv = NULL;

    const struct if_nameindex   *iut_if;

    int listener6 = -1;
    int iut_s_aux = -1;

    int     sockets_num;
    te_bool active;
    te_bool first_ipv4;
    te_bool second_ipv4;
    te_bool set_bindtodevice;

    struct sockaddr_storage listener_bind_addr;
    struct sockaddr_storage conn_addr_ipv4;
    struct sockaddr_storage conn_addr_ipv6;

    int *clnt_socks = NULL;
    int *srv_socks = NULL;
    int  i;

    int init_contention;
    int init_cached;
    int init_cache_hit;
    int contention;
    int cached;
    int cache_hit;
    int cached_diff;
    int cache_hit_diff;
    int shared_local_ports_max;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_tst, tst_addr6);
    TEST_GET_INT_PARAM(sockets_num);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_BOOL_PARAM(first_ipv4);
    TEST_GET_BOOL_PARAM(second_ipv4);
    TEST_GET_BOOL_PARAM(set_bindtodevice);

    if (active)
    {
        CHECK_RC(tapi_sh_env_get_int(pco_iut, "EF_TCP_SHARED_LOCAL_PORTS_MAX",
                                     &shared_local_ports_max));
        sockets_num = MIN(sockets_num, shared_local_ports_max);
    }


    clnt_socks = tapi_calloc(sockets_num, sizeof(int));
    srv_socks = tapi_calloc(sockets_num, sizeof(int));
    for (i = 0; i < sockets_num; i++)
    {
        clnt_socks[i] = -1;
        srv_socks[i] = -1;
    }

    TEST_STEP("If @p active is @c TRUE, IUT is client and Tester is "
              "server. Otherwise IUT is server and Tester is client.");

    if (active)
    {
        pco_clnt = pco_iut;
        pco_srv = pco_tst;
        srv_addr = tst_addr;
        srv_addr6 = tst_addr6;
    }
    else
    {
        pco_clnt = pco_tst;
        pco_srv = pco_iut;
        srv_addr = iut_addr;
        srv_addr6 = iut_addr6;
    }

    tapi_sockaddr_clone_exact(srv_addr6, &listener_bind_addr);
    te_sockaddr_set_wildcard(SA(&listener_bind_addr));

    tapi_sockaddr_clone_exact(srv_addr6, &conn_addr_ipv6);
    tapi_sockaddr_clone_exact(srv_addr, &conn_addr_ipv4);
    SIN(&conn_addr_ipv4)->sin_port = SIN6(srv_addr6)->sin6_port;

    TEST_STEP("Create IPv6 listener on server, binding it to wildcard "
              "address so that it can accept both IPv4 and IPv6 "
              "connections.");

    listener6 = rpc_socket(pco_srv, RPC_PF_INET6, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_srv, listener6, RPC_IPV6_V6ONLY, 0);
    TEST_STEP("Bind socket to the interface on IUT in the case of "
              "@p active is @c FALSE to add the ability to check common "
              "scalable cache.");
    if (!active && set_bindtodevice)
    {
        rpc_setsockopt_raw(pco_iut, listener6, RPC_SO_BINDTODEVICE,
                           iut_if->if_name, (strlen(iut_if->if_name) + 1));
    }
    rpc_bind(pco_srv, listener6, SA(&listener_bind_addr));
    rpc_listen(pco_srv, listener6, -1);

    /*
     * Create a socket on IUT to make sure that Onload stack is created
     * and Onload statistics can be retrieved.
     */
    iut_s_aux = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);

    TEST_STEP("Save initial values of @c sockcache_contention, "
              "@c sockcache_cached and @c sockcache_hit Onload counters.");

    /*
     * Another process is used here to obtain Onload counters because
     * it requires forking to run te_onload_stdump, and fork() and
     * execve() are harmful for socket caching.
     */
    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut2", &pco_iut2));
    init_contention = tapi_onload_get_stats_val(pco_iut2,
                                                "sockcache_contention");
    init_cached = tapi_onload_get_stats_val(pco_iut2, "sockcache_cached");

    TEST_STEP("Establish @p sockets_num connections, using IPv4 or IPv6 "
              "sockets on client according to @p first_ipv4. Check data "
              "transmission over established connections.");

    establish_check_conns(pco_clnt, pco_srv,
                          (first_ipv4 ? SA(&conn_addr_ipv4) :
                                        SA(&conn_addr_ipv6)),
                          clnt_socks, srv_socks, sockets_num, listener6,
                          "The first group");

    check_onload_fds(pco_clnt, pco_srv, clnt_socks, srv_socks,
                     sockets_num, active, "The first group");

    TEST_STEP("Close established connections so that closed sockets do not "
              "hang in @c TIME_WAIT state on IUT.");

    close_conns(pco_clnt, pco_srv, clnt_socks, srv_socks, sockets_num,
                active);
    /*
     * The cache may be non-empty since the tests can be run in the
     * reuse_stack mode.
     * In this case, some sockets may be taken from the cache when
     * establishing first connections.
     * So it makes sense to get init_cache_hit value in this place.
     */
    init_cache_hit = tapi_onload_get_stats_val(pco_iut2, "sockcache_hit");

    TEST_STEP("Establish again @p sockets_num connections, using IPv4 or "
              "IPv6 sockets on client according to @p second_ipv4. Check "
              "data transmission over established connections.");

    establish_check_conns(pco_clnt, pco_srv,
                          (second_ipv4 ? SA(&conn_addr_ipv4) :
                                         SA(&conn_addr_ipv6)),
                          clnt_socks, srv_socks, sockets_num, listener6,
                          "The second group");

    check_onload_fds(pco_clnt, pco_srv, clnt_socks, srv_socks,
                     sockets_num, active, "The second group");

    contention = tapi_onload_get_stats_val(pco_iut2,
                                           "sockcache_contention");
    cached = tapi_onload_get_stats_val(pco_iut2, "sockcache_cached");
    cache_hit = tapi_onload_get_stats_val(pco_iut2, "sockcache_hit");

    TEST_STEP("Check that value of @c sockcache_contention counter did not "
              "increase.");

    if (contention > init_contention)
        RING_VERDICT("sockcache_contention counter increased");

    TEST_STEP("Check that values of @c sockcache_cached and "
              "@c sockcache_hit counters both increased by "
              "@p sockets_num.");

    cached_diff = cached - init_cached;
    cache_hit_diff = cache_hit - init_cache_hit;
    RING("sockcache_cached increased by %d, sockcache_hit increased by %d",
         cached_diff, cache_hit_diff);

    if (cached_diff == 0)
        ERROR_VERDICT("No sockets were cached");
    else if (cached_diff < sockets_num)
        ERROR_VERDICT("Less sockets than expected were cached");
    else if (cached_diff > sockets_num)
        ERROR_VERDICT("More sockets than expected were cached");

    if (cache_hit_diff == 0)
        ERROR_VERDICT("No sockets were reused");
    else if (cache_hit_diff < sockets_num)
        ERROR_VERDICT("Less sockets than expected were reused");
    else if (cache_hit_diff > sockets_num)
        ERROR_VERDICT("More sockets than expected were reused");

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut2));

    /*
     * CLEANUP_RPC_CLOSE() is not used for all sockets here
     * because some may be cached due to closing, and
     * trying to close cached socket with CLEANUP_RPC_CLOSE()
     * results in failure because system FD still exists for
     * such socket.
     */

    if (pco_clnt != NULL)
    {
        for (i = 0; i < sockets_num; i++)
        {
            if (clnt_socks[i] >= 0)
                RPC_CLOSE(pco_clnt, clnt_socks[i]);
            if (srv_socks[i] >= 0)
                RPC_CLOSE(pco_srv, srv_socks[i]);
        }
        CLEANUP_RPC_CLOSE(pco_srv, listener6);
    }

    RPC_CLOSE(pco_iut, iut_s_aux);

    free(clnt_socks);
    free(srv_socks);

    TEST_END;
}
