/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 *
 * This test package contains tests for special cases of TCP protocol,
 * such as ICMP and routing table handling, small and zero window,
 * fragmentation of TCP packets, etc.
 */

/**
 * @page tcp-many_listeners Create a lot of listener sockets using scalable filters
 *
 * @objective Create a lot of listener sockets using scalable filters and
 *            accept connections on them.
 *
 * @param cluster_ignore    If @c TRUE set EF_CLUSTER_IGNORE=1 and enable
 *                          SO_REUSEPORT on each listener socket.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/many_listeners"

#include "sockapi-test.h"

#if HAVE_MATH_H
#include "math.h"
#endif

/** Number of listener sockets on IUT. */
#define LISTENERS_NUM 9000

/** Maximum number of embryonic connections. It has to be large enough to
 * create desired listeners number. */
#define TCP_BACKLOG_MAX (LISTENERS_NUM * 2)

/**
 * Maximum number of open file descriptors
 * (listeners + connected sockets + some auxiliary
 * sockets created by TE)
 */
#define MAX_TEST_FDS (LISTENERS_NUM * 2 + 100)

/** Maximum endpoints number to configure Onload. It has to be large enough
 * to create desired listeners number. */
#define MAX_ENDPOINTS_NUM (TCP_BACKLOG_MAX * 4)

/** Number of packet buffers should be enough to handle all connections. */
#define MAX_PACKETS 40000

/**
 * Check RPC call result, print verdict and exit on failure.
 *
 * @param rpcs_       RPC server.
 * @param expr_       RPC call expression.
 * @param func_       Function name.
 */
#define CHECK_RPC(rpcs_, expr_, func_) \
    do {                                                            \
        RPC_AWAIT_ERROR(rpcs_);                                     \
        rc = (expr_);                                               \
        if (rc < 0)                                                 \
        {                                                           \
            ERROR(#expr_ " failed for socket %d", i + 1);           \
            TEST_VERDICT(func_ " failed on %s with errno %r",       \
                         rpcs_->name, RPC_ERRNO(rpcs_));            \
        }                                                           \
    } while(0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct if_nameindex *iut_if;

    int iut_listeners[LISTENERS_NUM];
    int iut_ports[LISTENERS_NUM];
    int iut_accs[LISTENERS_NUM];

    int tst_socks[LISTENERS_NUM];

    struct sockaddr_storage   addr_aux;
    te_string                 str = TE_STRING_INIT;
    int                       i;

    int                       init_tcp_backlog_max;
    int                       init_max_endpoints_num;
    int                       init_fdtable_size;
    int                       init_cluster_ignore;
    char                     *init_scalable_filters;
    int                       init_max_packets;
    te_bool                   restore_tcp_backlog_max;
    te_bool                   restore_max_endpoints_num;
    te_bool                   restore_fdtable_size;
    te_bool                   restore_cluster_ignore;
    te_bool                   restore_scalable_filters;
    te_bool                   restore_max_packets;

    te_bool cluster_ignore;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(cluster_ignore);

    for (i = 0; i < LISTENERS_NUM; i++)
    {
        iut_listeners[i] = -1;
        iut_accs[i] = -1;
        tst_socks[i] = -1;
    }

    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_TCP_BACKLOG_MAX",
                                      TCP_BACKLOG_MAX, FALSE,
                                      &restore_tcp_backlog_max,
                                      &init_tcp_backlog_max));

    TEST_STEP("Set EF_MAX_ENDPOINTS and EF_FDTABLE_SIZE to allow "
              "creation of @c MAX_ENDPOINTS_NUM descriptors.");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_MAX_ENDPOINTS",
                                      exp2(ceil(log2(MAX_ENDPOINTS_NUM))),
                                      FALSE, &restore_max_endpoints_num,
                                      &init_max_endpoints_num));
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_FDTABLE_SIZE",
                                      MAX_ENDPOINTS_NUM, FALSE,
                                      &restore_fdtable_size,
                                      &init_fdtable_size));

    TEST_STEP("Set env EF_SCALABLE_FILTERS=<iut_if>=passive.");

    te_string_append(&str, "%s=passive",
                     iut_if->if_name);
    CHECK_RC(tapi_sh_env_save_set(pco_iut, "EF_SCALABLE_FILTERS",
                                  &restore_scalable_filters,
                                  &init_scalable_filters,
                                  str.ptr, FALSE));

    TEST_STEP("If @p cluster_ignore is @c TRUE set env EF_CLUSTER_IGNORE=1.");
    if (cluster_ignore)
        CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_CLUSTER_IGNORE", 1,
                                          FALSE, &restore_cluster_ignore,
                                          &init_cluster_ignore));

    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_MAX_PACKETS",
                                      MAX_PACKETS, FALSE,
                                      &restore_max_packets,
                                      &init_max_packets));

    TEST_STEP("Restart RPC server.");
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    TEST_STEP("Set RLIMIT_NOFILE to allow creation of @c MAX_TEST_FDS "
              "descriptors.");

    sockts_inc_rlimit(pco_iut, RPC_RLIMIT_NOFILE, MAX_TEST_FDS);
    sockts_inc_rlimit(pco_tst, RPC_RLIMIT_NOFILE, MAX_TEST_FDS);

    pco_iut->silent_default = pco_iut->silent = TRUE;
    pco_tst->silent_default = pco_tst->silent = TRUE;

    TEST_STEP("In a loop for @c LISTENERS_NUM iterations:");
    TEST_SUBSTEP("Create a TCP socket on IUT.");
    TEST_SUBSTEP("If @p cluster_ignore is @c TRUE, set @c SO_REUSEPORT "
                 "for the socket.");
    TEST_SUBSTEP("Bind the socket using a new port.");
    TEST_SUBSTEP("Call listen().");
    RING("Creating listeners on IUT...");
    for (i = 0; i < LISTENERS_NUM; i++)
    {
        CHECK_RPC(
            pco_iut,
            iut_listeners[i] = rpc_socket(
                                      pco_iut,
                                      rpc_socket_domain_by_addr(iut_addr),
                                      RPC_SOCK_STREAM, RPC_PROTO_DEF),
            "socket()");

        if (cluster_ignore)
        {
            CHECK_RPC(
                pco_iut,
                rpc_setsockopt_int(pco_iut, iut_listeners[i],
                                   RPC_SO_REUSEPORT, 1),
                "setsockopt()");
        }

        CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &addr_aux));
        CHECK_RPC(pco_iut,
                  rpc_bind(pco_iut, iut_listeners[i],
                           SA(&addr_aux)),
                  "bind()");

        CHECK_RPC(pco_iut,
                  rpc_listen(pco_iut, iut_listeners[i],
                             SOCKTS_BACKLOG_DEF),
                  "listen()");

        iut_ports[i] = te_sockaddr_get_port(SA(&addr_aux));
    }

    TEST_STEP("In a loop for @c LISTENERS_NUM iterations:");
    TEST_SUBSTEP("Create a TCP socket on Tester, connect it to "
                 "IUT listener socket.");
    RING("Creating and connecting sockets on Tester...");
    for (i = 0; i < LISTENERS_NUM; i++)
    {
        CHECK_RPC(
            pco_tst,
            tst_socks[i] = rpc_socket(pco_tst,
                                      rpc_socket_domain_by_addr(tst_addr),
                                      RPC_SOCK_STREAM, RPC_PROTO_DEF),
            "socket()");

        tapi_sockaddr_clone_exact(tst_addr, &addr_aux);
        te_sockaddr_set_port(SA(&addr_aux), 0);
        CHECK_RPC(pco_tst,
                  rpc_bind(pco_tst, tst_socks[i], SA(&addr_aux)),
                  "bind()");

        tapi_sockaddr_clone_exact(iut_addr, &addr_aux);
        te_sockaddr_set_port(SA(&addr_aux), iut_ports[i]);
        CHECK_RPC(pco_tst,
                  rpc_connect(pco_tst, tst_socks[i], SA(&addr_aux)),
                  "connect()");
    }

    TEST_STEP("Accept connections using all the listeners on IUT.");
    RING("Accepting connections on IUT...");
    for (i = 0; i < LISTENERS_NUM; i++)
    {
        CHECK_RPC(pco_iut,
                  iut_accs[i] = rpc_accept(pco_iut, iut_listeners[i],
                                           NULL, NULL),
                  "accept()");
    }

    TEST_STEP("Close all listener sockets and connected sockets on IUT.");
    RING("Closing sockets on IUT...");
    for (i = 0; i < LISTENERS_NUM; i++)
    {
        CHECK_RPC(pco_iut,
                  rpc_close(pco_iut, iut_accs[i]),
                  "close() for accepted socket");
        iut_accs[i] = -1;

        CHECK_RPC(pco_iut,
                  rpc_close(pco_iut, iut_listeners[i]),
                  "close() for listener socket");
        iut_listeners[i] = -1;
    }

    TEST_STEP("Close all the opened sockets on Tester.");
    RING("Closing sockets on Tester...");
    for (i = 0; i < LISTENERS_NUM; i++)
    {
        CHECK_RPC(pco_tst,
                  rpc_close(pco_tst, tst_socks[i]),
                  "close()");
        tst_socks[i] = -1;
    }

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < LISTENERS_NUM; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, iut_listeners[i]);
        CLEANUP_RPC_CLOSE(pco_tst, tst_socks[i]);
        CLEANUP_RPC_CLOSE(pco_iut, iut_accs[i]);
    }

    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_MAX_PACKETS",
                                              restore_max_packets,
                                              init_max_packets, FALSE));

    CLEANUP_CHECK_RC(tapi_sh_env_rollback(pco_iut, "EF_SCALABLE_FILTERS",
                                          restore_scalable_filters,
                                          init_scalable_filters, FALSE));

    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_TCP_BACKLOG_MAX",
                                              restore_tcp_backlog_max,
                                              init_tcp_backlog_max, FALSE));

    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_MAX_ENDPOINTS",
                                              restore_max_endpoints_num,
                                              init_max_endpoints_num, FALSE));

    CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_FDTABLE_SIZE",
                                              restore_fdtable_size,
                                              init_fdtable_size, FALSE));

    if (cluster_ignore)
        CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_CLUSTER_IGNORE",
                                                  restore_cluster_ignore,
                                                  init_cluster_ignore, FALSE));

    /* Destroy Onload stack to avoid impact on other tests. It is possible
     * to have only one Onload stack with scalable filters. */
    rcf_rpc_server_restart(pco_iut);
    sockts_kill_zombie_stacks(pco_iut);

    TEST_END;
}
