/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-if_change_netns Using interface after moving it to/from a network namespace
 *
 * @objective Check that data can be sent and received over an interface
 *            after moving it to/from a network namespace.
 *
 *  @param env            Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 *  @param rt_sock_type   Socket type used in testing:
 *                        - @c tcp_active
 *                        - @c tcp_passive
 *                        - @c udp
 *                        - @c udp_connect
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/if_change_netns"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "ts_route.h"
#include "tapi_namespaces.h"
#include "tapi_host_ns.h"

/** Name of the created namespace */
#define TEST_NETNS "aux_netns"
/** Name of the created TA */
#define TEST_NETNS_TA "Agt_aux_netns"
/** Name of the created RPC server */
#define TEST_NETNS_RPCS "pco_iut_aux_netns"

/**
 * Add a new network namespace, create TA and RPC server in it.
 *
 * @param pco_iut       RPC server in the original namespace.
 * @param rpcs_ns       Where to save pointer to RPC server in the
 *                      created namespace.
 */
static void
configure_netns(rcf_rpc_server *pco_iut, rcf_rpc_server **rpcs_ns)
{
    const char *ta_rpcprovider;
    const char *iut_ta_name;
    const char *ta_type;
    const char *host;
    uint16_t rcf_port;

    CHECK_NOT_NULL(ta_rpcprovider = getenv("SF_TS_IUT_RPCPROVIDER"));
    CHECK_NOT_NULL(iut_ta_name = getenv("TE_IUT_TA_NAME"));
    CHECK_NOT_NULL(ta_type = getenv("TE_IUT_TA_TYPE"));
    CHECK_NOT_NULL(host = getenv("TE_IUT"));

    CHECK_RC(tapi_allocate_port_htons(pco_iut, &rcf_port));

    /*
     * tapi_netns_add() is not used here because it is required
     * to create namespace from a TA under default namespace,
     * which is different from pco_iut->ta if --ool=netns_iut
     * or --ool=netns_all is used. Creating network namespace
     * while being under non-default network namespace does not
     * work well.
     */
    CHECK_RC(cfg_add_instance_fmt(
                              NULL, CVT_NONE, NULL,
                              "/agent:%s/namespace:/net:%s", iut_ta_name,
                              TEST_NETNS));
    CHECK_RC(tapi_netns_add_rsrc(pco_iut->ta, TEST_NETNS));

    CHECK_RC(tapi_netns_add_ta(host, TEST_NETNS, TEST_NETNS_TA,
                               ta_type, rcf_port, NULL, NULL,
                               TRUE));

    CHECK_RC(cfg_synchronize("/:", TRUE));
    CHECK_RC(cfg_set_instance_fmt(CVT_STRING, ta_rpcprovider,
                                  "/agent:%s/rpcprovider:", TEST_NETNS_TA));

    /*
     * Loopback interface should be UP in the namespace for logging from
     * RPC servers to work correctly.
     * TE grabs interface by its name, so it does not allow to grab
     * "lo" interface in two different namespaces by two different
     * TAs simultaneously.
     */

    CHECK_RC(tapi_cfg_base_if_del_rsrc(pco_iut->ta, "lo"));
    CHECK_RC(tapi_cfg_base_if_add_rsrc(TEST_NETNS_TA, "lo"));
    CHECK_RC(tapi_cfg_base_if_up(TEST_NETNS_TA, "lo"));

    CHECK_RC(tapi_cfg_base_if_del_rsrc(TEST_NETNS_TA, "lo"));
    CHECK_RC(tapi_cfg_base_if_add_rsrc(pco_iut->ta, "lo"));

    CHECK_RC(rcf_rpc_server_create(TEST_NETNS_TA, TEST_NETNS_RPCS,
                                   rpcs_ns));
    if (!te_str_is_null_or_empty(pco_iut->nv_lib))
        rcf_rpc_setlibname(*rpcs_ns, pco_iut->nv_lib);
}

/**
 * Destroy the created network namespace together with TA and RPC server
 * created in it.
 *
 * @param pco_iut     RPC server in the original namespace.
 * @param rpcs_ns     RPC server in the created namespace.
 */
static void
destroy_netns(rcf_rpc_server *pco_iut, rcf_rpc_server *rpcs_ns)
{
    const char *iut_ta_name;

    CHECK_NOT_NULL(iut_ta_name = getenv("TE_IUT_TA_NAME"));
    CHECK_RC(rcf_rpc_server_destroy(rpcs_ns));
    CHECK_RC(rcf_del_ta(TEST_NETNS_TA));
    CHECK_RC(tapi_host_ns_agent_del(TEST_NETNS_TA));
    CHECK_RC(tapi_netns_del_rsrc(pco_iut->ta, TEST_NETNS));
    CHECK_RC(tapi_netns_add_rsrc(iut_ta_name, TEST_NETNS));
    CHECK_RC(tapi_netns_del(iut_ta_name, TEST_NETNS));

    /*
     * Without this Configurator will fail to restore from backup.
     */
    CHECK_RC(cfg_synchronize_fmt(TRUE, "/agent:%s", TEST_NETNS_TA));
}

/**
 * Create a pair of sockets on IUT and Tester, connect them if
 * required, send/receive data in both directions between them
 * and check that traffic from IUT is accelerated when expected.
 *
 * @param pco_iut             RPC server on IUT.
 * @param iut_if              Network interface on IUT.
 * @param iut_if_accelerated  TRUE if traffic should be accelerated,
 *                            FALSE otherwise.
 * @param iut_addr            Network address on IUT.
 * @param pco_tst             RPC server on Tester.
 * @param tst_addr            Network address on Tester.
 * @param rt_sock_type        Sockets type to check.
 * @param accel_check_fail    Will be set to TRUE if check for traffic
 *                            acceleration failed.
 * @param msg                 Message to print in verdicts.
 *
 * @return Status code.
 */
static te_errno
check_connection(rcf_rpc_server *pco_iut, const struct if_nameindex *iut_if,
                 te_bool iut_if_accelerated,
                 const struct sockaddr *iut_addr, rcf_rpc_server *pco_tst,
                 const struct sockaddr *tst_addr,
                 sockts_socket_type rt_sock_type,
                 te_bool *accel_check_fail, const char *msg)
{
#define CHECK_EXPR(_expr) \
    do {                  \
        rc = (_expr);     \
        if (rc != 0)      \
            goto cleanup; \
    } while (0)

    sockts_if_monitor traffic_monitor = SOCKTS_IF_MONITOR_INIT;
    te_errno rc = 0;
    sockts_test_send_rc test_send_rc;
    te_string str = TE_STRING_INIT_STATIC(1024);

    struct sockaddr_storage iut_bind_addr;
    struct sockaddr_storage tst_bind_addr;
    int iut_s = -1;
    int tst_s = -1;


    CHECK_EXPR(sockts_if_monitor_init(&traffic_monitor,
                                      pco_iut->ta,
                                      iut_if->if_name,
                                      iut_addr->sa_family,
                                      sock_type_sockts2rpc(rt_sock_type),
                                      iut_addr, tst_addr,
                                      FALSE, TRUE));

    CHECK_EXPR(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_bind_addr));
    CHECK_EXPR(tapi_sockaddr_clone(pco_tst, tst_addr, &tst_bind_addr));

    if (sockts_rt_connection(rt_sock_type, pco_iut, TRUE,
                             SA(&iut_bind_addr), SA(&iut_bind_addr),
                             pco_tst, SA(&tst_bind_addr),
                             &iut_s, &tst_s, msg) != 0)
    {
        rc = TE_EFAIL;
        goto cleanup;
    }
    if (rt_sock_type == SOCKTS_SOCK_UDP)
        rpc_connect(pco_tst, tst_s, SA(&iut_bind_addr));

    te_string_append(&str, "%s, sending from IUT", msg);
    test_send_rc = sockts_rt_test_send(rt_sock_type, pco_iut, iut_s,
                                       pco_tst, tst_s,
                                       SA(&tst_bind_addr), NULL,
                                       TRUE, str.ptr);
    if (test_send_rc != SOCKTS_TEST_SEND_SUCCESS)
    {
        rc = TE_EFAIL;
        goto cleanup;
    }

    te_string_reset(&str);
    te_string_append(&str, "%s, sending from Tester", msg);
    test_send_rc = sockts_rt_test_send(rt_sock_type, pco_tst, tst_s,
                                       pco_iut, iut_s,
                                       SA(&iut_bind_addr), NULL,
                                       TRUE, str.ptr);
    if (test_send_rc != SOCKTS_TEST_SEND_SUCCESS)
    {
        rc = TE_EFAIL;
        goto cleanup;
    }

    RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_tst, tst_s);

    if (sockts_if_monitor_check_out(&traffic_monitor,
                                    TRUE) != !iut_if_accelerated)
    {
        ERROR_VERDICT("%s: traffic over IUT interface "
                      "is %saccelerated", msg,
                      (iut_if_accelerated ? "not " : ""));
        *accel_check_fail = TRUE;
    }

cleanup:

    CHECK_RC(sockts_if_monitor_destroy(&traffic_monitor));

    if (iut_s >= 0)
        RPC_CLOSE(pco_iut, iut_s);
    if (tst_s >= 0)
        RPC_CLOSE(pco_tst, tst_s);

    return rc;
#undef CHECK_EXPR
}

static void
move_if_back(rcf_rpc_server *pco_iut,
             rcf_rpc_server *pco_iut_ns,
             const struct if_nameindex *iut_if,
             const struct sockaddr *iut_addr,
             int prefix)
{
    CHECK_RC(tapi_cfg_base_if_del_rsrc(pco_iut_ns->ta, iut_if->if_name));
    CHECK_RC(tapi_netns_if_unset(pco_iut->ta, TEST_NETNS,
                                 iut_if->if_name));
    CHECK_RC(tapi_cfg_base_if_add_rsrc(pco_iut->ta, iut_if->if_name));
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, prefix, FALSE, NULL));
    CFG_WAIT_CHANGES;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_iut_ns = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    const struct if_nameindex *iut_if = NULL;
    tapi_env_net *net = NULL;
    int prefix;

    sockts_socket_type rt_sock_type;

    te_bool iut_if_accelerated;
    te_bool accel_check_fail = FALSE;

    te_bool move_back = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    prefix = (iut_addr->sa_family == AF_INET ? net->ip4pfx : net->ip6pfx);
    iut_if_accelerated = sockts_if_accelerated(&env, pco_iut->ta,
                                               iut_if->if_name);

    TEST_STEP("Create a pair of sockets on IUT and Tester according to "
              "@p rt_sock_type, send/receive data in both directions, "
              "check whether traffic is accelerated as expected.");
    CHECK_RC(check_connection(
                     pco_iut, iut_if, iut_if_accelerated, iut_addr,
                     pco_tst, tst_addr, rt_sock_type, &accel_check_fail,
                     "The first connection"));

    TEST_STEP("Create a network namespace on IUT with a new TA and RPC "
              "server inside it.");
    configure_netns(pco_iut, &pco_iut_ns);

    TEST_STEP("Move @p iut_if to the created namespace.");
    CHECK_RC(tapi_netns_if_set(pco_iut->ta, TEST_NETNS, iut_if->if_name));
    CHECK_RC(tapi_cfg_base_if_add_rsrc(pco_iut_ns->ta, iut_if->if_name));
    CHECK_RC(tapi_cfg_base_if_up(pco_iut_ns->ta, iut_if->if_name));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut_ns->ta, iut_if->if_name,
                                           iut_addr, prefix, FALSE, NULL));
    CFG_WAIT_CHANGES;
    move_back = TRUE;

    TEST_STEP("Create a pair of sockets on IUT and Tester according to "
              "@p rt_sock_type, doing it inside the created network "
              "namespace on IUT. Send/receive data in both directions, "
              "check whether traffic is accelerated as expected.");
    CHECK_RC(check_connection(
                     pco_iut_ns, iut_if, iut_if_accelerated, iut_addr,
                     pco_tst, tst_addr, rt_sock_type, &accel_check_fail,
                     "The second connection"));

    TEST_STEP("Move @p iut_if back to the original network namespace.");
    move_if_back(pco_iut, pco_iut_ns, iut_if, iut_addr, prefix);
    move_back = FALSE;

    TEST_STEP("Create a pair of sockets on IUT and Tester according to "
              "@p rt_sock_type, doing it inside the original network "
              "namespace on IUT. Send/receive data in both directions, "
              "check whether traffic is accelerated as expected.");
    CHECK_RC(check_connection(
                     pco_iut, iut_if, iut_if_accelerated, iut_addr,
                     pco_tst, tst_addr, rt_sock_type, &accel_check_fail,
                     "The third connection"));

    if (accel_check_fail)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    if (move_back)
        move_if_back(pco_iut, pco_iut_ns, iut_if, iut_addr, prefix);

    destroy_netns(pco_iut, pco_iut_ns);

    TEST_END;
}
