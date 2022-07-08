/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/**
 * @page route-rt_switched_tos Routing with/without TOS
 *
 * @objective Check that a new route with specific TOS correctly directs the IP
 *            traffic on established connection.
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_route_two_iut_ifs
 * @param sock_type Socket connection type:
 *      - udp
 *      - udp_connect
 *      - tcp_active
 *      - tcp_passive
 * @param use_rules If @c TRUE, use policy-based routing, else use destination-
 *                  based:
 *      - TRUE
 *      - FALSE
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/rt_switched_tos"

#include "sockapi-test.h"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

#define TABLE_TOS       SOCKTS_RT_TABLE_FOO
#define TABLE_NONTOS    SOCKTS_RT_TABLE_BAR

/*
 * This timeout includes ARP resolution and 3-way TCP handshake.  It must
 * be larger than TAPI_WAIT_NETWORK_DELAY.
 */
#define NET_TIMEOUT (TAPI_WAIT_NETWORK_DELAY * 3)

/*
 * Add route on @p pco_iut to @p alien addr.
 *
 * @param dev           Interface name
 * @param tosval        Type of service
 * @param hdl           Route handle (OUT)
 * @param rule          Rule for adding
 * @param rule_added    Set to TRUE if rule was added (OUT)
 *
 */
#define SET_IUT_ROUTE(dev, tosval, hdl, rule, rule_added) \
    do {                                                                \
        int table;                                                      \
        if (use_rules)                                                  \
            table = tosval > 0 ? TABLE_TOS : TABLE_NONTOS;              \
        else                                                            \
            table = TAPI_RT_TABLE_MAIN;                                 \
                                                                        \
        CHECK_RC(tapi_cfg_add_full_route(                               \
                        pco_iut->ta, af,                                \
                        te_sockaddr_get_netaddr(alien_addr),            \
                        route_prefix, NULL, dev->if_name, NULL, NULL,   \
                        0, 0, use_rules ? 0 : tosval, 0, 0, 0,          \
                        table, &hdl));                                  \
        if (use_rules)                                                  \
        {                                                               \
            te_conf_ip_rule_init(&rule);                                \
            rule.table = table;                                         \
            tapi_sockaddr_clone_exact(alien_addr, &rule.dst);           \
            rule.mask |= TE_IP_RULE_FLAG_TABLE | TE_IP_RULE_FLAG_DST;   \
            rule.dstlen = route_prefix;                                 \
            if (tosval > 0)                                             \
            {                                                           \
                rule.tos = tosval;                                      \
                rule.mask |= TE_IP_RULE_FLAG_TOS;                       \
            }                                                           \
            CHECK_RC(tapi_cfg_add_rule(pco_iut->ta, af, &rule));        \
            rule_added = TRUE;                                          \
        }                                                               \
    } while (0)

/*
 * Create sockets, bind and connect them in accordance to the parameters,
 * and set IP_TOS option equal to @p tos argument.
 *
 * @param rt_sock_type        Socket type.
 * @param pco_iut             IUT RPC server handle.
 * @param iut_addr            IUT network address.
 * @param s_iut               IUT socket location.
 * @param pco_tst             Tester RPC server handle.
 * @param tst_addr            Tester network address.
 * @param s_tst               Tester socket location.
 * @param tos                 Value of IP_TOS to be set for sockets.
 *
 * @return 0 on success, value from sockts_rt_error_code
 *         on failure (description of error will be saved
 *         in rt_error).
 */
static int
rt_gen_conn(sockts_socket_type rt_sock_type,
            rcf_rpc_server *pco_iut,
            const struct sockaddr *iut_addr, int *s_iut,
            rcf_rpc_server *pco_tst,
            const struct sockaddr *tst_addr, int *s_tst,
            int tos)
{
    rpc_socket_type     sock_type;
    rpc_socket_domain   domain;

    int rc = 0;

    sock_type = sock_type_sockts2rpc(rt_sock_type);
    domain = rpc_socket_domain_by_addr(iut_addr);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        int iut_s = -1;
        int tst_s = -1;

        iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_TOS, tos);

        if (rt_sock_type == SOCKTS_SOCK_UDP)
        {
            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, iut_s, tst_addr);

            if (rc < 0)
            {
                ERROR_VERDICT("connect() failed with errno %r",
                               RPC_ERRNO(pco_iut));
                rt_error.err_code = SOCKTS_RT_ERR_RPC_CONNECT;
                rt_error.rpcs = pco_iut;
                return SOCKTS_RT_ERR_RPC_CONNECT;
            }
        }

        tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_tst, tst_s, RPC_IP_TOS, tos);
        rpc_bind(pco_tst, tst_s, tst_addr);

        *s_iut = iut_s;
        *s_tst = tst_s;
    }
    else
    {
        const struct sockaddr  *srv_conn_addr = NULL;
        const struct sockaddr  *srv_bind_addr = NULL;
        const struct sockaddr  *clnt_bind_addr = NULL;

        int               s_listener = -1;
        int               s_srv = -1;
        int               s_clnt = -1;
        rcf_rpc_server   *rpcs_srv = NULL;
        rcf_rpc_server   *rpcs_clnt = NULL;
        int               fdflags;
        te_bool           readable = FALSE;

        if (rt_sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        {
            rpcs_srv = pco_tst;
            rpcs_clnt = pco_iut;
            srv_bind_addr = tst_addr;
            srv_conn_addr = tst_addr;
            clnt_bind_addr = iut_addr;
        }
        else
        {
            rpcs_srv = pco_iut;
            rpcs_clnt = pco_tst;
            srv_bind_addr = iut_addr;
            srv_conn_addr = iut_addr;
            clnt_bind_addr = tst_addr;
        }

        s_listener = rpc_socket(rpcs_srv, domain,
                                RPC_SOCK_STREAM,
                                RPC_PROTO_DEF);

        rpc_setsockopt_int(rpcs_srv, s_listener, RPC_IP_TOS, tos);

        rpc_bind(rpcs_srv, s_listener, srv_bind_addr);
        rpc_listen(rpcs_srv, s_listener, SOCKTS_BACKLOG_DEF);

        s_clnt = rpc_socket(rpcs_clnt, domain,
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);

        rpc_setsockopt_int(rpcs_clnt, s_clnt, RPC_IP_TOS, tos);

        if (rt_sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL)
            rpc_bind(rpcs_clnt, s_clnt, clnt_bind_addr);

        fdflags = rpc_fcntl(rpcs_clnt, s_clnt, RPC_F_GETFL, 0);
        rpc_fcntl(rpcs_clnt, s_clnt, RPC_F_SETFL, fdflags | RPC_O_NONBLOCK);

        RPC_AWAIT_ERROR(rpcs_clnt);
        rc = rpc_connect(rpcs_clnt, s_clnt, srv_conn_addr);
        if (rc < 0 && RPC_ERRNO(rpcs_clnt) != RPC_EINPROGRESS)
        {
            ERROR_VERDICT("connect() failed with errno %r",
                           RPC_ERRNO(rpcs_clnt));

            if (rpcs_clnt == pco_tst)
            {
                TEST_STOP;
            }
            else
            {
                rt_error.err_code = SOCKTS_RT_ERR_RPC_CONNECT;
                rt_error.rpcs = rpcs_clnt;
                return SOCKTS_RT_ERR_RPC_CONNECT;
            }
        }

        RPC_GET_READABILITY(readable, rpcs_srv, s_listener, NET_TIMEOUT);
        if (!readable)
        {
            ERROR_VERDICT("Listener did not accept connection");
            rt_error.err_code = SOCKTS_RT_ERR_NOT_ACCEPTED;
            rt_error.rpcs = rpcs_srv;
            return SOCKTS_RT_ERR_NOT_ACCEPTED;
        }

        rpc_fcntl(rpcs_clnt, s_clnt, RPC_F_SETFL, fdflags);
        s_srv = rpc_accept(rpcs_srv, s_listener, NULL, NULL);
        rpc_close(rpcs_srv, s_listener);

        rpc_setsockopt_int(rpcs_srv, s_srv, RPC_IP_TOS, tos);

        *s_iut = rt_sock_type == SOCKTS_SOCK_TCP_ACTIVE ? s_clnt : s_srv;
        *s_tst = rt_sock_type == SOCKTS_SOCK_TCP_ACTIVE ? s_srv : s_clnt;
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    DECLARE_TWO_IFS_COMMON_PARAMS;

    cfg_handle      tst1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle      tst2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle      rh1 = CFG_HANDLE_INVALID;
    cfg_handle      rh2 = CFG_HANDLE_INVALID;

    te_conf_ip_rule rule_tos;
    te_bool         rule_tos_added = FALSE;
    te_conf_ip_rule rule_nontos;
    te_bool         rule_nontos_added = FALSE;

    sockts_socket_type      sock_type;
    te_bool                 use_rules;

    int     af;
    int     route_prefix;
    int     domain;
    int     iut_s = -1;
    int     tst_s = -1;

    DECLARE_TWO_IFS_MONITORS;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_RT_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(use_rules);

    GET_DOMAIN_AF_PREFIX(tst1_addr, domain, af, route_prefix);

    TEST_STEP("Initialize monitors to check traffic.");
    INIT_TWO_IFS_MONITORS(alien_addr, af, sock_type);

    TEST_STEP("Set IUT and Tester to receive/send packets via all interfaces.");
    CHECK_RC(tapi_cfg_sys_set_int(pco_tst1->ta, 0, NULL,
                                  "net/ipv4/conf:all/rp_filter"));
    CHECK_RC(tapi_cfg_sys_set_int(pco_tst1->ta, 0, NULL,
                                  "net/ipv4/conf:%s/rp_filter",
                                  tst1_if->if_name));
    CHECK_RC(tapi_cfg_sys_set_int(pco_tst2->ta, 0, NULL,
                                  "net/ipv4/conf:%s/rp_filter",
                                  tst2_if->if_name));
    CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 0, NULL,
                                  "net/ipv4/conf:all/rp_filter"));

    TEST_STEP("Add @p alien_addr on Tester interfaces.");
    TWO_IFS_ADD_TST_ADDRS(single_peer, alien_addr,
                          &tst1_addr_hndl, &tst2_addr_hndl);

    TEST_STEP("Add new non-TOS route to @p alien_addr via @p iut_if1 interface "
              "according to @p use_rules parameter.");
    SET_IUT_ROUTE(iut_if1, 0, rh1, rule_nontos, rule_nontos_added);
    TWO_IFS_CNS_ROUTE(TRUE);
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a connection according to @p sock_type parameter.");
    TEST_STEP("Set non-zero IP_TOS option on IUT socket.");
    SOCKTS_RT_CHECK_RC(rt_gen_conn(sock_type, SOCKTS_RT_PCO_IUT_SOCK,
                                   SOCKTS_RT_IUT_ADDR1, &iut_s,
                                   pco_tst1, alien_addr, &tst_s,
                                   SOCKTS_RT_DEF_TOS));

    TEST_STEP("Send packets from IUT. Receive on tst1.");
    CHECK_SOCKTS_TEST_SEND_RC(
          sockts_rt_test_send(sock_type, SOCKTS_RT_PCO_IUT_SOCK, iut_s,
                              pco_tst1, tst_s,
                              alien_addr, NULL, TRUE, "Non-TOS route"));

    TEST_STEP("Check that monitor on tst1 caught packets.");
    SOCKTS_RT_RING("Checking that CSAP captured packets "
                   "only on the first Tester interface");
    CHECK_TWO_IFS_IN(&tst1_if_monitor, &tst2_if_monitor,
                     TRUE, FALSE, "Non-TOS route");
    CHECK_IF_ACCELERATED(&env, &iut_if1_monitor,
                         "Non-TOS route");

    TEST_STEP("Add new TOS route to @p alien_addr via @p iut_if2 interface "
              "according to @p use_rules parameter.");
    SET_IUT_ROUTE(iut_if2, SOCKTS_RT_DEF_TOS, rh2, rule_tos, rule_tos_added);
    TWO_IFS_CNS_ROUTE(FALSE);
    CFG_WAIT_CHANGES;

    TEST_STEP("Send packets from IUT. Receive on tst1.");
    CHECK_SOCKTS_TEST_SEND_RC(
          sockts_rt_test_send(sock_type, SOCKTS_RT_PCO_IUT_SOCK, iut_s,
                              pco_tst1, tst_s,
                              alien_addr, NULL, TRUE, "TOS route"));

    TEST_STEP("Check that monitor on tst2 caught packets.");
    SOCKTS_RT_RING("Checking that CSAP captured packets "
                   "only on the second Tester interface");
    CHECK_TWO_IFS_IN(&tst1_if_monitor, &tst2_if_monitor,
                     FALSE, TRUE, "TOS route");
    CHECK_IF_ACCELERATED(&env, &iut_if2_monitor,
                         "TOS route");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(SOCKTS_RT_PCO_IUT_SOCK, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s);

    CLEANUP_TWO_IFS_MONITORS;

    if (rule_tos_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           rule_tos.mask, &rule_tos));
    if (rule_nontos_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           rule_nontos.mask, &rule_nontos));

    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst1_addr_hndl, FALSE));
    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst2_addr_hndl, FALSE));

    if (rh2 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh2));
    if (rh1 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh1));

    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
