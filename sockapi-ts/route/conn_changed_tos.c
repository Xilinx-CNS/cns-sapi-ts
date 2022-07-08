/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/**
 * @page route-conn_changed_tos Routing with two different TOS
 *
 * @objective Check that if we send @b cmsg with set TOS
 *            or change TOS during UDP or TCP
 *            connection it goes to correct route.
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_route_two_iut_ifs
 * @param sock_type       Socket type:
 *                        - @c udp (connected UDP socket)
 *                        - @c udp_notconn (not connected UDP socket)
 *                        - @c tcp_active (actively established TCP
 *                          connection)
 *                        - @c tcp_passive (passively established TCP
 *                          connection)
 *                        - @c tcp_passive_close (passively established
 *                          TCP connection, listener is closed after
 *                          @b accept())
 * @param with_cmsg       If @c TRUE, IP_TOS would be sent with cmsg,
 *                        otherwise setsockopt would be used
 * @param use_rules       If @c TRUE, use policy-based routing, else use
 *                        destination-based
 * @param null_alien_addr If @c TRUE, send packets to a specified address,
 *                        do not specify the address in sent message otherwise
 *
 * @par Scenario:
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/conn_changed_tos"

#include "sockapi-test.h"
#include "ts_route.h"

#define TABLE_TOS_X    SOCKTS_RT_TABLE_FOO
#define TABLE_TOS_Y    SOCKTS_RT_TABLE_BAR

static void
test_send(rcf_rpc_server *pco_iut,
          rcf_rpc_server *pco_tst,
          int iut_s, int tst_s,
          const struct sockaddr *alien_addr,
          int tos, te_bool with_cmsg)
{
    if (!with_cmsg)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_TOS, tos);

    sockts_send_check_field_cmsg(pco_iut, pco_tst, iut_s, tst_s,
                                 alien_addr,
                                 CSAP_INVALID_HANDLE, NULL, NULL,
                                 NULL, 0, NULL, 0,
                                 with_cmsg, IPPROTO_IP, IP_TOS, tos,
                                 NULL, "Test send");
}

static void
set_iut_route(rcf_rpc_server *pco_iut,
              const struct if_nameindex *dev,
              int tosval, cfg_handle *rt_hdl,
              te_bool use_rules, te_conf_ip_rule *rule,
              te_bool *rule_added, int used_table,
              const struct sockaddr *alien_addr,
              int af, int route_prefix)
{
    int table = use_rules ? used_table : TAPI_RT_TABLE_MAIN;

    CHECK_RC(tapi_cfg_add_full_route(
        pco_iut->ta, af,
        te_sockaddr_get_netaddr(alien_addr),
        route_prefix, NULL, dev->if_name, NULL, NULL,
        0, 0, use_rules ? 0 : tosval, 0, 0, 0,
        table, rt_hdl));

    if (use_rules)
    {
        te_conf_ip_rule_init(rule);
        rule->table = table;
        tapi_sockaddr_clone_exact(alien_addr, &rule->dst);
        rule->mask |= TE_IP_RULE_FLAG_TABLE | TE_IP_RULE_FLAG_DST;
        rule->dstlen = route_prefix;
        if (tosval > 0)
        {
            rule->tos = tosval;
            rule->mask |= TE_IP_RULE_FLAG_TOS;
        }
        CHECK_RC(tapi_cfg_add_rule(pco_iut->ta, af, rule));
        *rule_added = TRUE;
    }
}

int
main(int argc, char *argv[])
{
    DECLARE_TWO_IFS_COMMON_PARAMS;

    cfg_handle      tst1_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle      tst2_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle      rh0 = CFG_HANDLE_INVALID;
    cfg_handle      rh1 = CFG_HANDLE_INVALID;
    cfg_handle      rh2 = CFG_HANDLE_INVALID;

    te_conf_ip_rule rule_tos_x;
    te_bool         rule_tos_x_added = FALSE;
    te_conf_ip_rule rule_tos_y;
    te_bool         rule_tos_y_added = FALSE;

    sockts_socket_type      sock_type;
    te_bool                 with_cmsg;
    te_bool                 use_rules;
    te_bool                 null_alien_addr;

    int tos_x;
    int tos_y;

    int     af;
    int     route_prefix;
    int     domain;
    int     iut_s = -1;
    int     iut_l = -1;
    int     tst_s = -1;
    int     i = 0;

    DECLARE_TWO_IFS_MONITORS;

    TEST_START;

    GET_TWO_IFS_COMMON_PARAMS;
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(with_cmsg);
    TEST_GET_BOOL_PARAM(use_rules);
    TEST_GET_BOOL_PARAM(null_alien_addr);

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

    TEST_STEP("Generate two random @c IP_TOS values.");
    tos_x = rand_range(0x01, 0x07) << 2;
    do {
        tos_y = rand_range(0x01, 0x07) << 2;
    } while (tos_y == tos_x);

    TEST_STEP("Add two routes on IUT to Tester address, one via the first IUT "
              "interface and with the first @c IP_TOS value, "
              "another one via the second IUT interface and "
              "with the second @c IP_TOS value."
              "Also add a route without @c IP_TOS over the first IUT "
              "interface to make possible TCP connection establishment.");
    set_iut_route(pco_iut, iut_if1, 0, &rh0, FALSE,
                  NULL, NULL, 0, alien_addr, af, route_prefix);
    set_iut_route(pco_iut, iut_if1, tos_x, &rh1, use_rules,
                  &rule_tos_x, &rule_tos_x_added, TABLE_TOS_X,
                  alien_addr, af, route_prefix);
    set_iut_route(pco_iut, iut_if2, tos_y, &rh2, use_rules,
                  &rule_tos_y, &rule_tos_y_added, TABLE_TOS_Y,
                  alien_addr, af, route_prefix);
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a connection according to @p sock_type parameter.");
    sockts_connection(SOCKTS_RT_PCO_IUT_SOCK, pco_tst1,
                      SOCKTS_RT_IUT_ADDR1, alien_addr,
                      sock_type,
                      FALSE, TRUE, NULL,
                      &iut_s, &tst_s, &iut_l,
                      SOCKTS_SOCK_FUNC_SOCKET);

    if (null_alien_addr)
        alien_addr = NULL;

    TEST_STEP("Send three packets with zero TOS");
    for (i = 0; i < 3; i++)
    {
        test_send(SOCKTS_RT_PCO_IUT_SOCK, pco_tst1, iut_s, tst_s,
                  alien_addr, 0, with_cmsg);
    }

    TEST_STEP("Check that packets with initial TOS were captured "
              "on the first interface");
    CHECK_TWO_IFS_IN(&tst1_if_monitor, &tst2_if_monitor,
                     TRUE, FALSE, "Initial route");

    TEST_STEP("If @p with_cmsg is @c FALSE, use "
              "@b setsockopt(@c IP_TOS) to set "
              "the first TOS value for the IUT socket.");
    TEST_STEP("Send a few packets from IUT, receiving "
              "them on peer. If @p with_cmsg is "
              "@c TRUE, set @c IP_TOS to the first "
              "value in control message for IUT "
              "packets.");
    test_send(SOCKTS_RT_PCO_IUT_SOCK, pco_tst1, iut_s, tst_s,
              alien_addr, tos_x, with_cmsg);

    TEST_STEP("Checking that CSAP captured packets "
              "only on the first Tester interface");
    CHECK_TWO_IFS_IN(&tst1_if_monitor, &tst2_if_monitor,
                     TRUE, FALSE, "TOS_X route");

    TEST_STEP("If @c with_cmsg is @c FALSE, use "
              "@b setsockopt(@c IP_TOS) to set "
              "the second TOS value for the IUT socket.");
    TEST_STEP("Send a few packets from IUT, receiving "
              "them on peer. If @p with_cmsg is "
              "@c TRUE, set @c IP_TOS to the second "
              "value in control message for IUT "
              "packets.");
    test_send(SOCKTS_RT_PCO_IUT_SOCK, pco_tst1, iut_s, tst_s,
              alien_addr, tos_y, with_cmsg);

    TEST_STEP("Checking that CSAP captured packets "
              "only on the second Tester interface");
    CHECK_TWO_IFS_IN(&tst1_if_monitor, &tst2_if_monitor,
                     FALSE, TRUE, "TOS_Y route");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(SOCKTS_RT_PCO_IUT_SOCK, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s);

    CLEANUP_TWO_IFS_MONITORS;

    if (rule_tos_x_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           rule_tos_x.mask, &rule_tos_x));
    if (rule_tos_y_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           rule_tos_y.mask, &rule_tos_y));

    if (tst1_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst1_addr_hndl, FALSE));
    if (tst2_addr_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(tst2_addr_hndl, FALSE));

    if (rh0 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh0));
    if (rh1 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh1));
    if (rh2 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh2));

    TEST_END;
}
