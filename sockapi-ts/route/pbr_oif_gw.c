/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-pbr_oif_gw Using outgoing interface rule to determine gateway
 *
 * @objective Check that outgoing interface rule works for a socket for which
 *            @c SO_BINDTODEVICE was set, so that a route from selected table is
 *            used to determine gateway.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param rt_sock_type  Socket types:
 *                      - tcp_active
 *                      - tcp_passive
 *                      - udp
 *                      - udp_connect
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/pbr_oif_gw"

#include "sockapi-test.h"
#include "tapi_ip_common.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"
#include "ts_route.h"
#include "te_ethernet.h"
#include "tapi_proc.h"

/** Name of MAC VLAN interface to be used if its creation is required. */
#define MAC_VLAN_NAME "tst_macvlan"

/**
 * Check that source address of a packet sent from IUT
 * depends on whether SO_BINDTODEVICE was set or not.
 *
 * @param pco_iut         RPC server on IUT.
 * @param pco_tst         RPC server on Tester.
 * @param rt_sock_type    Socket type to check.
 * @param iut_if          IUT network interface.
 * @param iut_addr        IP address assigned to IUT interface.
 * @param tst_addr        IP address assigned to the first Tester interface.
 * @oaram bind_to_device  Whether SO_BINDTODEVICE should be set. It is
 *                        expected that if it is set, only the second
 *                        CSAP will catch packets; otherwise only
 *                        the first one will catch them.
 * @param tst_csap1       CSAP on the first Tester interface.
 * @param tst_csap2       CSAP on the second Tester interface.
 */
static void
check_gw_addr(rcf_rpc_server *pco_iut,
              rcf_rpc_server *pco_tst,
              sockts_socket_type rt_sock_type,
              const struct if_nameindex *iut_if,
              const struct sockaddr *iut_addr,
              const struct sockaddr *tst_addr,
              te_bool bind_to_device,
              csap_handle_t tst_csap1,
              csap_handle_t tst_csap2)
{
    const char *msg = NULL;

    unsigned int csap1_num = 0;
    unsigned int csap2_num = 0;

    if (bind_to_device)
    {
        msg = "Checking with SO_BINDTODEVICE";
        snprintf(sockts_rt_opt_iut_bind_dev,
                 IFNAMSIZ, iut_if->if_name);
    }
    else
    {
        msg = "Checking without SO_BINDTODEVICE";
        sockts_rt_opt_iut_bind_dev[0] = '\0';
    }

    CHECK_RC(sockts_rt_check_route(rt_sock_type, pco_iut, iut_addr,
                                   pco_tst, tst_addr,
                                   SOCKTS_ADDR_SPEC, FALSE, msg));

    /* Ensure that CSAP gets all the packets. */
    TAPI_WAIT_NETWORK;

    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, tst_csap1, NULL,
                                 &csap1_num));

    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, tst_csap2, NULL,
                                 &csap2_num));

    if (bind_to_device)
    {
        if (csap1_num > 0)
            ERROR_VERDICT("%s: packets were detected on the "
                          "first Tester interface", msg);
        if (csap2_num == 0)
            ERROR_VERDICT("%s: packets were not detected on the "
                          "second Tester interface", msg);
    }
    else
    {
        if (csap1_num == 0)
            ERROR_VERDICT("%s: packets were not detected on the "
                          "first Tester interface", msg);
        if (csap2_num > 0)
            ERROR_VERDICT("%s: packets were detected on the "
                          "second Tester interface", msg);
    }
}

/**
 * Check that traffic is accelerated or not as expected. If traffic is
 * accelerated, only the first packet may be detected.
 *
 * @param env_        Test environment.
 * @param rpcs_       RPC server handle.
 * @param csap_       CSAP capturing outgoing packets.
 * @param if_name_    Interface name.
 * @param msg_        Message to print in verdicts.
 */
#define CHECK_TRAFFIC_ACCELERATED(env_, rpcs_, csap_, if_name_, msg_) \
    do {                                                              \
        unsigned int pkts_num_ = 0;                                   \
                                                                      \
        CHECK_RC(tapi_tad_trrecv_get(rpcs_->ta, 0, csap_, NULL,       \
                                     &pkts_num_));                    \
                                                                      \
        if (sockts_if_accelerated(&env_, rpcs_->ta, if_name_))        \
        {                                                             \
            if (pkts_num_ > 1)                                        \
                ERROR_VERDICT("%s: more than one "                    \
                              "outgoing packet was detected", msg_);  \
        }                                                             \
        else                                                          \
        {                                                             \
            if (pkts_num_ <= 1)                                       \
                ERROR_VERDICT("%s: some outgoing packets "            \
                              "were not detected", msg_);             \
        }                                                             \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    struct sockaddr        *tst_addr2 = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    tapi_env_net    *net = NULL;

    char                     tst_if2_name[IF_NAMESIZE] = MAC_VLAN_NAME;
    struct sockaddr          tst_if2_mac;
    te_bool                  tst_if2_added = FALSE;
    const struct sockaddr   *tst_lladdr;

    sockts_socket_type    rt_sock_type;
    rpc_socket_type       sock_type;

    cfg_handle      rh1 = CFG_HANDLE_INVALID;
    cfg_handle      rh2 = CFG_HANDLE_INVALID;
    cfg_handle      ah1 = CFG_HANDLE_INVALID;
    cfg_handle      ah2 = CFG_HANDLE_INVALID;

    te_conf_ip_rule ip_rule;
    te_bool         rule_added = FALSE;

    csap_handle_t iut_csap1 = CSAP_INVALID_HANDLE;
    csap_handle_t iut_csap2 = CSAP_INVALID_HANDLE;
    csap_handle_t tst_csap1 = CSAP_INVALID_HANDLE;
    csap_handle_t tst_csap2 = CSAP_INVALID_HANDLE;

    int           af;
    int           route_prefix;
    int           domain;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    GET_DOMAIN_AF_PREFIX(iut_addr, domain, af, route_prefix);
    sock_type = sock_type_sockts2rpc(rt_sock_type);

    TEST_STEP("Add MAC VLAN interface @b tst_if2_name over @p tst_if, "
              "get its MAC address @b tst_if2_mac.");

    CHECK_RC(tapi_cfg_base_if_add_macvlan(pco_tst->ta,
                                          tst_if->if_name,
                                          tst_if2_name,
                                          NULL));
    tst_if2_added = TRUE;

    CHECK_RC(tapi_cfg_base_if_get_link_addr(pco_tst->ta,
                                            tst_if2_name,
                                            &tst_if2_mac));
    sockts_rt_fix_macvlan_conf(pco_tst->ta, tst_if->if_name);
    sockts_rt_fix_macvlan_conf(pco_tst->ta, tst_if2_name);

    TEST_STEP("Allocate additional IP address @b tst_addr2 and assign it "
              "to @b tst_if2_name interface.");
    CHECK_RC(tapi_cfg_alloc_net_addr((af == AF_INET ? net->ip4net :
                                                      net->ip6net),
                                     &ah1, &tst_addr2));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(
                                        pco_tst->ta,
                                        tst_if2_name,
                                        tst_addr2,
                                        (af == AF_INET ? net->ip4pfx :
                                                         net->ip6pfx),
                                        FALSE, &ah2));

    TEST_STEP("Remove ARP entry for @b tst_addr2 on IUT, if it is present.");
    CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                              iut_if->if_name,
                                              tst_addr2));

    TEST_STEP("IUT: ip route add @p tst_addr dev @p iut_if");

    CHECK_RC(tapi_cfg_add_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(tst_addr),
                        route_prefix, NULL, iut_if->if_name,
                        NULL, 0, 0, 0, 0, 0, 0,
                        &rh1));

    TEST_STEP("IUT: ip rule add oif @p iut_if table @c SOCKTS_RT_TABLE_FOO");

    te_conf_ip_rule_init(&ip_rule);
    ip_rule.mask |= TE_IP_RULE_FLAG_FAMILY;
    ip_rule.family = af;
    ip_rule.mask |= TE_IP_RULE_FLAG_OIFNAME;
    sprintf(ip_rule.oifname, iut_if->if_name);
    ip_rule.mask |= TE_IP_RULE_FLAG_TABLE;
    ip_rule.table = SOCKTS_RT_TABLE_FOO;
    CHECK_RC(tapi_cfg_add_rule(pco_iut->ta, af, &ip_rule));
    rule_added = TRUE;

    TEST_STEP("IUT: ip route add @p tst_addr dev @p iut_if "
              "via @b tst_addr2 table @c SOCKTS_RT_TABLE_FOO");

    CHECK_RC(tapi_cfg_add_full_route(
                        pco_iut->ta, af,
                        te_sockaddr_get_netaddr(tst_addr),
                        route_prefix,
                        te_sockaddr_get_netaddr(tst_addr2),
                        iut_if->if_name,
                        NULL, NULL, 0, 0, 0, 0, 0, 0,
                        SOCKTS_RT_TABLE_FOO, &rh2));

    CFG_WAIT_CHANGES;

    CHECK_RC(tapi_ip_eth_csap_create(pco_iut->ta, 0,
                                     iut_if->if_name,
                                     TAD_ETH_RECV_OUT |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     (uint8_t *)tst_lladdr->sa_data,
                                     NULL, af,
                                     te_sockaddr_get_netaddr(tst_addr),
                                     te_sockaddr_get_netaddr(iut_addr),
                                     (sock_type == RPC_SOCK_STREAM ?
                                               IPPROTO_TCP : IPPROTO_UDP),
                                     &iut_csap1));

    CHECK_RC(tapi_ip_eth_csap_create(pco_iut->ta, 0,
                                     iut_if->if_name,
                                     TAD_ETH_RECV_OUT |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     (uint8_t *)tst_if2_mac.sa_data,
                                     NULL, af,
                                     te_sockaddr_get_netaddr(tst_addr),
                                     te_sockaddr_get_netaddr(iut_addr),
                                     (sock_type == RPC_SOCK_STREAM ?
                                               IPPROTO_TCP : IPPROTO_UDP),
                                     &iut_csap2));

    CHECK_RC(tapi_ip_eth_csap_create(pco_tst->ta, 0,
                                     tst_if->if_name,
                                     TAD_ETH_RECV_HOST |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     (uint8_t *)tst_lladdr->sa_data,
                                     NULL, af,
                                     te_sockaddr_get_netaddr(tst_addr),
                                     te_sockaddr_get_netaddr(iut_addr),
                                     (sock_type == RPC_SOCK_STREAM ?
                                               IPPROTO_TCP : IPPROTO_UDP),
                                     &tst_csap1));

    CHECK_RC(tapi_ip_eth_csap_create(pco_tst->ta, 0,
                                     tst_if2_name,
                                     TAD_ETH_RECV_HOST |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     (uint8_t *)tst_if2_mac.sa_data,
                                     NULL, af,
                                     te_sockaddr_get_netaddr(tst_addr),
                                     te_sockaddr_get_netaddr(iut_addr),
                                     (sock_type == RPC_SOCK_STREAM ?
                                               IPPROTO_TCP : IPPROTO_UDP),
                                     &tst_csap2));

    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, 0, iut_csap1, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_COUNT));

    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, 0, iut_csap2, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_COUNT));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, tst_csap1, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_COUNT));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, tst_csap2, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_COUNT));
    /* Ensure that CSAPs have really started. */
    TAPI_WAIT_NETWORK;

    TEST_STEP("Create a pair of sockets on IUT and Tester according to "
              "@p rt_sock_type. Check that a packet sent from IUT to "
              "@p tst_addr has MAC address of @p tst_if as destination.");
    check_gw_addr(pco_iut, pco_tst, rt_sock_type, iut_if,
                   iut_addr, tst_addr, FALSE,
                   tst_csap1, tst_csap2);

    TEST_STEP("Create another pair of sockets on IUT and Tester according to "
              "@p rt_sock_type. Set @c SO_BINDTODEVICE option for IUT socket "
              "to @p iut_if name. Check that a packet sent from IUT to "
              "@p tst_addr has MAC address of @b tst_if2_name interface as "
              "destination.");
    check_gw_addr(pco_iut, pco_tst, rt_sock_type, iut_if,
                  iut_addr, tst_addr, TRUE,
                  tst_csap1, tst_csap2);

    TEST_STEP("Check that on Onload outgoing traffic is accelerated on IUT "
              "(only the first packets may be detected), and on Linux it "
              "is not.");
    CHECK_TRAFFIC_ACCELERATED(env, pco_iut, iut_csap1, iut_if->if_name,
                              "Checking the first route");
    CHECK_TRAFFIC_ACCELERATED(env, pco_iut, iut_csap2, iut_if->if_name,
                              "Checking the second route");

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, iut_csap1));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, iut_csap2));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, tst_csap1));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, tst_csap2));

    if (rh2 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh2));
    if (rh1 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rh1));

    if (rule_added)
    {
        CLEANUP_CHECK_RC(tapi_cfg_del_rule(pco_iut->ta, af,
                                           ip_rule.mask, &ip_rule));
    }

    if (ah2 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(ah2, FALSE));
    if (ah1 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_free_entry(&ah1));

    CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                              iut_if->if_name,
                                              tst_addr2));

    if (tst_if2_added)
        CLEANUP_CHECK_RC(
                    tapi_cfg_base_if_del_macvlan(pco_tst->ta,
                                                 tst_if->if_name,
                                                 tst_if2_name));

    free(tst_addr2);

    CFG_WAIT_CHANGES;

    TEST_END;
}
