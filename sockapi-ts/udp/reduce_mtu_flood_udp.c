/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2025 Advanced Micro Devices, Inc. */
/*
 * Socket API Test Suite
 *
 * UDP tests
 *
 * $Id$
 */

/** @page udp-reduce_mtu_flood_udp Reduce MTU while sending a flood of (oversized) UDP packets
 *
 * @objective Reduce MTU while sending a flood of UDP packets with size
 *            equal to initial MTU. Then check that eventually the TST side
 *            sees UDP packets after some lost ones.
 *
 * @param env           Testing environment:
 *                          - @ref arg_types_env_peer2peer
 * @param route_direct  Use direct route or not
 *                      - @c TRUE - use default prefix length
 *                      - @c FALSE - use 24 for prefix length
 * @param from_tst      Send from @p pco_tst to @p pco_iut or vice versa
 *
 * @par Test sequence:
 *
 * @author Nikolai Kosovskii <Nikolai.Kosovskii@arknetworks.am>
 */

#define TE_TEST_NAME  "udp/reduce_mtu_flood_udp"

#include "../sockopts/lib/sockopts_common.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"
#include "te_ethernet.h"

#define SENDER_TIME_SEC 10
#define RECEIVER_TIME_SEC 13
#define RECEIVER_TO_SENDER_DELAY_MS 100
#define SENDER_TO_CHANGE_MTU_DELAY_MS 1000
#define MAX_PERCENT_ALLOWED_TO_BE_DROPPED 0.01
#define LENGTH_RESERVED_FOR_HEADERS 100

/* Check ipv4 or ipv6 is using in test */
bool
ip_version_6(const struct sockaddr *addr)
{
    return addr->sa_family == AF_INET6 ? TRUE : FALSE;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_gw  = NULL;
    tapi_env_host *iut_host  = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int iut_s = -1;
    int tst_s = -1;

    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *gw_iut_addr = NULL;
    const struct sockaddr *gw_tst_addr = NULL;

    struct sockaddr *new_iut_addr = NULL;
    struct sockaddr *new_tst_addr = NULL;
    struct sockaddr *new_gw_iut_addr = NULL;
    struct sockaddr *new_gw_tst_addr = NULL;

    bool neigh_gw_iut_entry_added = FALSE;
    bool neigh_gw_tst_entry_added = FALSE;

    int mtu_gw_saved;
    int mtu_lo_saved;
    int mtu_min_saved;
    int pkt_len;

    uint8_t iut_if_mac[ETHER_ADDR_LEN];
    uint8_t tst_if_mac[ETHER_ADDR_LEN];
    size_t mac_len = ETHER_ADDR_LEN;

    cfg_val_type type = CVT_INTEGER;
    const struct if_nameindex *gw_tst_if = NULL;
    const struct if_nameindex *gw_iut_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    rpc_socket_domain domain;

    cfg_handle net_handle1;
    cfg_handle net_handle2;

    cfg_handle h1 = CFG_HANDLE_INVALID;
    cfg_handle h2 = CFG_HANDLE_INVALID;
    cfg_handle h3 = CFG_HANDLE_INVALID;
    cfg_handle h4 = CFG_HANDLE_INVALID;

    char *net_oid;
    unsigned int net_prefix;

    te_saved_mtus gw_mtus = LIST_HEAD_INITIALIZER(gw_mtus);

    bool route_direct;
    size_t prefix_len;

    bool from_tst = TRUE;

    uint64_t received;
    uint64_t sent;
    rcf_rpc_server *pco_snd = NULL;
    rcf_rpc_server *pco_rcv = NULL;
    int snd_s = -1;
    int rcv_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_HOST(iut_host);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(gw_iut_addr);
    TEST_GET_ADDR_NO_PORT(gw_tst_addr);

    TEST_GET_IF(gw_tst_if);
    TEST_GET_IF(gw_iut_if);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_BOOL_PARAM(route_direct);

    TEST_GET_BOOL_PARAM(from_tst);

    domain = rpc_socket_domain_by_addr(tst_addr);

    prefix_len = (route_direct ? te_netaddr_get_size(
                  addr_family_rpc2h(sockts_domain2family(domain))) * 8 : 24);

    if (ip_version_6(tst_addr))
        CHECK_RC(tapi_cfg_alloc_ip6_net(&net_handle1));
    else
        CHECK_RC(tapi_cfg_alloc_ip4_net(&net_handle1));

    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle1, NULL, &new_iut_addr));
    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle1, NULL, &new_gw_iut_addr));
    CHECK_RC(cfg_get_oid_str(net_handle1, &net_oid));
    type = CVT_INTEGER;
    CHECK_RC(cfg_get_instance_fmt(&type, &net_prefix,
                                  "%s/prefix:", net_oid));

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           new_iut_addr, net_prefix, TRUE,
                                           &h1));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_gw->ta, gw_iut_if->if_name,
                                           new_gw_iut_addr, net_prefix, TRUE,
                                           &h2));

    iut_addr = new_iut_addr;
    gw_iut_addr = new_gw_iut_addr;

    if (ip_version_6(tst_addr))
        CHECK_RC(tapi_cfg_alloc_ip6_net(&net_handle2));
    else
        CHECK_RC(tapi_cfg_alloc_ip4_net(&net_handle2));

    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle2, NULL, &new_tst_addr));
    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle2, NULL, &new_gw_tst_addr));
    CHECK_RC(cfg_get_oid_str(net_handle2, &net_oid));
    type = CVT_INTEGER;
    CHECK_RC(cfg_get_instance_fmt(&type, &net_prefix,
                                  "%s/prefix:", net_oid));

    tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                  new_tst_addr, net_prefix, TRUE, &h3);
    tapi_cfg_base_if_add_net_addr(pco_gw->ta, gw_tst_if->if_name,
                                  new_gw_tst_addr, net_prefix, TRUE, &h4);

    tst_addr = new_tst_addr;
    gw_tst_addr = new_gw_tst_addr;

    TEST_STEP("Add route on @p pco_iut: "
              "@p tst_addr via gateway @p gw_iut_addr.");
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
        addr_family_rpc2h(sockts_domain2family(domain)),
        te_sockaddr_get_netaddr(tst_addr),
        prefix_len,
        te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the dst");
    }

    TEST_STEP("Add route on @p pco_tst: "
              "@p iut_addr via gateway @p gw_tst_addr.");
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
        addr_family_rpc2h(sockts_domain2family(domain)),
        te_sockaddr_get_netaddr(iut_addr),
        te_netaddr_get_size(
            addr_family_rpc2h(sockts_domain2family(domain))) * 8,
        te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the src");
    }

    TEST_STEP("Turn on forwarding on @p pco_gw.");
    if (ip_version_6(gw_iut_addr))
        CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                      "net/ipv6/conf/all/forwarding"));
    else
        CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                      "net/ipv4/ip_forward"));

    TEST_STEP("Add neigbor entries to @p pco_gw if IPv6 is used.");
    if (ip_version_6(iut_addr))
    {
        CHECK_RC(tapi_cfg_get_hwaddr(pco_iut->ta, iut_if->if_name,
                                     iut_if_mac, &mac_len));
        CHECK_RC(tapi_update_arp(pco_gw->ta, gw_iut_if->if_name, NULL, NULL,
                                 iut_addr, iut_if_mac, TRUE));
        neigh_gw_iut_entry_added = TRUE;

        CHECK_RC(tapi_cfg_get_hwaddr(pco_tst->ta, tst_if->if_name,
                                     tst_if_mac, &mac_len));
        CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name, NULL, NULL,
                                 tst_addr, tst_if_mac, TRUE));
        neigh_gw_tst_entry_added = TRUE;
    }

    CFG_WAIT_CHANGES;

    TEST_STEP("Retrieve the path MTU of @p pco_gw and @p pco_iut by means "
              "of tapi_cfg_base_if_get_mtu_u().");
    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_gw->ta, gw_tst_if->if_name,
                                        &mtu_gw_saved));
    RING("Current 'gw' %s MTU=%d", gw_tst_if->if_name, mtu_gw_saved);

    CHECK_RC(tapi_cfg_base_if_get_mtu_u(iut_host->ta, iut_if->if_name,
                                        &mtu_lo_saved));
    RING("Current local %s MTU=%d", iut_if->if_name, mtu_lo_saved);

    mtu_min_saved = mtu_gw_saved < mtu_lo_saved ? mtu_gw_saved : mtu_lo_saved;

    TEST_STEP("Create and bind UDP socket on IUT and its peer on Tester. "
              "Connect IUT socket to its peer's address.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (from_tst)
    {
        pco_snd = pco_tst;
        pco_rcv = pco_iut;
        snd_s = tst_s;
        rcv_s = iut_s;
    }
    else
    {
        pco_snd = pco_iut;
        pco_rcv = pco_tst;
        snd_s = iut_s;
        rcv_s = tst_s;
    }

    TEST_STEP("Start to send and receive packets with length equal to MTU "
              "minus 100 reserved for headers for "
              "a while (ignore POLL errors), then reduce MTU by 10 percents.");
    pkt_len = mtu_min_saved - LENGTH_RESERVED_FOR_HEADERS;
    pco_rcv->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_rcv, rcv_s, RECEIVER_TIME_SEC, &received);
    MSLEEP(RECEIVER_TO_SENDER_DELAY_MS);

    pco_snd->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_snd, snd_s, pkt_len, pkt_len, TRUE, 0, 0, TRUE,
                      SENDER_TIME_SEC, &sent, TRUE);
    MSLEEP(SENDER_TO_CHANGE_MTU_DELAY_MS);

    CHECK_RC(tapi_set_if_mtu_smart2(pco_gw->ta, gw_tst_if->if_name,
                                    mtu_min_saved - mtu_min_saved / 10,
                                    &gw_mtus));

    pco_snd->op = RCF_RPC_WAIT;
    rpc_simple_sender(pco_snd, snd_s, pkt_len, pkt_len, TRUE, 0, 0, TRUE,
                      SENDER_TIME_SEC, &sent, TRUE);

    pco_rcv->op = RCF_RPC_WAIT;
    rpc_simple_receiver(pco_rcv, rcv_s, RECEIVER_TIME_SEC, &received);

    if ((sent - received) / (float) sent > MAX_PERCENT_ALLOWED_TO_BE_DROPPED)
    {
        TEST_VERDICT("Too many bytes were not received (%"PRIu64") while "
                     "sent after MTU was reduced", sent - received);
    }
    else
    {
        RING("Not too many bytes were not received (%"PRIu64") while "
             "sent after MTU was reduced", sent - received);
    }

    TEST_STEP("Check the connection.");
    CHECK_RC(sockts_test_send(pco_snd, snd_s, pco_rcv, rcv_s, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (neigh_gw_iut_entry_added)
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_gw->ta, gw_iut_if->if_name,
                 iut_addr));

    if (neigh_gw_tst_entry_added)
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_gw->ta, gw_tst_if->if_name,
                 tst_addr));

    if (tapi_cfg_del_route_via_gw(pco_iut->ta,
                           addr_family_rpc2h(
                                sockts_domain2family(domain)),
                           te_sockaddr_get_netaddr(tst_addr),
                            prefix_len,
                           te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
    {
        ERROR("Cannot delete route to the dst");
        result = EXIT_FAILURE;
    }

    if (tapi_cfg_del_route_via_gw(pco_tst->ta,
                           addr_family_rpc2h(
                               sockts_domain2family(domain)),
                           te_sockaddr_get_netaddr(iut_addr),
                            te_netaddr_get_size(addr_family_rpc2h(
                                sockts_domain2family(domain))) * 8,
                           te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
    {
        ERROR("Cannot delete route to the src");
        result = EXIT_FAILURE;
    }

    if (h1 != CFG_HANDLE_INVALID)
        cfg_del_instance(h1, FALSE);
    if (h2 != CFG_HANDLE_INVALID)
        cfg_del_instance(h2, FALSE);
    if (h3 != CFG_HANDLE_INVALID)
        cfg_del_instance(h3, FALSE);
    if (h4 != CFG_HANDLE_INVALID)
        cfg_del_instance(h4, FALSE);

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&gw_mtus));

    TEST_END;
}
