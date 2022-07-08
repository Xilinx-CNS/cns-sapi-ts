/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-xdp_lpm_rule Filtering by the longest prefix match rule
 *
 * @objective Check that XDP program applies action by longest prefix
 *            match from rules
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/xdp_lpm_rule"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "tapi_route_gw.h"

/* Name of BPF object. */
#define BPF_OBJ_NAME "xdp_lpm_rule_prog"

/* Name of program in BPF object. */
#define PROGRAM_NAME "xdp_lpm_rule"

/* Names of map in BPF object. */
#define LPM_MAP_NAME "lpm_map"

#define IP4_ADDR_PREFIX_FULL    32
#define IP4_ADDR_PREFIX_SHORT   24
#define IP6_ADDR_PREFIX_FULL    128
#define IP6_ADDR_PREFIX_SHORT   96

/*
 * Update XDP map of type @ref TAPI_BPF_MAP_TYPE_LPM_TRIE. The map key
 * is obtained from @p src_addr and @p prefix. The map value is XDP action.
 *
 * @param pco       RPC server handle
 * @param ifname    Interface name
 * @param bpf_id    BPF object ID
 * @param map       Map name
 * @param src_addr  Address to use as a map key
 * @param prefix    Prefix length of @p src_addr. Can be up to 32 for IPv4
 *                  and 128 for IPv6
 * @param action    XDP action to write to map
 *
 * @return Status code
 */
static te_errno
set_xdp_lpm_rule(rcf_rpc_server *pco, const char *ifname,
                 unsigned int bpf_id, const char *map,
                 const struct sockaddr *src_addr, unsigned int prefix,
                 tapi_bpf_xdp_action action)
{
    struct sockaddr_storage     addr;
    tapi_bpf_lpm_trie_key       prefix_key;

    tapi_sockaddr_clone_exact(src_addr, &addr);
    CHECK_RC(te_sockaddr_cleanup_to_prefix(SA(&addr), prefix));

    prefix_key.prefixlen = prefix;
    memcpy(prefix_key.data, te_sockaddr_get_netaddr(SA(&addr)),
           te_netaddr_get_size(addr.ss_family));

    return sockts_bpf_map_update_kvpair(pco, ifname, bpf_id, map,
                                        (uint8_t *)&prefix_key,
                                        sizeof(prefix_key),
                                        (uint8_t *)&action,
                                        sizeof(action));
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;
    const struct sockaddr      *tst_fake_addr;
    tapi_env_net               *net;

    int                 iut_l = -1;
    int                 iut_s = -1;
    int                 tst_s = -1;
    int                 iut_fake_s = -1;
    int                 tst_fake_s = -1;
    char               *bpf_path = NULL;
    unsigned int        bpf_id = 0;
    tqh_strings         xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);
    cfg_handle          handle = CFG_HANDLE_INVALID;
    unsigned int        prefix_full = IP4_ADDR_PREFIX_FULL;
    unsigned int        prefix_short = IP4_ADDR_PREFIX_SHORT;
    te_bool             ip6_env = FALSE;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);

    ip6_env = rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET6;

    if (ip6_env)
    {
        prefix_full = IP6_ADDR_PREFIX_FULL;
        prefix_short = IP6_ADDR_PREFIX_SHORT;
    }

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta,
                 tst_if->if_name, tst_fake_addr,
                 ip6_env ? net->ip4pfx : net->ip4pfx,
                 FALSE, &handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Add and load to kernel BPF object @c BPF_OBJ_NAME on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, BPF_OBJ_NAME);
    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if->if_name, bpf_path,
                                 TAPI_BPF_PROG_TYPE_XDP, &bpf_id));

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, PROGRAM_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, LPM_MAP_NAME));

    TEST_STEP("Create a listening socket on IUT.");
    iut_l = rpc_stream_server(pco_iut, RPC_PROTO_DEF, FALSE, iut_addr);
    if (iut_l < 0)
        TEST_FAIL("Failed to create connection");

    TEST_STEP("Establish connection from @p tst_addr.");
    tst_s = rpc_stream_client(pco_tst,
                         rpc_socket_domain_by_addr(tst_addr),
                         RPC_PROTO_DEF, tst_addr);
    if (tst_s < 0)
        TEST_FAIL("Failed to create connection");

    rpc_connect(pco_tst, tst_s, iut_addr);
    iut_s = rpc_accept(pco_iut, iut_l, NULL, NULL);

    TEST_STEP("Establish connection from @p tst_addr_fake.");
    tst_fake_s = rpc_stream_client(pco_tst,
                         rpc_socket_domain_by_addr(tst_fake_addr),
                         RPC_PROTO_DEF, tst_fake_addr);
    if (tst_fake_s < 0)
        TEST_FAIL("Failed to create connection");

    rpc_connect(pco_tst, tst_fake_s, iut_addr);
    iut_fake_s = rpc_accept(pco_iut, iut_l, NULL, NULL);

    TEST_STEP("Check that data can be passed from Tester to IUT.");
    rc = sockts_test_send(pco_tst, tst_s, pco_iut, iut_s,
                          NULL, NULL, RPC_PF_UNKNOWN, FALSE,
                          "Normal connection before linking XDP program");
    if (rc != 0)
        TEST_STOP;

    TEST_STEP("Set the rules for XDP program.");
    rc = sockts_test_send(pco_tst, tst_fake_s, pco_iut, iut_fake_s,
                          NULL, NULL, RPC_PF_UNKNOWN, FALSE,
                          "Fake connection before linking XDP program");
    if (rc != 0)
        TEST_STOP;

    TEST_SUBSTEP("Add writable view to the map @c LPM_MAP_NAME.");
    CHECK_RC(sockts_bpf_map_set_writable(pco_iut, iut_if->if_name,
                                         bpf_id, LPM_MAP_NAME));

    TEST_SUBSTEP("Set @c XDP_PASS action to the rule that match "
                 "full prefix subnet.");
    CHECK_RC(set_xdp_lpm_rule(pco_iut, iut_if->if_name,
                              bpf_id, LPM_MAP_NAME, tst_addr,
                              prefix_full, TAPI_BPF_XDP_PASS));

    TEST_SUBSTEP("Set @c XDP_DROP action to the rule that match "
                 "short prefix subnet.");
    CHECK_RC(set_xdp_lpm_rule(pco_iut, iut_if->if_name,
                              bpf_id, LPM_MAP_NAME, tst_addr,
                              prefix_short, TAPI_BPF_XDP_DROP));

    TEST_STEP("Link XDP program @c PROGRAM_NAME to interface on IUT.");
    sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id, PROGRAM_NAME,
                             TRUE, &xdp_ifaces);

    TEST_STEP("Send some data to IUT from @p tst_addr and check that "
              "traffic can pass successfully.");
    /*
     * This connection matches the full prefix key rule. According to the
     * rule, XDP program passes this traffic.
     */
    rc = sockts_test_send(pco_tst, tst_s, pco_iut, iut_s,
                          NULL, NULL, RPC_PF_UNKNOWN, FALSE,
                          "Normal connection after linking XDP program");
    if (rc != 0)
    {
        TEST_VERDICT("Sending data to IUT from address that "
                     "matches XDP_PASS rule unexpectedly failed");
    }

    TEST_STEP("Send some data to IUT from @p tst_fake_addr and check that "
              "traffic does not pass.");
    /*
     * This connection matches the short prefix key rule. According to the
     * rule, XDP program drops this traffic.
     */
    rc = sockts_test_send(pco_tst, tst_fake_s, pco_iut, iut_fake_s,
                          NULL, NULL, RPC_PF_UNKNOWN, FALSE,
                          "Fake connection after linking XDP program");
    if (rc == 0)
    {
        TEST_VERDICT("Sending data to IUT from address that "
                     "matches XDP_DROP rule unexpectedly succeed.");
    }

    TEST_SUCCESS;

cleanup:
    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name, &xdp_ifaces);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_fake_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fake_s);

    free(bpf_path);
    if (bpf_id != 0)
        sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id);
    if (handle != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(handle, FALSE));

    TEST_END;
}
