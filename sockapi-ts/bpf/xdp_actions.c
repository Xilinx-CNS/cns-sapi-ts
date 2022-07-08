/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-xdp_actions Base BPF programs actions
 *
 * @objective  Check that BPF program can pass or drop packets
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type Socket type:
 *                  - udp
 *                  - TCP active
 *                  - TCP passive
 * @param action    XDP action:
 *                  - pass
 *                  - drop
 * @param parent_if How to attach BPF program:
 *                  - @c TRUE: attach to parent physical interfaces
 *                  - @c FALSE: attach to current working interface
 *                  (vlan, macvlan, ipvlan, bond, team)
 * @param link_type Type of BPF link point:
 *                  - bpf
 *                  - tc_ingress
 *
 * @par Scenario:
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/xdp_actions"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "conf_api.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_bpf.h"
#include "tapi_cfg_qdisc.h"
#include "te_string.h"
#include "tapi_ip_common.h"

/**
 * List of actions, to be passed to TEST_GET_ENUM_PARAM().
 */
#define ACTION              \
    { "pass",   TEST_BPF_PASS }, \
    { "drop",   TEST_BPF_DROP }

/**
 * List of BPF link point types.
 */
#define BPF_LINK_POINT_TYPES \
    { "xdp",        TAPI_BPF_LINK_XDP },        \
    { "tc_ingress", TAPI_BPF_LINK_TC_INGRESS }

/**
 * Get BPF link point type.
 */
#define GET_BPF_LINK_POINT_TYPE(_bpf_link_point_type) \
    TEST_GET_ENUM_PARAM(_bpf_link_point_type, BPF_LINK_POINT_TYPES)

/* Name of BPF object. */
#define BPF_XDP_OBJ_NAME "xdp_actions_prog"
#define BPF_TC_OBJ_NAME "tc_actions_prog"

/* Name of program in BPF object. */
#define XDP_PROGRAM_NAME "xdp_actions"
#define TC_PROGRAM_NAME "tc_actions"

/* Names of maps in BPF object. */
#define ACTION_MAP_NAME "test_action"
#define PACKET_COUNT_MAP_NAME "pkt_cnt"

/*
 * Enumeration describing an action to perform by BPF program.
 * The identical enum is declared in the files xdp_actions_prog.c
 * and tc_actions_prog.c
 */
typedef enum test_bpf_action {
    TEST_BPF_DROP,
    TEST_BPF_PASS,
} test_bpf_action;

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *iut_lladdr;
    const struct sockaddr      *tst_lladdr;
    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;

    char               *bpf_path = NULL;
    unsigned int        bpf_id = 0;
    unsigned int        iut_n_pkts;
    test_bpf_action     action;
    unsigned int        key = 0;
    tqh_strings         bpf_ifaces = TAILQ_HEAD_INITIALIZER(bpf_ifaces);
    te_bool             parent_if;

    int                 sid;
    csap_handle_t       csap = CSAP_INVALID_HANDLE;
    sockts_socket_type  sock_type;
    rpc_socket_type     rpc_sock_type;
    int                 iut_s = -1;
    int                 tst_s = -1;
    unsigned int        tst_n_pkts;
    tarpc_linger        zero_linger = {.l_onoff = 1, .l_linger = 0};
    const char         *bpf_obj_name = NULL;
    const char         *bpf_prog_name = NULL;
    tapi_bpf_prog_type  bpf_prog_type;
    tapi_bpf_link_point link_type;
    tqe_string         *iface;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_ENUM_PARAM(action, ACTION);
    TEST_GET_BOOL_PARAM(parent_if);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    GET_BPF_LINK_POINT_TYPE(link_type);

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    switch (link_type)
    {
        case TAPI_BPF_LINK_XDP:
            bpf_prog_type = TAPI_BPF_PROG_TYPE_XDP;
            bpf_obj_name = BPF_XDP_OBJ_NAME;
            bpf_prog_name = XDP_PROGRAM_NAME;
            break;

        case TAPI_BPF_LINK_TC_INGRESS:
            bpf_prog_type = TAPI_BPF_PROG_TYPE_SCHED_CLS;
            bpf_obj_name = BPF_TC_OBJ_NAME;
            bpf_prog_name = TC_PROGRAM_NAME;
            break;

        default:
            TEST_FAIL("Unsupported BPF link point type");
    }

    TEST_STEP("Add and load to kernel BPF object on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, bpf_obj_name);
    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if->if_name,
                                 bpf_path, bpf_prog_type, &bpf_id));

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, bpf_prog_name));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, ACTION_MAP_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name, bpf_id,
                                       PACKET_COUNT_MAP_NAME));

    TEST_STEP("Add writable view to the map @c ACTION_MAP_NAME.");
    CHECK_RC(sockts_bpf_map_set_writable(pco_iut, iut_if->if_name, bpf_id, ACTION_MAP_NAME));

    TEST_STEP("Write @p action to the map @c ACTION_MAP_NAME.");
    CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                          bpf_id, ACTION_MAP_NAME,
                                          (uint8_t *)&key, sizeof(key),
                                          (uint8_t *)&action, sizeof(action)));

    TEST_STEP("Create connection according to @p conn_type.");
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      FALSE, FALSE, NULL, &iut_s, &tst_s, NULL,
                      SOCKTS_SOCK_FUNC_SOCKET);

    if (sock_type == SOCKTS_SOCK_UDP)
    {
        TEST_STEP("In case of @b UDP sockets send one-byte datagram to provoke "
                  "ARP resolution.");
        tapi_rpc_provoke_arp_resolution(pco_iut, tst_addr);
        TAPI_WAIT_NETWORK;
    }
    else
    {
        TEST_STEP("Set @c SO_LINGER option to zero in case of @b TCP sockets.");
        CHECK_RC(rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &zero_linger));
        CHECK_RC(rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER, &zero_linger));
    }

    TEST_STEP("Create and start CSAP on Tester to count all sent packets.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));

    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                    pco_tst->ta, sid, tst_if->if_name,
                    TAD_ETH_RECV_OUT,
                    (const uint8_t *)iut_lladdr->sa_data,
                    (const uint8_t *)tst_lladdr->sa_data,
                    tst_addr->sa_family,
                    (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                    TAD_SA2ARGS(NULL, NULL),
                    &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    TEST_STEP("Link BPF program to the @p link_type point on IUT interface "
              "according to @p parent_if value.");
    if (link_type == TAPI_BPF_LINK_TC_INGRESS)
    {
        if (parent_if)
            sockts_bpf_find_parent_if(pco_iut, iut_if->if_name, &bpf_ifaces);
        else
            CHECK_RC(tq_strings_add_uniq_dup(&bpf_ifaces,
                                             sockts_get_used_if_name(pco_iut,
                                                                     iut_if->if_name)));

        TEST_SUBSTEP("Enable clsact qdisc if @p link_type is \"tc_ingress\".");
        for (iface = TAILQ_FIRST(&bpf_ifaces);
             iface != NULL;
             iface = TAILQ_NEXT(iface, links))
        {
            CHECK_RC(tapi_cfg_qdisc_set_kind(sockts_get_used_agt_name(pco_iut, iface->v),
                                             iface->v,
                                             TAPI_CFG_QDISC_KIND_CLSACT));
            CHECK_RC(tapi_cfg_qdisc_enable(sockts_get_used_agt_name(pco_iut, iface->v),
                                           iface->v));

            rc = tapi_bpf_prog_link(sockts_get_used_agt_name(pco_iut, iface->v),
                                    iface->v,
                                    bpf_id, link_type,
                                    bpf_prog_name);
            if (rc != 0)
            {
                TEST_VERDICT("Failed to link TC ingress program: %r",
                             TE_RC_GET_ERROR(rc));
            }
        }
    }
    else if (link_type == TAPI_BPF_LINK_XDP)
    {
        sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id,
                                 bpf_prog_name, parent_if, &bpf_ifaces);
    }
    else
    {
        TEST_FAIL("Unsupported link point type");
    }

    TEST_STEP("Send packets from IUT and check that they are received on "
              "Tester.");
    CHECK_RC(sockts_test_send(pco_iut, iut_s, pco_tst, tst_s, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));

    TEST_STEP("Send packets from Tester and check that they are received or "
              "dropped on Tester according to @p action.");
    rc = sockts_test_send(pco_tst, tst_s, pco_iut, iut_s, NULL, NULL,
                          RPC_PF_UNSPEC, FALSE, "");
    if ((action == TEST_BPF_DROP && rc != TE_ENODATA) ||
        (action == TEST_BPF_PASS && rc != 0))
    {
        if (rc == 0)
            TEST_VERDICT("Packets were received successfully with DROP action.");
        else
            TEST_FAIL("sockts_test_send() unexpectedly failed with rc = %r.", rc);
    }
    TAPI_WAIT_NETWORK;

    TEST_STEP("Get number of packets from the map @c PACKET_COUNT_MAP_NAME.");
    CHECK_RC(sockts_bpf_map_lookup_kvpair(pco_iut, iut_if->if_name, bpf_id,
                                          PACKET_COUNT_MAP_NAME,
                                          (uint8_t *)&key, sizeof(key),
                                          (uint8_t *)&iut_n_pkts,
                                          sizeof(iut_n_pkts)));
    RING("Number of packets from the map %s is %u.", PACKET_COUNT_MAP_NAME,
         iut_n_pkts);

    TEST_STEP("Get number of sent packets from CSAP.");
    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, sid, csap, NULL, &tst_n_pkts));

    TEST_STEP("Check that number of sent packets from Tester is equal to number "
              "of packets that are processed by XDP program.");
    if (iut_n_pkts != tst_n_pkts)
        TEST_VERDICT("Numbers of sent and processed packets aren't equal.");

    TEST_SUCCESS;

cleanup:
    free(bpf_path);
    tapi_tad_csap_destroy(pco_tst->ta, sid, csap);

    if (parent_if)
    {
        for (iface = TAILQ_FIRST(&bpf_ifaces);
             iface != NULL;
             iface = TAILQ_NEXT(iface, links))
        {
            tapi_bpf_prog_unlink(sockts_get_used_agt_name(pco_iut, iface->v),
                                 iface->v, link_type);
            if (link_type == TAPI_BPF_LINK_TC_INGRESS)
                CLEANUP_CHECK_RC(tapi_cfg_qdisc_disable(
                                 sockts_get_used_agt_name(pco_iut, iface->v),
                                 iface->v));
        }
    }
    else
    {
        tapi_bpf_prog_unlink(sockts_get_used_agt_name(pco_iut, iut_if->if_name),
                             sockts_get_used_if_name(pco_iut, iut_if->if_name),
                             link_type);
        if (link_type == TAPI_BPF_LINK_TC_INGRESS)
                CLEANUP_CHECK_RC(tapi_cfg_qdisc_disable(
                                 sockts_get_used_agt_name(pco_iut, iut_if->if_name),
                                 sockts_get_used_if_name(pco_iut, iut_if->if_name)));
    }

    tq_strings_free(&bpf_ifaces, &free);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (bpf_id != 0)
        sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id);
    TEST_END;
}
