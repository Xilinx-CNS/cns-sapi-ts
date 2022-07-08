/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-xdp_maps XDP with array and hash map types
 *
 * @objective   Check that XDP program can work with array and hash maps
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type Socket type:
 *                  - UDP
 *                  - TCP active
 *                  - TCP passive
 * @param map_type  Link XDP program to IUT interface:
 *                  - array
 *                  - hash
 *
 * @par Scenario:
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/xdp_maps"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "conf_api.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_bpf.h"
#include "tapi_ip_common.h"

/* Name of BPF object. */
#define BPF_OBJ_NAME "xdp_maps_prog"

/* Name of program in BPF object. */
#define XDP_PROG_NAME "xdp_maps"

/* Names of maps in BPF object. */
#define MAP_HASH_NAME    "map_hash"
#define MAP_ARRAY_NAME   "map_array"
#define MAP_SELECT_NAME  "map_select"

#define BPF_MAP_TYPE                \
    {"hash",  TAPI_BPF_MAP_TYPE_HASH},   \
    {"array", TAPI_BPF_MAP_TYPE_ARRAY}

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

    unsigned int        bpf_id = 0;
    uint32_t            key = 0;
    uint32_t            hash = 0xAABBCCDD;
    uint32_t            hash_init_val = 0;
    uint32_t            iut_pkts;
    uint32_t            tst_pkts;

    csap_handle_t       csap = CSAP_INVALID_HANDLE;
    sockts_socket_type  sock_type;
    rpc_socket_type     rpc_sock_type;
    int                 map_type;
    int                 iut_s = -1;
    int                 tst_s = -1;
    char               *bpf_path = NULL;
    tqh_strings         xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_ENUM_PARAM(map_type, BPF_MAP_TYPE);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    TEST_STEP("Add and load into the kernel @c BPF_OBJ_NAME on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, BPF_OBJ_NAME);
    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if->if_name, bpf_path,
                                 TAPI_BPF_PROG_TYPE_XDP, &bpf_id));

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, XDP_PROG_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_HASH_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_ARRAY_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_SELECT_NAME));

    TEST_STEP("Add writable view to the @c MAP_SELECT_NAME.");
    CHECK_RC(sockts_bpf_map_set_writable(pco_iut, iut_if->if_name,
                                         bpf_id, MAP_SELECT_NAME));

    TEST_STEP("Write @p map_type to the @c MAP_SELECT_NAME.");
    CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                          bpf_id, MAP_SELECT_NAME,
                                          (uint8_t *)&key, sizeof(key),
                                          (uint8_t *)&map_type, sizeof(map_type)));

    TEST_STEP("Initialize hash map in the BPF object.");
    CHECK_RC(sockts_bpf_map_set_writable(pco_iut, iut_if->if_name,
                                         bpf_id, MAP_HASH_NAME));
    CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                          bpf_id, MAP_HASH_NAME,
                                          (uint8_t *)&hash, sizeof(hash),
                                          (uint8_t *)&hash_init_val,
                                          sizeof(hash_init_val)));
    CHECK_RC(sockts_bpf_map_unset_writable(pco_iut, iut_if->if_name, bpf_id, MAP_HASH_NAME));

    TEST_STEP("Create connections according to @p sock_type.");
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      FALSE, FALSE, NULL, &iut_s, &tst_s, NULL,
                      SOCKTS_SOCK_FUNC_SOCKET);

    TEST_STEP("Create and start CSAP on Tester to count all sent packets.");
    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                    pco_tst->ta, 0, tst_if->if_name,
                    TAD_ETH_RECV_OUT,
                    (const uint8_t *)iut_lladdr->sa_data,
                    (const uint8_t *)tst_lladdr->sa_data,
                    tst_addr->sa_family,
                    (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                    TAD_SA2ARGS(NULL, NULL),
                    &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    TEST_STEP("Link @c XDP_PROG_NAME to interface on IUT.");
    sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id,
                             XDP_PROG_NAME, TRUE, &xdp_ifaces);
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that accepted connections can send/receive data. "
              "Close them.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);
    CHECK_RC(rpc_closesocket(pco_iut, iut_s));
    CHECK_RC(rpc_closesocket(pco_tst, tst_s));

    TEST_STEP("Stop CSAP and get number of sent packets.");
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, csap, NULL, &tst_pkts));

    TEST_STEP("Get number of packets from the map according to @p map_type.");
    if (map_type == TAPI_BPF_MAP_TYPE_HASH)
    {
        CHECK_RC(sockts_bpf_map_lookup_kvpair(pco_iut,
                    iut_if->if_name, bpf_id, MAP_HASH_NAME,
                    (uint8_t *)&hash, sizeof(hash),
                    (uint8_t *)&iut_pkts, sizeof(iut_pkts)));
    }
    else
    {
        CHECK_RC(sockts_bpf_map_lookup_kvpair(pco_iut,
                    iut_if->if_name, bpf_id, MAP_ARRAY_NAME,
                    (uint8_t *)&key, sizeof(key),
                    (uint8_t *)&iut_pkts, sizeof(iut_pkts)));
    }

    RING("Number of packets from the %s is %u.",
         map_type == TAPI_BPF_MAP_TYPE_HASH ? MAP_HASH_NAME : MAP_ARRAY_NAME,
         iut_pkts);


    TEST_STEP("Check that number of sent packets from Tester is equal to "
              "number of packets that are processed by XDP program.");
    if (iut_pkts == 0)
    {
        TEST_VERDICT("XDP program processed zero packets.");
    }
    else if (iut_pkts != tst_pkts)
    {
        TEST_ARTIFACT("(processed packets: %u) != (sent packets: %u)",
                      iut_pkts, tst_pkts);

        TEST_VERDICT("Numbers of sent and processed packets aren't equal.");
    }

    TEST_SUCCESS;

cleanup:
    free(bpf_path);
    tapi_tad_csap_destroy(pco_tst->ta, 0, csap);
    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name, &xdp_ifaces);
    if (bpf_id != 0)
        sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id);
    TEST_END;
}
