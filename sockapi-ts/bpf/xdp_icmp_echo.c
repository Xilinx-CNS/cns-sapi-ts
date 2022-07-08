/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-xdp_icmp_echo XDP process ICMP echo messages
 *
 * @objective   Check that XDP program can work with ICMPv4/ICMPv6 messages
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 *
 * @par Scenario:
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/xdp_icmp_echo"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "conf_api.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_bpf.h"

/* Name of BPF object. */
#define BPF_OBJ_NAME "xdp_icmp_echo_prog"

/* Name of program in BPF object. */
#define XDP_PROG_NAME "xdp_icmp_echo"

/* Names of map in BPF object. */
#define MAP_ICMP_CNT "pkt_cnt"

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
    uint32_t            iut_pkts;
    uint32_t            tst_pkts;

    csap_handle_t       csap = CSAP_INVALID_HANDLE;
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

    TEST_STEP("Add and load into the kernel @c BPF_OBJ_NAME on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, BPF_OBJ_NAME);
    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if->if_name, bpf_path,
                                 TAPI_BPF_PROG_TYPE_XDP, &bpf_id));

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name, bpf_id, XDP_PROG_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name, bpf_id, MAP_ICMP_CNT));

    TEST_STEP("Create and start CSAP on Tester to count all sent packets.");
    CHECK_RC(tapi_ip_eth_csap_create(pco_tst->ta, 0, tst_if->if_name,
                                     TAD_ETH_RECV_OUT,
                                     (const uint8_t *)iut_lladdr->sa_data,
                                     (const uint8_t *)tst_lladdr->sa_data,
                                     iut_addr->sa_family,
                                     te_sockaddr_get_netaddr(iut_addr),
                                     te_sockaddr_get_netaddr(tst_addr),
                                     -1, &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    TEST_STEP("Link @c XDP_PROG_NAME to interface on IUT.");
    sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id,
                             XDP_PROG_NAME, TRUE, &xdp_ifaces);
    CFG_WAIT_CHANGES;

    TEST_STEP("Send ICMPv4/ICMPv6 echo requests from Tester to IUT three times.");
    tapi_rpc_provoke_arp_resolution(pco_tst, iut_addr);
    tapi_rpc_provoke_arp_resolution(pco_tst, iut_addr);
    tapi_rpc_provoke_arp_resolution(pco_tst, iut_addr);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Stop CSAP and get number of sent packets.");
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, csap, NULL, &tst_pkts));

    TEST_STEP("Get number of packets from the map @c MAP_ICMP_CNT.");
    CHECK_RC(sockts_bpf_map_lookup_kvpair(pco_iut, iut_if->if_name,
                                          bpf_id, MAP_ICMP_CNT,
                                          (uint8_t *)&key, sizeof(key),
                                          (uint8_t *)&iut_pkts,
                                          sizeof(iut_pkts)));

    RING("Number of processed packets is %u.", iut_pkts);

    TEST_STEP("Check that number of sent packets from Tester is equal to "
              "number of packets that are processed by XDP program.");
    if (iut_pkts != tst_pkts)
    {
        TEST_ARTIFACT("(processed packets: %u) != (sent packets: %u)",
                      iut_pkts, tst_pkts);
        if (iut_pkts == 0)
        {
            TEST_VERDICT("No ICMP messages were processed");
        }
        else
        {
            TEST_VERDICT("Numbers of sent and processed ICMP messages aren't "
                         "equal");
        }
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
