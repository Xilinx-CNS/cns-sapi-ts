/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-xdp_diff_ifs XDP on different interfaces
 *
 * @objective   Check that XDP program can be linked to different interfaces
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_two_links
 *                  - @ref arg_types_env_peer2peer_two_links_ipv6
 * @param sock_type Socket type:
 *                  - UDP
 *                  - TCP active
 *                  - TCP passive
 * @param link_if   Link XDP program to IUT interface:
 *                  - first
 *                  - second
 *                  - both
 *
 * @par Scenario:
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/xdp_diff_ifs"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "conf_api.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_bpf.h"
#include "tapi_ip_common.h"

/* Name of BPF object. */
#define BPF_OBJ_NAME "xdp_diff_ifs_prog"

/* Name of program in BPF object. */
#define XDP_PROG_NAME "xdp_drop"

/* Names of maps in BPF object. */
#define XDP_MAP_NAME "pkt_cnt"

#define XDP_IF1 (1 << 1)
#define XDP_IF2 (1 << 2)

#define XDP_LINK_IF                 \
    {"first",   XDP_IF1},           \
    {"second",  XDP_IF2},           \
    {"both",    XDP_IF1 | XDP_IF2}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;

    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;
    const struct if_nameindex  *tst1_if = NULL;
    const struct if_nameindex  *tst2_if = NULL;

    const struct sockaddr      *iut_if1_hwaddr;
    const struct sockaddr      *iut_if2_hwaddr;
    const struct sockaddr      *tst1_hwaddr;
    const struct sockaddr      *tst2_hwaddr;
    const struct sockaddr      *iut_addr1;
    const struct sockaddr      *iut_addr2;
    const struct sockaddr      *tst1_addr;
    const struct sockaddr      *tst2_addr;

    tarpc_linger                zero_linger = {.l_onoff = 1, .l_linger = 0};

    unsigned int        bpf_id = 0;
    uint32_t            key = 0;
    uint32_t            iut_pkts;
    unsigned int        tst1_pkts;
    unsigned int        tst2_pkts;
    unsigned int        exp_pkts;

    csap_handle_t       csap1 = CSAP_INVALID_HANDLE;
    csap_handle_t       csap2 = CSAP_INVALID_HANDLE;
    sockts_socket_type  sock_type;
    rpc_socket_type     rpc_sock_type;
    int                 iut_s1 = -1;
    int                 iut_s2 = -1;
    int                 tst_s1 = -1;
    int                 tst_s2 = -1;
    int                 link_if;
    char               *bpf_path = NULL;
    tqh_strings         xdp_iut1_ifs = TAILQ_HEAD_INITIALIZER(xdp_iut1_ifs);
    tqh_strings         xdp_iut2_ifs = TAILQ_HEAD_INITIALIZER(xdp_iut2_ifs);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst1_addr);
    TEST_GET_ADDR(pco_tst, tst2_addr);
    TEST_GET_LINK_ADDR(iut_if1_hwaddr);
    TEST_GET_LINK_ADDR(iut_if2_hwaddr);
    TEST_GET_LINK_ADDR(tst1_hwaddr);
    TEST_GET_LINK_ADDR(tst2_hwaddr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_ENUM_PARAM(link_if, XDP_LINK_IF);

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    TEST_STEP("Add and load into the kernel @c BPF_OBJ_NAME on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if1->if_name, BPF_OBJ_NAME);
    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if1->if_name, bpf_path,
                                 TAPI_BPF_PROG_TYPE_XDP, &bpf_id));

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if1->if_name,
                                        bpf_id, XDP_PROG_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if1->if_name,
                                       bpf_id, XDP_MAP_NAME));

    TEST_STEP("Create connections according to @p sock_type.");
    sockts_connection(pco_iut, pco_tst, iut_addr1, tst1_addr, sock_type,
                      FALSE, FALSE, NULL, &iut_s1, &tst_s1, NULL,
                      SOCKTS_SOCK_FUNC_SOCKET);

    sockts_connection(pco_iut, pco_tst, iut_addr2, tst2_addr, sock_type,
                      FALSE, FALSE, NULL, &iut_s2, &tst_s2, NULL,
                      SOCKTS_SOCK_FUNC_SOCKET);

    if (sock_type == SOCKTS_SOCK_UDP)
    {
        TEST_STEP("Provoke ARP resolution in case of @b UDP sockets.");
        tapi_rpc_provoke_arp_resolution(pco_iut, tst1_addr);
        tapi_rpc_provoke_arp_resolution(pco_iut, tst2_addr);
    }
    else
    {
        TEST_STEP("Set @c SO_LINGER option to zero in case of @b TCP sockets "
                  "to force sockets closing because XDP program drops all "
                  "incoming traffic in IUT.");
        CHECK_RC(rpc_setsockopt(pco_iut, iut_s1, RPC_SO_LINGER, &zero_linger));
        CHECK_RC(rpc_setsockopt(pco_iut, iut_s2, RPC_SO_LINGER, &zero_linger));
        CHECK_RC(rpc_setsockopt(pco_tst, tst_s1, RPC_SO_LINGER, &zero_linger));
        CHECK_RC(rpc_setsockopt(pco_tst, tst_s2, RPC_SO_LINGER, &zero_linger));
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Create and start CSAPs on Tester to count all sent packets.");
    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                    pco_tst->ta, 0, tst1_if->if_name,
                    TAD_ETH_RECV_OUT,
                    (const uint8_t *)iut_if1_hwaddr->sa_data,
                    (const uint8_t *)tst1_hwaddr->sa_data,
                    tst1_addr->sa_family,
                    (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                    TAD_SA2ARGS(NULL, NULL),
                    &csap1));

    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                    pco_tst->ta, 0, tst2_if->if_name,
                    TAD_ETH_RECV_OUT,
                    (const uint8_t *)iut_if2_hwaddr->sa_data,
                    (const uint8_t *)tst2_hwaddr->sa_data,
                    tst2_addr->sa_family,
                    (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                    TAD_SA2ARGS(NULL, NULL),
                    &csap2));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap1, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap2, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    TEST_STEP("Link @c XDP_PROG_NAME to IUT interface(s) according to "
              "@p link_if");
    if (link_if & XDP_IF1)
    {
        sockts_bpf_link_xdp_prog(pco_iut, iut_if1->if_name, bpf_id,
                                 XDP_PROG_NAME, TRUE, &xdp_iut1_ifs);
    }

    if (link_if & XDP_IF2)
    {
        sockts_bpf_link_xdp_prog(pco_iut, iut_if2->if_name, bpf_id,
                                 XDP_PROG_NAME, TRUE, &xdp_iut2_ifs);
    }
    CFG_WAIT_CHANGES;

    TEST_STEP("Send packets from both IUT interfaces and check that packets "
              "are received on Tester.");
    CHECK_RC(sockts_test_send(pco_iut, iut_s1, pco_tst, tst_s1, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));
    CHECK_RC(sockts_test_send(pco_iut, iut_s2, pco_tst, tst_s2, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));

    TEST_STEP("Send packets from Tester to first IUT interface and check that "
              "they are passed or dropped on IUT according to @p link_if.");

    rc = sockts_test_send(pco_tst, tst_s1, pco_iut, iut_s1, NULL, NULL,
                          RPC_PF_UNSPEC, FALSE,
                          "Sending from first Tester interface");

    if ((link_if & XDP_IF1 && rc != TE_ENODATA) ||
        (!(link_if & XDP_IF1) && rc != 0))
    {
        TEST_VERDICT("Sending data via the first interface unexpectedly %s%s",
                     rc == 0 ? "succeed" : "failed with error ",
                     rc != 0 ? te_rc_err2str(rc) : "");
    }

    TEST_STEP("Send packets from Tester to second IUT interface and check that "
              "they are passed or dropped on IUT according to @p link_if.");

    rc = sockts_test_send(pco_tst, tst_s2, pco_iut, iut_s2, NULL, NULL,
                          RPC_PF_UNSPEC, FALSE,
                          "Sending from second Tester interface");

    if ((link_if & XDP_IF2 && rc != TE_ENODATA) ||
        (!(link_if & XDP_IF2) && rc != 0))
    {
        TEST_VERDICT("Sending data via the second interface unexpectedly %s%s",
                     rc == 0 ? "succeed" : "failed with error ",
                     rc != 0 ? te_rc_err2str(rc) : "");
    }

    TEST_STEP("Close all opened sockets on IUT and Tester.");
    CHECK_RC(rpc_closesocket(pco_iut, iut_s1));
    CHECK_RC(rpc_closesocket(pco_iut, iut_s2));
    CHECK_RC(rpc_closesocket(pco_tst, tst_s1));
    CHECK_RC(rpc_closesocket(pco_tst, tst_s2));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Stop CSAPs and get number of sent packets.");
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, csap1, NULL, &tst1_pkts));
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, csap2, NULL, &tst2_pkts));

    TEST_STEP("Get number of packets from the @c XDP_MAP_NAME.");
    CHECK_RC(sockts_bpf_map_lookup_kvpair(pco_iut, iut_if1->if_name,
                                          bpf_id, XDP_MAP_NAME,
                                          (uint8_t *)&key, sizeof(key),
                                          (uint8_t *)&iut_pkts,
                                          sizeof(iut_pkts)));

    RING("Number of packets from the map %s is %u.", XDP_MAP_NAME, iut_pkts);

    TEST_STEP("Check that number of sent packets from Tester (taking into "
              "account @p link_if) is equal to number of packets that were "
              "processed by XDP program.");

    exp_pkts = link_if & XDP_IF1 ? tst1_pkts : 0;
    exp_pkts += link_if & XDP_IF2 ? tst2_pkts : 0;

    if (iut_pkts != exp_pkts)
    {
        TEST_ARTIFACT("(processed packets %d) != (expected packets %d)",
                      iut_pkts, exp_pkts);
        TEST_VERDICT("Numbers of sent and processed packets aren't equal.");
    }

    TEST_SUCCESS;

cleanup:
    free(bpf_path);
    tapi_tad_csap_destroy(pco_tst->ta, 0, csap1);
    tapi_tad_csap_destroy(pco_tst->ta, 0, csap2);
    sockts_bpf_unlink_xdp(pco_iut, iut_if2->if_name, &xdp_iut2_ifs);
    sockts_bpf_unlink_xdp(pco_iut, iut_if1->if_name, &xdp_iut1_ifs);
    if (bpf_id != 0)
        sockts_bpf_obj_fini(pco_iut, iut_if1->if_name, bpf_id);
    TEST_END;
}
