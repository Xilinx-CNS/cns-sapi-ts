/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-xdp_perf_event XDP performance events handling
 *
 * @objective Count length of packets and get it with bpf_perf_event
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type Socket type:
 *                  - UDP
 *                  - TCP active
 *                  - TCP passive
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/xdp_perf_event"

#include "sockapi-test.h"
#include "tapi_bpf.h"
#include "sockapi-ts_bpf.h"
#include "tapi_eth.h"

/* Name of BPF object. */
#define BPF_OBJ_NAME "xdp_perf_event_prog"

/* Name of program in BPF object. */
#define PROGRAM_NAME "xdp_perf_event"

/* Name of map. */
#define MAP_NAME "perf_map"

/* Name of map containing 5-tuple rule. */
#define MAP_RULE_NAME "map_rule"

#define PERF_EVENT_COOKIE 0xdead

typedef struct perf_event_data {
    uint16_t cookie;
    uint16_t len;
} perf_event_data;

/* Callback for catching raw packets and counting their length. */
static void
callback(asn_value *packet, void *total_len)
{
    int p_len;

    p_len = asn_get_length(packet, "payload.#bytes");
    if (p_len == -1)
        ERROR("Failed to obtain payload length");
    else
        *(unsigned int *)total_len += p_len;

    asn_free_value(packet);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *iut_lladdr;
    const struct sockaddr      *tst_lladdr;
    unsigned int                bpf_id = 0;
    sockts_socket_type          sock_type;
    int                         iut_s = -1;
    int                         tst_s = -1;
    int                         sid = 0;
    csap_handle_t               csap = CSAP_INVALID_HANDLE;
    unsigned int                tst_pkts_num = 0;
    unsigned int                tst_pkts_total_len = 0;
    unsigned int                xdp_pkts_total_len = 0;
    tapi_tad_trrecv_cb_data    *cb_data = NULL;
    unsigned int                i = 0;
    unsigned int                num_events = 0;
    perf_event_data            *data = NULL;

    tqh_strings     xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);
    char           *bpf_path = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    /* See ST-2014. */
    TEST_STEP("Disable TSO on Tester.");
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(pco_tst->ta,
                                                 tst_if->if_name,
                                                 "tx-tcp-segmentation", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(pco_tst->ta,
                                                 tst_if->if_name,
                                                 "tx-tcp6-segmentation", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(pco_tst->ta,
                                                 tst_if->if_name,
                                                 "tx-udp-segmentation", 0));

    TEST_STEP("Add and load to kernel BPF object @c BPF_OBJ_NAME on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, BPF_OBJ_NAME);
    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if->if_name,
                                 bpf_path, TAPI_BPF_PROG_TYPE_XDP, &bpf_id));

    TEST_STEP("Load connection address/port into @c MAP_RULE_NAME map, to "
              "filter alien traffic.");
    CHECK_RC(sockts_bpf_xdp_load_tuple(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_RULE_NAME,
                                       tst_addr, iut_addr,
                                       sock_type_sockts2rpc(sock_type)));

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, PROGRAM_NAME));
    CHECK_RC(sockts_bpf_map_type_name_check(pco_iut, iut_if->if_name,
                                            bpf_id, MAP_NAME,
                                            TAPI_BPF_MAP_TYPE_PERF_EVENT_ARRAY));

    TEST_STEP("Create connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Initialize perf events handling.");
    CHECK_RC(sockts_bpf_perf_event_init(pco_iut, iut_if->if_name,
                                        bpf_id, MAP_NAME,
                                        sizeof(perf_event_data)));

    TEST_STEP("Create and start CSAP on Tester to count all sent packets.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));
    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                    pco_tst->ta, sid, tst_if->if_name,
                    TAD_ETH_RECV_OUT,
                    (const uint8_t *)iut_lladdr->sa_data,
                    (const uint8_t *)tst_lladdr->sa_data,
                    iut_addr->sa_family,
                    sock_type_sockts2rpc(sock_type) == RPC_SOCK_STREAM ?
                        IPPROTO_TCP : IPPROTO_UDP,
                    TAD_SA2ARGS(iut_addr, tst_addr),
                    &csap));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));

    TEST_STEP("Link XDP program @c PROGRAM_NAME to interface on IUT.");
    sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id, PROGRAM_NAME,
                             TRUE, &xdp_ifaces);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Send some data to IUT.");
    CHECK_RC(sockts_test_send(pco_tst, tst_s, pco_iut, iut_s, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));

    TEST_STEP("Unlink XDP program, so it stops getting packets.");
    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name, &xdp_ifaces);

    TEST_STEP("Stop CSAP and get total length of sent packets.");
    cb_data = tapi_tad_trrecv_make_cb_data(callback, &tst_pkts_total_len);
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid, csap, cb_data,
                                  &tst_pkts_num));
    TEST_ARTIFACT("Number of sent packets - %u", tst_pkts_num);
    TEST_ARTIFACT("Total sent data length - %u", tst_pkts_total_len);

    TEST_STEP("Read data from all events.");
    CHECK_RC(sockts_bpf_perf_get_events(pco_iut, iut_if->if_name,
                                        bpf_id, MAP_NAME,
                                        &num_events, (uint8_t **)&data));

    TEST_ARTIFACT("Number of processed packets - %u", num_events);

    TEST_SUBSTEP("Count total processed data length.");
    for (i = 0; i < num_events; ++i)
    {
        if (data[i].cookie != PERF_EVENT_COOKIE)
        {
            WARN("Event has incorrect cookie. Probably the data "
                 "is corrupted.");
            RING("cookie = 0x%x", data[i].cookie);
            RING("length = %u", data[i].len);
            continue;
        }

        xdp_pkts_total_len += data[i].len;
    }

    TEST_ARTIFACT("Total processed data length - %u", xdp_pkts_total_len);
    TEST_SUBSTEP("Check that total data length processed by XDP program "
                 "is equal to total data length sent by Tester.");
    if (num_events != tst_pkts_num)
    {
        TEST_VERDICT("Number of sent packets and number of processed frames "
                     "are not equal");
    }
    if (tst_pkts_total_len != xdp_pkts_total_len)
    {
        TEST_VERDICT("Total length of processed data does not match the "
                     "length of sent frames");
    }

    TEST_SUCCESS;

cleanup:
    free(bpf_path);
    free(cb_data);
    free(data);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    tapi_tad_csap_destroy(pco_tst->ta, sid, csap);
    CLEANUP_CHECK_RC(sockts_bpf_perf_event_deinit(pco_iut, iut_if->if_name,
                                                  bpf_id, MAP_NAME));
    if (bpf_id != 0)
        CLEANUP_CHECK_RC(sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id));
    TEST_END;
}
