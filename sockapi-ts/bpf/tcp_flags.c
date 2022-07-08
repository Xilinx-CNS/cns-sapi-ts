/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-tcp_flags Retreiving TCP flags of incoming packets in XDP program
 *
 * @objective Check that XDP program can recognize packets by TCP flags
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type IUT socket type:
 *                  - tcp_active
 *                  - tcp_passive_close
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/tcp_flags"

#include "sockapi-test.h"
#include "tapi_bpf.h"
#include "sockapi-ts_bpf.h"
#include "te_string.h"

/* Name of BPF object. */
#define BPF_OBJ_NAME "tcp_flags_prog"

/* Name of program in BPF object. */
#define PROGRAM_NAME "tcp_flags"

/* Name of map containing TCP segment counters. */
#define PACKET_COUNT_MAP_NAME "tcp_seg_cnt"

/* Name of map containing 5-tuple rule. */
#define MAP_RULE_NAME "map_rule"

enum {
    ACK,
    SYN,
    SYNACK,
    PSHACK,
    FINACK,
    PSHFINACK,
    RSTACK,
    RST,
};

/* Structure describing a TCP flag counter. */
typedef struct flag_to_check
{
    const uint8_t value;        /**< Value of the flag(s) according
                                     to TCP header. */
    uint32_t      bpf_counter;  /**< Counter which is incremented in
                                     BPF program when a segment with
                                     specified flags value is received. */
    const char   *name;         /**< String representation of the flag(s). */
} flag_to_check;

/* Array with the flags needed to be checked. */
static flag_to_check flags_to_check[] = {
    [ACK] = {TCP_ACK_FLAG, 0, "ACK"},
    [SYN] = {TCP_SYN_FLAG, 0, "SYN"},
    [SYNACK] = {TCP_ACK_FLAG | TCP_SYN_FLAG, 0, "SYN-ACK"},
    [PSHACK] = {TCP_ACK_FLAG | TCP_PSH_FLAG, 0, "PSH-ACK"},
    [FINACK] = {TCP_ACK_FLAG | TCP_FIN_FLAG, 0, "FIN-ACK"},
    [PSHFINACK] = {TCP_ACK_FLAG | TCP_FIN_FLAG | TCP_PSH_FLAG,
                   0, "PSH-FIN-ACK"},
    [RSTACK] = {TCP_ACK_FLAG | TCP_RST_FLAG, 0, "RST-ACK"},
    [RST] = {TCP_RST_FLAG, 0, "RST"},
};

#define FLAGS_TO_CHECK_NUM \
    (sizeof(flags_to_check) / sizeof(flag_to_check))

/**
 * Print verdict if IUT packet counter does not match the Testers one.
 *
 * @param flag      Flag to check.
 * @param tst_cnt   Tester side counter of the specified flag.
 */
#define CHECK_COUNTERS(flag, tst_cnt)                                       \
    do {                                                                    \
        if (flags_to_check[flag].bpf_counter != (uint32_t)tst_cnt)          \
        {                                                                   \
            ERROR_VERDICT("IUT and Tester have different counter values "   \
                          "of %s flag", flags_to_check[flag].name);         \
            failed = TRUE;                                                  \
        }                                                                   \
    } while(0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    sockts_socket_type          sock_type;
    unsigned int                bpf_id = 0;
    int                         iut_s = -1;
    int                         tst_s = -1;
    int                         sid = -1;
    csap_handle_t               csap = CSAP_INVALID_HANDLE;
    tsa_packets_counter         ctx = {0};
    unsigned int                i = 0;
    uint8_t                    *tx_buf = NULL;
    size_t                      tx_buf_len = 0;
    te_bool                     failed = FALSE;

    tqh_strings     xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);
    char           *bpf_path = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Add and load to kernel BPF object @c BPF_OBJ_NAME on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, BPF_OBJ_NAME);

    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if->if_name,
                                 bpf_path, TAPI_BPF_PROG_TYPE_XDP,
                                 &bpf_id));

    TEST_STEP("Load connection address/port into @c MAP_RULE_NAME map, to "
              "filter alien traffic.");
    CHECK_RC(sockts_bpf_xdp_load_tuple(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_RULE_NAME,
                                       tst_addr, iut_addr,
                                       sock_type_sockts2rpc(sock_type)));

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name, bpf_id, PROGRAM_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name, bpf_id, PACKET_COUNT_MAP_NAME));

    TEST_STEP("Link XDP program @c PROGRAM_NAME to interface on IUT.");
    sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id, PROGRAM_NAME,
                             TRUE, &xdp_ifaces);

    TEST_STEP("Create and start TCP CSAP on Tester to count all sent packets.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));
    CHECK_RC(tapi_tcp_ip_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                         TAD_ETH_RECV_OUT,
                                         NULL,
                                         NULL,
                                         tst_addr->sa_family,
                                         TAD_SA2ARGS(iut_addr, tst_addr),
                                         &csap));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_NO_PAYLOAD));

    TEST_STEP("Establish connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Send some data from Tester.");
    CHECK_RC(sockts_test_send(pco_tst, tst_s, pco_iut, iut_s, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));

    TEST_STEP("Close the connection on Tester.");
    RPC_CLOSE(pco_tst, tst_s);

    TEST_STEP("Try to send some data from IUT to get RST segment.");
    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    RPC_AWAIT_ERROR(pco_iut);
    rpc_send(pco_iut, iut_s, tx_buf, tx_buf_len, 0);

    TAPI_WAIT_NETWORK;

    TEST_STEP("Stop CSAP and get number of sent packets.");
    CHECK_RC(rcf_ta_trrecv_stop(pco_tst->ta, sid, csap, tsa_packet_handler,
                                &ctx, NULL));
    tsa_print_packet_stats(&ctx);

    TEST_STEP("Get number of packets from the map @c PACKET_COUNT_MAP_NAME.");
    for (i = 0; i < FLAGS_TO_CHECK_NUM; i++)
    {
        uint32_t    key = 0;
        uint32_t    value = 0;

        key = flags_to_check[i].value;
        CHECK_RC(sockts_bpf_map_lookup_kvpair(pco_iut, iut_if->if_name, bpf_id,
                                            PACKET_COUNT_MAP_NAME,
                                            (uint8_t *)&key, sizeof(key),
                                            (uint8_t *)&value, sizeof(value)));
        flags_to_check[i].bpf_counter = value;
        RING("%s = %u", flags_to_check[i].name,
                        flags_to_check[i].bpf_counter);
    }

    TEST_STEP("Compare IUT and Tester packet counters.");
    CHECK_COUNTERS(ACK, ctx.ack);
    CHECK_COUNTERS(SYN, ctx.syn);
    CHECK_COUNTERS(SYNACK, ctx.syn_ack);
    CHECK_COUNTERS(FINACK, ctx.fin_ack);
    CHECK_COUNTERS(PSHACK, ctx.push_ack);
    CHECK_COUNTERS(PSHFINACK, ctx.push_fin_ack);
    CHECK_COUNTERS(RSTACK, ctx.rst_ack);
    CHECK_COUNTERS(RST, ctx.rst);

    if (failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    free(bpf_path);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, sid, csap));
    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name, &xdp_ifaces);
    if (bpf_id != 0)
        CLEANUP_CHECK_RC(sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id));
    TEST_END;
}
