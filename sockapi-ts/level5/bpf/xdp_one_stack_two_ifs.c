/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload specific BPF testing
 */

/**
 * @page level5-bpf-xdp_one_stack_two_ifs Attach XDP program the stack+iface pair
 *
 * @objective Check XDP program attachment to different interfaces and one stack
 *
 * @param env           Testing environment:
 *      - @ref arg_types_env_peer2peer_two_links
 *      - @ref arg_types_env_peer2peer_two_links_ipv6
 * @param xdp_link_if   Interface to link XDP program to:
 *      - first
 *      - second
 *      - wild
 *      - both
 * @param sock_type     Socket type:
 *      - UDP
 *      - TCP active
 *      - TCP passive
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/bpf/xdp_one_stack_two_ifs"

#include "sockapi-test.h"
#include "tapi_bpf.h"
#include "sockapi-ts_bpf.h"
#include "move_fd_helpers.h"
#include "tapi_ip_common.h"
#include "bpf_onload_lib.h"

/* Name of a stack which an XDP program is attached to. */
#define STACK_NAME_WITH_XDP "sapixdp"

/* Name of BPF object. */
#define XDP_OBJ_NAME  "xdp_actions_prog"

/* Name of program that count packets in BPF object. */
#define XDP_PROG_NAME "xdp_actions"

/* Name of map in BPF object. */
#define XDP_COUNT_MAP  "pkt_cnt"
#define XDP_ACTION_MAP "xdp_action"

/**
 * Check data transmission in one direction. Random number of packets is
 * used.
 *
 * @param rpcs1    Sender PCO
 * @param s1       Sender socket
 * @param rpcs2    Receiver PCO
 * @param s2       Receiver socket
 */
static void test_send_rand_pkts(rcf_rpc_server *rpcs1, int s1,
                                rcf_rpc_server *rpcs2, int s2)
{
    static unsigned int       prev_pkt_cnt = 0;
    sockts_test_send_ext_args args = SOCKTS_TEST_SEND_EXT_ARGS_INIT;

    args.rpcs_send = rpcs1;
    args.s_send = s1;
    args.rpcs_recv = rpcs2;
    args.s_recv = s2;
    args.s_recv_domain = RPC_PF_UNSPEC;

    do {
        args.pkts_num = rand_range(SOCKTS_SEND_PACKETS_NUM,
                                   SOCKTS_SEND_PACKETS_NUM * 10);
    } while (args.pkts_num == prev_pkt_cnt);
    prev_pkt_cnt = args.pkts_num;
    CHECK_SOCKTS_TEST_SEND_RC(sockts_test_send_ext(&args));
}

/* The list of values allowed for parameter of type 'iface'. */
#define TESTPARAM_IFACE_MAPPING_LIST            \
            { "first",  XDP_IFACE_FIRST },      \
            { "second", XDP_IFACE_SECOND },     \
            { "wild",   XDP_IFACE_WILD },       \
            { "both",   XDP_IFACE_BOTH }

/* Enumeration for 'iface' parameter. */
typedef enum testparam_xdp_iface {
    XDP_IFACE_FIRST,
    XDP_IFACE_SECOND,
    XDP_IFACE_WILD,
    XDP_IFACE_BOTH,
} testparam_xdp_iface;

/*
 * Enumeration describing an XDP action to perform by
 * 'xdp_actions' XDP program. The identical enum is declared
 * in xdp_actions_prog.c
 */
enum test_xdp_action {
    TEST_XDP_ABORTED = 0,
    TEST_XDP_DROP,
    TEST_XDP_PASS,
    TEST_XDP_TX,
    TEST_XDP_REDIRECT,
};

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;
    const struct if_nameindex  *tst1_if = NULL;
    const struct if_nameindex  *tst2_if = NULL;
    const struct sockaddr      *iut_addr1 = NULL;
    const struct sockaddr      *iut_addr2 = NULL;
    const struct sockaddr      *tst1_addr = NULL;
    const struct sockaddr      *tst2_addr = NULL;
    const struct sockaddr      *iut_if1_hwaddr;
    const struct sockaddr      *iut_if2_hwaddr;
    const struct sockaddr      *tst1_hwaddr;
    const struct sockaddr      *tst2_hwaddr;

    sockts_socket_type      sock_type;
    int                     ip_proto;
    unsigned int            action = TEST_XDP_PASS;
    unsigned int            key = 0;
    testparam_xdp_iface     xdp_link_if;
    int                     iut_s_aux = -1;
    int                     iut_s1 = -1;
    int                     iut_s2 = -1;
    int                     tst_s1 = -1;
    int                     tst_s2 = -1;
    csap_handle_t           csap_if1 = CSAP_INVALID_HANDLE;
    unsigned int            cnt_if1 = 0;
    csap_handle_t           csap_if2 = CSAP_INVALID_HANDLE;
    unsigned int            cnt_if2 = 0;
    unsigned int            xdp_counter = 0;
    unsigned int            xdp_counter_must_be = 0;
    bpf_object_handle       bpf_object = {0};
    xdp_attach_onload_pair  attach_pair1 = XDP_STACK_IF_PAIR_INIT;
    xdp_attach_onload_pair  attach_pair2 = XDP_STACK_IF_PAIR_INIT;

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
    TEST_GET_ENUM_PARAM(xdp_link_if, TESTPARAM_IFACE_MAPPING_LIST);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    ip_proto = sock_type_sockts2rpc(sock_type) == RPC_SOCK_STREAM ?
               IPPROTO_TCP : IPPROTO_UDP;

    attach_pair1.stack_name = STACK_NAME_WITH_XDP;
    attach_pair2.stack_name = STACK_NAME_WITH_XDP;

    CHECK_RC(sockts_bpf_object_init(&bpf_object, pco_iut, XDP_PROG_NAME));

    TEST_STEP("Load BPF object.");
    CHECK_RC(sockts_bpf_object_load(&bpf_object, XDP_OBJ_NAME));

    TEST_SUBSTEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_object_prog_name_check(&bpf_object));
    CHECK_RC(sockts_bpf_object_map_name_check(&bpf_object, XDP_ACTION_MAP));
    CHECK_RC(sockts_bpf_object_map_name_check(&bpf_object, XDP_COUNT_MAP));

    TEST_SUBSTEP("Set XDP program to pass all packets.");
    CHECK_RC(sockts_bpf_map_set_writable(pco_iut, iut_if1->if_name,
                                         bpf_object.id, XDP_ACTION_MAP));
    CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if1->if_name, bpf_object.id,
                                          XDP_ACTION_MAP,
                                          (uint8_t *)&key, sizeof(key),
                                          (uint8_t *)&action, sizeof(action)));

    TEST_STEP("Attach XDP program which counts incoming packets to the Onload "
              "stack+interface pair.");
    switch (xdp_link_if)
    {
        case XDP_IFACE_FIRST:
            attach_pair1.if_index = iut_if1->if_index;
            break;
        case XDP_IFACE_SECOND:
            attach_pair1.if_index = iut_if2->if_index;
            break;
        case XDP_IFACE_WILD:
            attach_pair1.if_index = XDP_LINK_WILD_IFACE;
            break;
        case XDP_IFACE_BOTH:
            attach_pair1.if_index = iut_if1->if_index;
            attach_pair2.if_index = iut_if2->if_index;
            break;
    }
    CHECK_RC(xdp_program_onload_link(&bpf_object, &attach_pair1,
                                     iut_if1->if_name));
    if (xdp_link_if == XDP_IFACE_BOTH)
    {
        CHECK_RC(xdp_program_onload_link(&bpf_object, &attach_pair2,
                                         iut_if2->if_name));
    }

    TEST_STEP("Create a stack with the name according to @c "
              "TEST_LIBBPF_STACK.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_GLOBAL,
                                         STACK_NAME_WITH_XDP,
                                         TRUE, &iut_s_aux);

    TEST_STEP("Create CSAPs on both Tester's interfaces. Start them.");
    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                    pco_tst->ta, 0, tst1_if->if_name,
                    TAD_ETH_RECV_OUT,
                    (const uint8_t *)iut_if1_hwaddr->sa_data,
                    (const uint8_t *)tst1_hwaddr->sa_data,
                    tst1_addr->sa_family, ip_proto,
                    TAD_SA2ARGS(NULL, NULL),
                    &csap_if1));

    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                    pco_tst->ta, 0, tst2_if->if_name,
                    TAD_ETH_RECV_OUT,
                    (const uint8_t *)iut_if2_hwaddr->sa_data,
                    (const uint8_t *)tst2_hwaddr->sa_data,
                    tst2_addr->sa_family, ip_proto,
                    TAD_SA2ARGS(NULL, NULL),
                    &csap_if2));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_if1, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_if2, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    TEST_STEP("Establish connections with Tester via @c 2 interfaces "
              "according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr1, tst1_addr, sock_type,
                      &iut_s1, &tst_s1, NULL);
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr2, tst2_addr, sock_type,
                      &iut_s2, &tst_s2, NULL);

    TEST_STEP("Pass some traffic from Tester via both connections.");
    test_send_rand_pkts(pco_tst, tst_s1, pco_iut, iut_s1);
    test_send_rand_pkts(pco_tst, tst_s2, pco_iut, iut_s2);

    TEST_STEP("Stop CSAPs.");
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, csap_if1, NULL, &cnt_if1));
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, csap_if2, NULL, &cnt_if2));
    TEST_ARTIFACT("Tester iface1 counter = %u", cnt_if1);
    TEST_ARTIFACT("Tester iface2 counter = %u", cnt_if2);

    TEST_STEP("Compare CSAP counters with XDP counter");
    CHECK_RC(sockts_bpf_object_read_u32_map(&bpf_object, XDP_COUNT_MAP,
                                            key, &xdp_counter));
    TEST_ARTIFACT("XDP counter = %u", xdp_counter);

    TEST_SUBSTEP("If @p xdp_link_if is @c first, check that XDP program "
                 "counts only packets going via the first interface.");
    TEST_SUBSTEP("If @p xdp_link_if is @c second, check that XDP program "
                 "counts only packets going via the second interface.");
    TEST_SUBSTEP("If @p xdp_link_if is @c wild or @c both, check that "
                 "XDP program counts packets going via both interfaces.");

    switch (xdp_link_if)
    {
        case XDP_IFACE_FIRST:
            xdp_counter_must_be = cnt_if1;
            break;
        case XDP_IFACE_SECOND:
            xdp_counter_must_be = cnt_if2;
            break;
        case XDP_IFACE_WILD:
        case XDP_IFACE_BOTH:
            xdp_counter_must_be = cnt_if1 + cnt_if2;
            break;
    }

    if (xdp_counter != xdp_counter_must_be)
    {
        if (xdp_counter == cnt_if1)
        {
            TEST_VERDICT("XDP program unexpectedly ran only on the "
                         "first interface");
        }
        else if (xdp_counter == cnt_if2)
        {
            TEST_VERDICT("XDP program unexpectedly ran only on the "
                         "second interface");
        }
        else if (xdp_counter == cnt_if1 + cnt_if2)
        {
            TEST_VERDICT("XDP program unexpectedly ran on both "
                         "interfaces");
        }
        else
        {
            TEST_VERDICT("XDP program returned unexpected number "
                         "of packets");
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);

    tapi_tad_csap_destroy(pco_tst->ta, 0, csap_if1);
    tapi_tad_csap_destroy(pco_tst->ta, 0, csap_if2);
    CLEANUP_CHECK_RC(xdp_program_onload_unlink(&bpf_object, &attach_pair1,
                                               iut_if1->if_name));
    if (xdp_link_if == XDP_IFACE_BOTH)
    {
        CLEANUP_CHECK_RC(xdp_program_onload_unlink(&bpf_object,
                                                   &attach_pair2,
                                                   iut_if2->if_name));
    }
    CLEANUP_CHECK_RC(sockts_bpf_object_unload(&bpf_object));
    CLEANUP_CHECK_RC(tapi_no_reuse_pco_disable_once());
    TEST_END;
}
