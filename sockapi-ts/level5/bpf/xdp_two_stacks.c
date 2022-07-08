/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload specific BPF testing
 */

/**
 * @page level5-bpf-xdp_two_stacks Attach multiple XDP programs to multiple stacks
 *
 * @objective Check that multiple XDP programs can be attached to multiple
 *            stacks and the most specific XDP program is applied.
 *
 * @param env        Testing environment:
 *      - @ref arg_types_env_peer2peer_two_links
 *      - @ref arg_types_env_peer2peer_two_links_ipv6
 * @param wild_stack Attach one of XDP programs to wildcard stack:
 *      - FALSE
 *      - TRUE
 * @param wild_if    Attach XDP program to wildcard interface:
 *      - FALSE
 *      - TRUE
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/bpf/xdp_two_stacks"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "move_fd_helpers.h"
#include "bpf_onload_lib.h"

/* Name of BPF object with drop-all program. */
#define XDP_DROP_OBJ_NAME   "xdp_drop_prog"

/* Name of BPF object with pass-all program. */
#define XDP_PASS_OBJ_NAME   "xdp_pass_prog"

/* Name of drop-all program in BPF object. */
#define XDP_DROP_PROG_NAME  "xdp_drop"

/* Name of pass-all program in BPF object. */
#define XDP_PASS_PROG_NAME  "xdp_pass"

/*
 * Name of map that counts packets. The name is applicable for
 * both XDP programs.
 */
#define XDP_MAP_CNT_NAME    "map_counter"

/* Name of a stack which an drop-all XDP program is attached to. */
#define STACK_NAME_XDP_DROP "sapixdp1"

/* Name of a stack which an pass-all XDP program is attached to. */
#define STACK_NAME_XDP_PASS "sapixdp2"

/*
 * Get packet counter value from specified BPF object. The obtained value
 * is reduced by the current value of @p counter.
 */
#define GET_XDP_COUNTER(bpf_obj, counter) \
    do {                                                            \
        unsigned int old_value = counter;                           \
        CHECK_RC(sockts_bpf_object_read_u32_map(&bpf_obj,           \
                                                XDP_MAP_CNT_NAME,   \
                                                0, &counter));      \
        counter -= old_value;                                       \
    } while (FALSE)

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;
    const struct if_nameindex  *tst1_if = NULL;
    const struct sockaddr      *iut_addr1 = NULL;
    const struct sockaddr      *tst1_addr = NULL;
    const struct sockaddr      *iut_if1_hwaddr = NULL;
    const struct sockaddr      *tst1_hwaddr = NULL;

    bpf_object_handle       bpf_hdl_xdp_pass = {0};
    xdp_attach_onload_pair  ifstack_pair_xdp_pass = XDP_STACK_IF_PAIR_INIT;
    bpf_object_handle       bpf_hdl_xdp_drop = {0};
    xdp_attach_onload_pair  ifstack_pair_xdp_drop = XDP_STACK_IF_PAIR_INIT;
    te_bool                 wild_stack = FALSE;
    te_bool                 wild_if = FALSE;
    int                     common_if_index;
    int                     iut_s = -1;
    int                     iut_l = -1;
    int                     tst_s = -1;
    int                     iut_s1_aux = -1;
    int                     iut_s2_aux = -1;
    unsigned int            xdp_pass_pkt_counter = 0;
    unsigned int            xdp_drop_pkt_counter = 0;
    csap_handle_t           csap = CSAP_INVALID_HANDLE;
    unsigned int            csap_counter = 0;

    sockts_test_send_ext_args test_send_args = SOCKTS_TEST_SEND_EXT_ARGS_INIT;
    sockts_test_send_rc       test_send_rc = SOCKTS_TEST_SEND_SUCCESS;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst, tst1_addr);
    TEST_GET_LINK_ADDR(iut_if1_hwaddr);
    TEST_GET_LINK_ADDR(tst1_hwaddr);
    TEST_GET_BOOL_PARAM(wild_stack);
    TEST_GET_BOOL_PARAM(wild_if);

    sockts_kill_zombie_stacks(pco_iut);

    CHECK_RC(sockts_bpf_object_init(&bpf_hdl_xdp_pass, pco_iut,
                                    XDP_PASS_PROG_NAME));
    CHECK_RC(sockts_bpf_object_init(&bpf_hdl_xdp_drop, pco_iut,
                                    XDP_DROP_PROG_NAME));

    TEST_STEP("Check that no stacks exist.");
    if (tapi_onload_stacks_number(pco_iut) != 0)
        TEST_FAIL("Some stack already exists before test beginning");

    TEST_STEP("Load BPF objects. Check that everything is loaded properly.");
    CHECK_RC(sockts_bpf_object_load(&bpf_hdl_xdp_pass, XDP_PASS_OBJ_NAME));
    CHECK_RC(sockts_bpf_object_load(&bpf_hdl_xdp_drop, XDP_DROP_OBJ_NAME));
    CHECK_RC(sockts_bpf_object_prog_name_check(&bpf_hdl_xdp_pass));
    CHECK_RC(sockts_bpf_object_prog_name_check(&bpf_hdl_xdp_drop));
    CHECK_RC(sockts_bpf_object_map_name_check(&bpf_hdl_xdp_pass,
                                              XDP_MAP_CNT_NAME));
    CHECK_RC(sockts_bpf_object_map_name_check(&bpf_hdl_xdp_drop,
                                              XDP_MAP_CNT_NAME));

    TEST_STEP("Link XDP programs to wildcard interface in case of "
              "@p wild_if is @c TRUE.");
    common_if_index = wild_if ? XDP_LINK_WILD_IFACE : iut_if1->if_index;

    TEST_STEP("Link XDP program that passes all traffic to the first stack.");
    ifstack_pair_xdp_pass.stack_name = STACK_NAME_XDP_PASS;
    ifstack_pair_xdp_pass.if_index = common_if_index;
    CHECK_RC(xdp_program_onload_link(&bpf_hdl_xdp_pass, &ifstack_pair_xdp_pass,
                                     iut_if1->if_name));

    TEST_STEP("Link XDP program that drops all traffic to the second stack, "
              "or to wildcard if @p wild_stack is @c TRUE.");
    ifstack_pair_xdp_drop.stack_name = wild_stack ? XDP_LINK_WILD_STACK :
                                                    STACK_NAME_XDP_DROP;
    ifstack_pair_xdp_drop.if_index = common_if_index;
    CHECK_RC(xdp_program_onload_link(&bpf_hdl_xdp_drop, &ifstack_pair_xdp_drop,
                                     iut_if2->if_name));

    TEST_STEP("Create the first stack with XDP pass-all program.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_GLOBAL,
                                         STACK_NAME_XDP_PASS,
                                         TRUE, &iut_s1_aux);

    TEST_STEP("Create an IUT socket within the first stack.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst1_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Create the second stack with XDP drop-all program.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_GLOBAL,
                                         STACK_NAME_XDP_DROP,
                                         TRUE, &iut_s2_aux);

    TEST_STEP("Create a CSAP on Tester and start it.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
                    pco_tst->ta, 0, tst1_if->if_name,
                    TAD_ETH_RECV_OUT,
                    (const uint8_t *)iut_if1_hwaddr->sa_data,
                    (const uint8_t *)tst1_hwaddr->sa_data,
                    tst1_addr->sa_family,
                    TAD_SA2ARGS(NULL, NULL),
                    &csap));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    TEST_STEP("Establish a passive open connection. It must not fail.");
    sockts_connection(pco_iut, pco_tst, iut_addr1, tst1_addr,
                      SOCKTS_SOCK_TCP_PASSIVE,
                      FALSE, TRUE, NULL, &iut_s, &tst_s, &iut_l,
                      SOCKTS_SOCK_FUNC_SOCKET);
    TEST_SUBSTEP("Check that XDP program really works - read packet counter.");
    GET_XDP_COUNTER(bpf_hdl_xdp_pass, xdp_pass_pkt_counter);
    GET_XDP_COUNTER(bpf_hdl_xdp_drop, xdp_drop_pkt_counter);
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, csap, NULL, &csap_counter));
    TEST_ARTIFACT("Before socket moving: XDP pass program counter = %u",
                  xdp_pass_pkt_counter);
    TEST_ARTIFACT("Before socket moving: XDP drop program counter = %u",
                  xdp_drop_pkt_counter);
    TEST_ARTIFACT("Before socket moving: CSAP counter = %u", csap_counter);
    if (xdp_pass_pkt_counter != csap_counter)
    {
        TEST_VERDICT("Traffic from Tester passed as expected, "
                     "but XDP packet counter value is invalid");
    }

    TEST_STEP("Move socket to the new stack.");
    if (!tapi_rpc_onload_move_fd_check(pco_iut, iut_s,
                                       TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                       STACK_NAME_XDP_DROP, ""))
    {
        TEST_FAIL("Fail to move IUT socket to the second stack.");
    }

    TEST_STEP("Check that @c 2 stacks have been created.");
    if (tapi_onload_stacks_number(pco_iut) != 2)
        TEST_FAIL("Invalid number of stacks has been created");

    TEST_STEP("Check that traffic from Tester does not pass.");
    test_send_args.rpcs_send = pco_tst;
    test_send_args.s_send = tst_s;
    test_send_args.rpcs_recv = pco_iut;
    test_send_args.s_recv = iut_s;
    test_send_args.s_recv_domain = RPC_PF_UNSPEC;
    test_send_args.print_verdicts = FALSE;

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));
    test_send_rc = sockts_test_send_ext(&test_send_args);

    TEST_SUBSTEP("Check that XDP program really works - read packet counter.");
    GET_XDP_COUNTER(bpf_hdl_xdp_pass, xdp_pass_pkt_counter);
    GET_XDP_COUNTER(bpf_hdl_xdp_drop, xdp_drop_pkt_counter);
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, csap, NULL, &csap_counter));

    TEST_ARTIFACT("After socket moving: XDP pass program counter = %u",
                  xdp_pass_pkt_counter);
    TEST_ARTIFACT("After socket moving: XDP drop program counter = %u",
                  xdp_drop_pkt_counter);
    TEST_ARTIFACT("After socket moving: CSAP counter = %u", csap_counter);

    if (test_send_rc == SOCKTS_TEST_SEND_SUCCESS)
    {
        ERROR("Data from Tester passed successfully");
        if (xdp_pass_pkt_counter != 0 && xdp_drop_pkt_counter != 0)
        {
            TEST_VERDICT("Impossible thing happened: both XDP programs "
                         "applied");
        }
        else if (xdp_pass_pkt_counter != 0)
        {
            TEST_VERDICT("Invalid XDP program (pass-all) applied "
                         "after moving socket to the second stack");
        }
        else if (xdp_drop_pkt_counter != 0)
        {
            TEST_VERDICT("Valid XDP program (drop-all) applied "
                         "after moving socket to the second stack, but "
                         "traffic from Tester passed successfully");
        }
        else
        {
            TEST_VERDICT("None of XDP programs applied after moving "
                         "socket to the second stack");
        }
    }

    if (xdp_pass_pkt_counter != 0)
    {
        TEST_VERDICT("Traffic from Tester did not pass as expected, "
                     "however invalid XDP program (pass-all) applied");
    }

    if (xdp_drop_pkt_counter != csap_counter)
    {
        TEST_VERDICT("Traffic from Tester did not pass as expected, "
                     "but XDP packet counter value is invalid");
    }

    TEST_SUCCESS;

cleanup:
    tapi_tad_csap_destroy(pco_tst->ta, 0, csap);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1_aux);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2_aux);

    CLEANUP_CHECK_RC(xdp_program_onload_unlink(&bpf_hdl_xdp_drop,
                                               &ifstack_pair_xdp_drop,
                                               iut_if2->if_name));

    CLEANUP_CHECK_RC(xdp_program_onload_unlink(&bpf_hdl_xdp_pass,
                                               &ifstack_pair_xdp_pass,
                                               iut_if1->if_name));

    CLEANUP_CHECK_RC(sockts_bpf_object_unload(&bpf_hdl_xdp_pass));
    CLEANUP_CHECK_RC(sockts_bpf_object_unload(&bpf_hdl_xdp_drop));

    CLEANUP_CHECK_RC(tapi_no_reuse_pco_disable_once());
    TEST_END;
}
