/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload specific BPF testing
 */

/**
 * @page level5-bpf-xdp_same_stack Attach two XDP programs to same stack/interface pair
 *
 * @objective Check that multiple XDP programs cannot be attached to a single
 *            stack/interface pair.
 *
 * @param env           Testing environment:
 *      - @ref arg_types_env_peer2peer_two_links
 *      - @ref arg_types_env_peer2peer_two_links_ipv6
 * @param sock_type     Socket type:
 *      - UDP
 *      - TCP passive
 *      - TCP active
 * @param link_before    Link the second XDP program before/after stack creation
 *      - FALSE
 *      - TRUE
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/bpf/xdp_same_stack"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "bpf_onload_lib.h"
#include "move_fd_helpers.h"

/* Name of BPF object with program that passes all traffic. */
#define XDP_OBJ1_NAME       "xdp_pass_prog"

/* Name of program that passes all traffic. */
#define XDP_PROG1_NAME      "xdp_pass"

/* Name of BPF object with program that drops all traffic. */
#define XDP_OBJ2_NAME       "xdp_drop_prog"

/* Name of program that drops all traffic. */
#define XDP_PROG2_NAME      "xdp_drop"

/* Name of stack to which XDP programs are attached. */
#define XDP_STACK_NAME      "sapixdp"

/*
 * Name of map that counts packets. The name is applicable for
 * both XDP programs.
 */
#define XDP_MAP_CNT_NAME    "map_counter"

/* Macro performs XDP object initialization and all necessary
 * checks for the test.
 *
 * @param rpcs          RPC server to which BPF object is loaded
 * @param obj_hdl       Handle of BPD object
 * @param obj_name      Name of BPF object
 * @param prog_name     Name of XDP program
 */
#define BPF_OBJ_LOAD_CHECK(rpcs, obj_hdl, obj_name, prog_name) \
    CHECK_RC(sockts_bpf_object_init(&obj_hdl, rpcs, prog_name));            \
    CHECK_RC(sockts_bpf_object_load(&obj_hdl, obj_name));                   \
    CHECK_RC(sockts_bpf_object_prog_name_check(&obj_hdl));                  \
    CHECK_RC(sockts_bpf_object_map_name_check(&obj_hdl, XDP_MAP_CNT_NAME));

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;
    const struct sockaddr      *iut_addr1 = NULL;
    const struct sockaddr      *tst1_addr = NULL;

    sockts_socket_type      sock_type;
    te_bool                 link_before;
    int                     iut_s = -1;
    int                     iut_s_aux = -1;
    int                     tst_s = -1;
    bpf_object_handle       bpf_obj1 = {0};
    bpf_object_handle       bpf_obj2 = {0};
    xdp_attach_onload_pair  ifstack_pair = XDP_STACK_IF_PAIR_INIT;
    unsigned int            xdp_counter = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst, tst1_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(link_before);

    sockts_kill_zombie_stacks(pco_iut);

    TEST_STEP("Check that no stacks exist.");
    if (tapi_onload_stacks_number(pco_iut) != 0)
        TEST_FAIL("Some stack already exists before test beginning");

    ifstack_pair.stack_name = XDP_STACK_NAME;
    ifstack_pair.if_index = iut_if1->if_index;

    TEST_STEP("Load BPF objects and check that everything is loaded.");
    BPF_OBJ_LOAD_CHECK(pco_iut, bpf_obj1, XDP_OBJ1_NAME, XDP_PROG1_NAME);
    BPF_OBJ_LOAD_CHECK(pco_iut, bpf_obj2, XDP_OBJ2_NAME, XDP_PROG2_NAME);

    TEST_STEP("Link the first program that passes all traffic to "
              "stack/interface pair.");
    CHECK_RC(xdp_program_onload_link(&bpf_obj1, &ifstack_pair,
                                     iut_if1->if_name));

    TEST_STEP("If @p link_before is @c TRUE try to link the second program "
              "that drops all traffic to the same stack/interface pair. "
              "Check that operation fails.");
    if (link_before)
    {
        rc = xdp_program_onload_link(&bpf_obj2, &ifstack_pair, iut_if2->if_name);
        if (rc == 0)
        {
            TEST_VERDICT("Second attachement to the same stack/interface pair "
                         "before stack creation unexpectedly succeed");
        }
    }

    TEST_STEP("Create a stack with attached XDP program.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_GLOBAL,
                                         XDP_STACK_NAME,
                                         TRUE, &iut_s_aux);

    TEST_STEP("If @p link_before is @c FALSE try to link the second program "
              "that drops all traffic to the same stack/interface pair. "
              "Check that operation fails.");
    if (!link_before)
    {
        rc = xdp_program_onload_link(&bpf_obj2, &ifstack_pair, iut_if2->if_name);
        if (rc == 0)
        {
            TEST_VERDICT("Second attachement to the same stack/interface pair "
                         "after stack creation unexpectedly succeed");
        }
    }

    TEST_STEP("Create a connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr1, tst1_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Check that traffic passes successfully.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("Check that the first XDP program really works - get "
              "packet counter.");
    CHECK_RC(sockts_bpf_object_read_u32_map(&bpf_obj1, XDP_MAP_CNT_NAME,
                                            0, &xdp_counter));
    TEST_ARTIFACT("XDP counter = %u", xdp_counter);
    if (xdp_counter == 0)
        TEST_VERDICT("XDP program is not applied");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CHECK_RC(xdp_program_onload_unlink(&bpf_obj1, &ifstack_pair,
                                       iut_if1->if_name));

    CLEANUP_CHECK_RC(sockts_bpf_object_unload(&bpf_obj1));
    CLEANUP_CHECK_RC(sockts_bpf_object_unload(&bpf_obj2));

    CLEANUP_CHECK_RC(tapi_no_reuse_pco_disable_once());
    TEST_END;
}
