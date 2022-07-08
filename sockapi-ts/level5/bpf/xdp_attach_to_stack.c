/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload specific BPF testing
 */

/**
 * @page level5-bpf-xdp_attach_to_stack Attach XDP program to Onload stack
 *
 * @objective Check that XDP program correctly works on a specific Onload stack
 *            and does not affect other stacks
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_peer2peer
 *                    - @ref arg_types_env_peer2peer_ipv6
 * @param link_before Attach XDP program before/after stack creation:
 *                    - FALSE
 *                    - TRUE
 * @param wild_if     Attach XDP program to wildcard interface:
 *                    - FALSE
 *                    - TRUE
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/bpf/xdp_attach_to_stack"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "move_fd_helpers.h"

/* Name of BPF object. */
#define XDP_DROP_OBJ_NAME   "xdp_drop_prog"

/* Name of program in BPF object. */
#define XDP_DROP_PROG_NAME  "xdp_drop"

/* Name of a stack which an XDP program is attached to. */
#define STACK_NAME_WITH_XDP "sapixdp"

/*
 * Setting this value to TEST_LIBBPF_IFINDEX environment variable
 * links XDP program to wildcard interface.
 */
#define XDP_LINK_WILD_IFACE 0

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;

    char               *bpf_path = NULL;
    unsigned int        bpf_id = 0;
    tqh_strings         xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);
    te_bool             link_before = FALSE;
    te_bool             wild_if = FALSE;
    int                 iut_s = -1;
    int                 iut_l = -1;
    int                 tst_s = -1;
    int                 iut_s_aux = -1;

    sockts_test_send_ext_args test_send_args = SOCKTS_TEST_SEND_EXT_ARGS_INIT;
    sockts_test_send_rc       test_send_rc = SOCKTS_TEST_SEND_SUCCESS;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(link_before);
    TEST_GET_BOOL_PARAM(wild_if);

    TEST_STEP("Set @c TEST_LIBBPF_STACK variable according to the name of "
              "stack which an XDP program will be attached to.");
    tapi_sh_env_set(pco_iut, "TEST_LIBBPF_STACK", STACK_NAME_WITH_XDP,
                    TRUE, FALSE);

    TEST_STEP("Set @c TEST_LIBBPF_IFINDEX variable so that XDP program will "
              "be attached to wildcard interface.");
    tapi_sh_env_set_int(pco_iut, "TEST_LIBBPF_IFINDEX",
                        wild_if ? XDP_LINK_WILD_IFACE : iut_if->if_index,
                        TRUE, TRUE);

    TEST_STEP("Check that no stacks exist.");
    if (tapi_onload_stacks_number(pco_iut) != 0)
        TEST_VERDICT("Some stack already exists before test beginning");

    TEST_STEP("Load BPF object and check that it is loaded.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, XDP_DROP_OBJ_NAME);
    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if->if_name, bpf_path,
                                 TAPI_BPF_PROG_TYPE_XDP, &bpf_id));
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, XDP_DROP_PROG_NAME));

    TEST_STEP("If @p link_before is @c TRUE attach the XDP program that drops "
              "all the packets to the stack.");
    if (link_before)
    {
        sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id,
                                 XDP_DROP_PROG_NAME, TRUE,
                                 &xdp_ifaces);
    }

    TEST_STEP("Create IUT and Tester sockets.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Create a stack with the same name as @c TEST_LIBBPF_STACK.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_GLOBAL,
                                         STACK_NAME_WITH_XDP,
                                         TRUE, &iut_s_aux);

    TEST_STEP("Check that @c 2 stacks have been created.");
    if (tapi_onload_stacks_number(pco_iut) != 2)
        TEST_VERDICT("Invalid number of stacks has been created");

    TEST_STEP("If @p link_before is @c FALSE attach the XDP program that "
              "drops all the packets to the stack.");
    if (!link_before)
    {
        sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id,
                                 XDP_DROP_PROG_NAME, TRUE,
                                 &xdp_ifaces);
    }

    TEST_STEP("Establish a passive open connection. It must not fail.");
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr,
                      SOCKTS_SOCK_TCP_PASSIVE,
                      FALSE, TRUE, NULL, &iut_s, &tst_s, &iut_l,
                      SOCKTS_SOCK_FUNC_SOCKET);

    TEST_STEP("Move IUT socket to the stack with attached XDP program.");
    if (!tapi_rpc_onload_move_fd_check(pco_iut, iut_s,
                                       TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                       STACK_NAME_WITH_XDP, ""))
    {
        TEST_VERDICT("Fail to move IUT socket to the stack with XDP program");
    }

    TEST_STEP("Check traffic flow between IUT and Tester");
    test_send_args.rpcs_send = pco_tst;
    test_send_args.s_send = tst_s;
    test_send_args.rpcs_recv = pco_iut;
    test_send_args.s_recv = iut_s;
    test_send_args.s_recv_domain = RPC_PF_UNSPEC;
    test_send_args.print_verdicts = FALSE;

    test_send_rc = sockts_test_send_ext(&test_send_args);

    TEST_SUBSTEP("Check that traffic from Tester does not pass.");
    if (test_send_rc == SOCKTS_TEST_SEND_SUCCESS)
        TEST_VERDICT("XDP program did not run unexpectedly");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);

    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name, &xdp_ifaces);
    if (bpf_id != 0)
        sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id);
    free(bpf_path);
    TEST_END;
}
