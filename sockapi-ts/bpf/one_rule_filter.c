/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-one_rule_filter Filtering by one rule
 *
 * @objective Check that XDP program filters packets by different tuple combinations
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param src_addr_diff     If @c TRUE use source address different from the
 *                          XDP rule when establish a connection.
 * @param dst_addr_diff     If @c TRUE use destination address different from the
 *                          XDP rule when establish a connection.
 * @param src_port_diff     If @c TRUE use source port different from the
 *                          XDP rule when establish a connection.
 * @param dst_port_diff     If @c TRUE use destintation port different from the
 *                          XDP rule when establish a connection.
 * @param conn_type         Type of connection.
 *                          - SOCK_STREAM
 *                          - SOCK_DGRAM
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/one_rule_filter"

#include "sockapi-test.h"
#include "tapi_bpf.h"
#include "sockapi-ts_bpf.h"
#include "tapi_route_gw.h"

/* Name of BPF object. */
#define BPF_OBJ_NAME "one_rule_filter_prog"

/* Name of program in BPF object. */
#define PROGRAM_NAME "one_rule_filter"

/* Name of map containing the 4-tuple rule. */
#define MAP_NAME "map_rule"

/**
 * Construct a new address based on @p base_addr, according to
 * addr_diff/port_diff values.
 *
 * @param rpcs              RPC server handle.
 * @param base_addr         Address obtained from environment.
 * @param net               Network to which addresses should belong.
 * @param if_name           Interface name.
 * @param addr_diff         If @c TRUE make an address differ from the base.
 * @param port_diff         If @c TRUE make a port differ from the base.
 * @param new_addr          Location to save the new address.
 */
static void
prepare_addr(rcf_rpc_server *rpcs, const struct sockaddr *base_addr,
             tapi_env_net *net, const char *if_name, te_bool addr_diff,
             te_bool port_diff, struct sockaddr_storage *new_addr)
{
    if (addr_diff)
    {
        struct sockaddr *addr_aux = NULL;
        int              af = base_addr->sa_family;

        CHECK_RC(tapi_cfg_alloc_net_addr((af == AF_INET ? net->ip4net :
                                                          net->ip6net),
                                         NULL, &addr_aux));
        tapi_sockaddr_clone_exact(addr_aux, new_addr);
        free(addr_aux);

        if (port_diff)
        {
            tapi_allocate_port_htons(rpcs,
                                     te_sockaddr_get_port_ptr(SA(new_addr)));
        }
        else
        {
            te_sockaddr_set_port(SA(new_addr),
                                 te_sockaddr_get_port(base_addr));
        }

        CHECK_RC(tapi_cfg_base_if_add_net_addr(
                            rpcs->ta, if_name, SA(new_addr),
                            (af == AF_INET ? net->ip4pfx : net->ip6pfx),
                            FALSE, NULL));
    }
    else
    {
        tapi_sockaddr_clone_exact(base_addr, new_addr);
        if (port_diff)
        {
            tapi_allocate_port_htons(rpcs,
                                     te_sockaddr_get_port_ptr(SA(new_addr)));
        }
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *tst_fake_addr = NULL;
    const struct sockaddr      *iut_lladdr = NULL;
    const struct sockaddr      *alien_link_addr;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    tapi_env_net               *net = NULL;
    te_bool                     src_addr_diff = FALSE;
    te_bool                     dst_addr_diff = FALSE;
    te_bool                     src_port_diff = FALSE;
    te_bool                     dst_port_diff = FALSE;
    rpc_socket_type             conn_type;
    struct sockaddr_storage     src_addr;
    struct sockaddr_storage     dst_addr;
    int                         iut_s = -1;
    int                         tst_s = -1;
    int                         listen_sock = -1;
    unsigned int                bpf_id = 0;
    tapi_tcp_handler_t          tcp_conn = 0;
    te_bool                     must_fail = FALSE;
    char                       *tx_buf = NULL;

    tqh_strings     xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);
    char           *bpf_path = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(src_addr_diff);
    TEST_GET_BOOL_PARAM(dst_addr_diff);
    TEST_GET_BOOL_PARAM(src_port_diff);
    TEST_GET_BOOL_PARAM(dst_port_diff);
    TEST_GET_SOCK_TYPE(conn_type);

    TEST_STEP("Prepare new addresses according to parameters: "
              "@p src_addr_diff, @p dst_addr_diff, "
              "@p src_port_diff, @p dst_port_diff.");
    prepare_addr(pco_tst, tst_addr, net, tst_if->if_name, src_addr_diff,
                 src_port_diff, &src_addr);
    prepare_addr(pco_iut, iut_addr, net, iut_if->if_name, dst_addr_diff,
                 dst_port_diff, &dst_addr);
    CFG_WAIT_CHANGES;

    must_fail = !(src_addr_diff == FALSE && dst_addr_diff == FALSE &&
                src_port_diff == FALSE && dst_port_diff == FALSE &&
                conn_type == RPC_SOCK_STREAM);

    TEST_STEP("Add and load to kernel BPF object @c BPF_OBJ_NAME on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, BPF_OBJ_NAME);
    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if->if_name, bpf_path,
                                 TAPI_BPF_PROG_TYPE_XDP, &bpf_id));

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, PROGRAM_NAME));

    TEST_STEP("Prepare the 5-tuple rule for XDP program, using IUT and Tester "
              "address/port and TCP protocol.");
    CHECK_RC(sockts_bpf_xdp_load_tuple(pco_iut, iut_if->if_name, bpf_id,
                                       MAP_NAME, tst_addr,
                                       iut_addr, RPC_SOCK_STREAM));

    TEST_STEP("Link XDP program @c PROGRAM_NAME to interface on IUT.");
    sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id, PROGRAM_NAME,
                             TRUE, &xdp_ifaces);
    CFG_WAIT_CHANGES;

    TEST_STEP("Try to establish connection using new adresses.");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             SA(&src_addr), CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             SA(&dst_addr), CVT_HW_ADDR(iut_lladdr),
                             TRUE));
    if (conn_type == RPC_SOCK_STREAM)
    {
        listen_sock = rpc_stream_server(pco_iut, RPC_PROTO_DEF, FALSE,
                                        SA(&dst_addr));

        CHECK_RC(tapi_tcp_create_conn(pco_tst->ta, SA(&src_addr), SA(&dst_addr),
                                      tst_if->if_name,
                                      (const uint8_t *)alien_link_addr->sa_data,
                                      (const uint8_t *)iut_lladdr->sa_data,
                                      TAPI_TCP_DEF_WINDOW, &tcp_conn));
        /* Wait a little so the CSAP really starts sniffing. */
        TAPI_WAIT_NETWORK;
        CHECK_RC(tapi_tcp_start_conn(tcp_conn, TAPI_TCP_CLIENT));

        rc = tapi_tcp_wait_open(tcp_conn, TAPI_WAIT_NETWORK_DELAY);
        if (rc != 0)
            tcp_conn = 0;

        if (rc != 0 && !must_fail)
            TEST_VERDICT("Connection establishment unexpectedly failed");
        if (rc == 0 && must_fail)
            TEST_VERDICT("Connection establishment unexpectedly succeed");

        if (rc == 0)
            iut_s = rpc_accept(pco_iut, listen_sock, NULL, NULL);
    }
    else if (conn_type == RPC_SOCK_DGRAM)
    {
        size_t     len = 0;
        te_bool     readable = FALSE;

        iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                           RPC_PROTO_DEF, FALSE, FALSE,
                                           SA(&dst_addr));
        tst_s = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_DGRAM,
                                           RPC_PROTO_DEF, FALSE, FALSE,
                                           SA(&src_addr));

        tx_buf = sockts_make_buf_dgram(&len);
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_sendto(pco_tst, tst_s, tx_buf, len, 0, SA(&dst_addr));
        if (rc < 0)
        {
            TEST_FAIL("sendto() unexpectedly failed with errno %r",
                      RPC_ERRNO(pco_tst));
        }
        else if ((size_t)rc != len)
        {
            TEST_FAIL("sendto() returned %d instead of %d", rc, len);
        }

        rpc_get_rw_ability(&readable, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY,
                           "READ");
        if (must_fail && readable)
            TEST_VERDICT("IUT is readable after UDP data was sent");
        if (!must_fail && !readable)
            TEST_VERDICT("IUT is not readable after UDP data was sent");
    }
    else
    {
        TEST_FAIL("Invalid conn_type parameter");
    }

    TEST_SUCCESS;

cleanup:
    free(tx_buf);
    free(bpf_path);

    CLEANUP_RPC_CLOSE(pco_iut, listen_sock);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (tcp_conn != 0)
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));

    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name ,&xdp_ifaces);
    if (bpf_id != 0)
        CLEANUP_CHECK_RC(sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id));

    TEST_END;
}
