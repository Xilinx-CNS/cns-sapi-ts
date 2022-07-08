/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-xdp_change_addr Change source IP address
 *
 * @objective       Verify that data is send from one IP address but received from another
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_2addr
 *                  - @ref arg_types_env_peer2peer_2addr_ipv6
 *
 * @par Scenario:
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/xdp_change_addr"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "conf_api.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_bpf.h"

/* Name of BPF object */
#define BPF_OBJ_NAME "xdp_change_addr_prog"

/* Name of XDP program */
#define XDP_PROG_NAME "xdp_change_addr"

/* Names of maps in BPF object */
#define MAP_IPV4_ADDR_NAME "map_ipv4_addr"
#define MAP_IPV6_ADDR_NAME "map_ipv6_addr"

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    const struct sockaddr      *iut_addr1;
    const struct sockaddr      *tst_addr1;
    const struct sockaddr      *tst_addr2;
    struct sockaddr_storage     tst_addr_aux;

    unsigned int        bpf_id = 0;

    int                 iut_s1 = -1;
    int                 tst_s1 = -1;
    int                 af;
    char               *bpf_path = NULL;
    tqh_strings         xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst, tst_addr1);
    TEST_GET_ADDR(pco_tst, tst_addr2);

    af = tst_addr1->sa_family;

    TEST_STEP("Add and load into the kernel @c BPF_OBJ_NAME on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, BPF_OBJ_NAME);
    if ((rc = sockts_bpf_obj_init(pco_iut, iut_if->if_name, bpf_path,
                                TAPI_BPF_PROG_TYPE_XDP, &bpf_id)) != 0)
    {
        TEST_VERDICT("Failed to load BPF object into the kernel");
    }

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, XDP_PROG_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_IPV4_ADDR_NAME));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_IPV6_ADDR_NAME));

    TEST_STEP("Create @c SOCKTS_SOCK_UDP connection between first IUT and "
              "Tester addresses and check that data from Tester comes to IUT.");
    sockts_connection(pco_iut, pco_tst, iut_addr1, tst_addr1,
                      SOCKTS_SOCK_UDP, TRUE, FALSE, NULL, &iut_s1, &tst_s1,
                      NULL, SOCKTS_SOCK_FUNC_SOCKET);
    CHECK_RC(sockts_test_send(pco_tst, tst_s1, pco_iut, iut_s1,
                              tst_addr1, iut_addr1,
                              domain_h2rpc(af), TRUE, "First check"));

    TEST_STEP("Write rule to the map to change source IP address on incoming "
              "data from @p tst_addr1 to @p tst_addr2 value.");
    if (tst_addr1->sa_family == AF_INET)
    {
        in_addr_t addr1 = SIN(tst_addr1)->sin_addr.s_addr;
        in_addr_t addr2 = SIN(tst_addr2)->sin_addr.s_addr;

        CHECK_RC(sockts_bpf_map_set_writable(pco_iut, iut_if->if_name, bpf_id,
                                             MAP_IPV4_ADDR_NAME));
        CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                              bpf_id, MAP_IPV4_ADDR_NAME,
                                              (uint8_t *)&addr1, sizeof(addr1),
                                              (uint8_t *)&addr2, sizeof(addr2)));
    }
    else
    {
        struct in6_addr *addr1 = &SIN6(tst_addr1)->sin6_addr;
        struct in6_addr *addr2 = &SIN6(tst_addr2)->sin6_addr;

        CHECK_RC(sockts_bpf_map_set_writable(pco_iut, iut_if->if_name, bpf_id,
                                             MAP_IPV6_ADDR_NAME));
        CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                              bpf_id, MAP_IPV6_ADDR_NAME,
                                              (uint8_t *)addr1, sizeof(*addr1),
                                              (uint8_t *)addr2, sizeof(*addr2)));
    }

    TEST_STEP("Link @c XDP_PROG_NAME to interface on IUT.");
    sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id, XDP_PROG_NAME,
                             TRUE, &xdp_ifaces);
    CFG_WAIT_CHANGES;

    TEST_STEP("Send packets from Tester and check that they are received "
              "with changed source IP address on IUT.");
    /* Prepare source address to check */
    tapi_sockaddr_clone_exact(tst_addr2, &tst_addr_aux);
    te_sockaddr_set_port(SA(&tst_addr_aux),
                         *te_sockaddr_get_port_ptr(tst_addr1));

    CHECK_RC(sockts_test_send(pco_tst, tst_s1, pco_iut, iut_s1,
                              SA(&tst_addr_aux), iut_addr1,
                              domain_h2rpc(af), TRUE, "Second check"));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    free(bpf_path);
    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name, &xdp_ifaces);
    if (bpf_id != 0)
        sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id);
    TEST_END;
}
