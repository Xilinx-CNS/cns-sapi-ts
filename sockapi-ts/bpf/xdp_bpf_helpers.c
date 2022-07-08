/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/** @page bpf-xdp_bpf_helpers Check that Onload does not crashes
 *
 * @objective   Simple test cases there to confirm the exception that onload does not implement, but does not crash
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_ipv6
 * @param prog_name XDP program name to test:
 *                  - xdp_sk_lookup
 *                  - xdp_fib_lookup
 *                  - xdp_redirect
 * @param sock_type Socket type:
 *                  - UDP
 *                  - TCP active
 *                  - TCP passive
 *
 * @par Scenario:
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bpf/xdp_bpf_helpers"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "conf_api.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_bpf.h"
#include "tapi_sniffer.h"

/* Name of BPF object. */
#define BPF_OBJ_NAME_SFX "_prog"

/* Names of maps in BPF object. */
#define MAP_NAME "map_debug"

/**
 * Default key value in debug map for keys > 0. If this value is
 * appeared in the map after xdp program was finished it means that
 * testing function (for example bpf_sk_lookup_tcp) was not launched.
 */
#define MAP_DEBUG_DEF_KEY_VAL 255

/**
 * Check that tested XDP program has been launched at least one time
 *
 * @param rpcs          RPC server handle
 * @param bpf_id        Id of bpf object
 * @param map_name      The name of map
 */
static void
check_that_program_worked(rcf_rpc_server *rpcs, char *ifname, unsigned int bpf_id,
                          const char *map_name)
{
    unsigned int    max_entries;
    uint32_t        key = 0;
    uint32_t        val;
    uint32_t        pkt_cnt;
    uint32_t        def_cnt = 0;

    CHECK_RC(sockts_bpf_map_get_max_entries(rpcs, ifname, bpf_id, map_name,
                                            &max_entries));

    /* Get number of processed packets */
    CHECK_RC(sockts_bpf_map_lookup_kvpair(rpcs, ifname, bpf_id, map_name,
                                          (uint8_t *)&key, sizeof(key),
                                          (uint8_t *)&pkt_cnt, sizeof(pkt_cnt)));
    if (pkt_cnt == 0)
        TEST_VERDICT("There were no packets processed by xdp program");

    if (pkt_cnt + 1 > max_entries)
    {
        ERROR("The number of processed packets is greater than the "
              "maximum entries in the map");
    }

    for (key = 1; key < pkt_cnt + 1 && key < max_entries; key++)
    {
        CHECK_RC(sockts_bpf_map_lookup_kvpair(rpcs, ifname, bpf_id, map_name,
                                              (uint8_t *)&key, sizeof(key),
                                              (uint8_t *)&val, sizeof(val)));
        if (val == MAP_DEBUG_DEF_KEY_VAL)
            def_cnt++;
    }

    if (def_cnt == pkt_cnt)
        TEST_VERDICT("The BPF function was never launched");
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;

    unsigned int        bpf_id = 0;

    sockts_socket_type  sock_type;
    int                 iut_s = -1;
    int                 tst_s = -1;
    char               *bpf_path = NULL;
    const char         *prog_name = NULL;
    te_string           str = TE_STRING_INIT_STATIC(1024);
    te_string           obj_name = TE_STRING_INIT_STATIC(RCF_MAX_PATH);
    tqh_strings         xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(prog_name);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    /*
     * Enable sniffer to get all traffic. It's a temporary
     * solution for debug purpose.
     */
    tapi_sniffer_add(pco_tst->ta, tst_if->if_name, NULL, NULL, TRUE);

    TEST_STEP("Add and load into the kernel @p prog_name on IUT.");
    CHECK_RC(te_string_append(&obj_name, "%s%s", prog_name, BPF_OBJ_NAME_SFX));
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, obj_name.ptr);
    rc = sockts_bpf_obj_init(pco_iut, iut_if->if_name, bpf_path,
                             TAPI_BPF_PROG_TYPE_XDP, &bpf_id);
    if (rc != 0)
        TEST_VERDICT("Failed to load BPF object into the kernel");

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, prog_name));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_NAME));

    TEST_STEP("Create connections according to @p sock_type.");
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      FALSE, FALSE, NULL, &iut_s, &tst_s, NULL,
                      SOCKTS_SOCK_FUNC_SOCKET);

    if (sock_type == SOCKTS_SOCK_UDP)
    {
        TEST_STEP("Provoke ARP resolution in case of @b UDP sockets.");
        tapi_rpc_provoke_arp_resolution(pco_iut, tst_addr);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Link @p prog_name to interface on IUT.");
    sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id,
                             prog_name, TRUE, &xdp_ifaces);

    CFG_WAIT_CHANGES;

    TEST_STEP("Send packets from IUT and check that they are received "
              "on Tester.");
    CHECK_RC(sockts_test_send(pco_iut, iut_s, pco_tst, tst_s, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, "Sending from IUT"));

    TEST_STEP("Send packets from Tester and check that they are received "
              "on IUT.");
    sockts_test_send(pco_tst, tst_s, pco_iut, iut_s, NULL, NULL,
                     RPC_PF_UNSPEC, FALSE, "Sending from Tester");
    TAPI_WAIT_NETWORK;
    sockts_bpf_map_arr32_to_str(pco_iut, iut_if->if_name, bpf_id, MAP_NAME, &str);
    TEST_ARTIFACT(str.ptr);

    TEST_STEP("Check that tested BPF function has been launched at least once.");
    check_that_program_worked(pco_iut, iut_if->if_name, bpf_id, MAP_NAME);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(bpf_path);
    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name, &xdp_ifaces);
    if (bpf_id != 0)
        sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id);
    TEST_END;
}
