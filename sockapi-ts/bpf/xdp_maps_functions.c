/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/**
 * @page bpf-xdp_maps_functions Update and delete elements from map
 *
 * @objective Check that XDP program correctly updates/deletes elements in maps
 *            of different types
 *
 * @param env      Testing environment:
 *                 - @ref arg_types_env_peer2peer
 * @param func     Functions for work with map:
 *                 - @c update
 *                 - @c delete
 * @param map_name Name of XDP maps:
 *                 - @c map_hash
 *                 - @c map_array
 *                 - @c map_lmp_trie
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "bpf/xdp_maps_functions"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "tapi_bpf.h"
#include <string.h>
#include "tapi_mem.h"

/* Name of BPF program. */
#define XDP_PROG "xdp_prog"

/* XDP program name to test */
#define PROG_NAME "xdp_maps_functions_prog"

#define MAP_PARAM "map_param"

#define MAP_RC "map_rc"

/*
 * The key by which to update/delete the value.
 * Value is 0, because map_entries = 1.
 */
#define VALUE_KEY 0

/*
 * Values of functions type.
 * Exactly the same enumeration should be in XDP program.
 */
typedef enum {
    FUNC_UPDATE = 1,
    FUNC_DELETE
} functions_values;

#define FUNC_VALUES            \
    { "update", FUNC_UPDATE }, \
    { "delete", FUNC_DELETE }

/*
 * Enumeration for pass map_type param to XDP program.
 * Exactly the same enumeration should be in XDP program.
 */
enum {
    TEST_MAP_TYPE_ARRAY,
    TEST_MAP_TYPE_HASH,
    TEST_MAP_TYPE_LPM_TRIE
};

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct if_nameindex *iut_if = NULL;
    functions_values           func;
    const char                *map_name;
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;

    char              *bpf_path = NULL;
    unsigned int       bpf_id;
    int                iut_s = -1;
    int                tst_s = -1;
    tqh_strings        xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);
    tapi_bpf_map_type  map_type;
    void              *tx_buf = NULL;
    void              *rx_buf = NULL;
    size_t             tx_buf_len;
    size_t             rx_buf_len;
    socklen_t          tst_addr_from_len;

    unsigned long  key = 0;
    unsigned long  val_func;
    unsigned long  val_map;
    unsigned long  val_key;
    unsigned long  val_value;
    unsigned long  val_lookup;
    unsigned int   key_size;
    uint8_t       *key_for_map_name;
    unsigned long  key_rc = 0; /* This value key use in XDP program */
    long           val_rc;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(func, FUNC_VALUES);
    TEST_GET_STRING_PARAM(map_name);

    tx_buf = sockts_make_buf_dgram(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    TEST_STEP("Add and load into the kernel XDP program on IUT.");
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, PROG_NAME);
    CHECK_RC(sockts_bpf_obj_init(pco_iut, iut_if->if_name, bpf_path,
                                 TAPI_BPF_PROG_TYPE_XDP, &bpf_id));

    TEST_STEP("Check that all needed programs and maps are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, XDP_PROG));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, map_name));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_PARAM));
    CHECK_RC(sockts_bpf_map_name_check(pco_iut, iut_if->if_name,
                                       bpf_id, MAP_RC));

    TEST_STEP("Create @c SOCK_DGRAM socket @b iut_s on IUT "
              "and bind to @b iut_addr");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);

    TEST_STEP("Create @c SOCK_DGRAM socket @b tst_s on Tester "
              "and bind to @b tst_addr");
    tst_s = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       tst_addr);
    TEST_STEP("Link XDP program to interface on IUT.");
    sockts_bpf_link_xdp_prog(pco_iut, iut_if->if_name, bpf_id,
                             XDP_PROG, TRUE, &xdp_ifaces);

    CFG_WAIT_CHANGES;

    TEST_STEP("Update map to pass test parameters to XDP program");
    /* In this step, the map is filled,
     * in which the parameters are passed to the XDP program.
     *
     * The map structure:
     * 0. Function for test: FUNC_UPDATE
     *                       FUNC_DELETE
     * 1. Map type:          BPF_MAP_TYPE_ARRAY
     *                       BPF_MAP_TYPE_HASH
     *                       BPF_MAP_TYPE_LPM_TRIE
     * 2. The key by which to update/delete the value.
     * 3. Value for update
     */
    val_func = func;
    CHECK_RC(sockts_bpf_map_get_type(pco_iut, iut_if->if_name, bpf_id, map_name, &map_type));
    switch (map_type)
    {
        case TAPI_BPF_MAP_TYPE_ARRAY:
            val_map = TEST_MAP_TYPE_ARRAY;
            break;

        case TAPI_BPF_MAP_TYPE_HASH:
            val_map = TEST_MAP_TYPE_HASH;
            break;

        case TAPI_BPF_MAP_TYPE_LPM_TRIE:
            val_map = TEST_MAP_TYPE_LPM_TRIE;
            break;

        default:
            TEST_FAIL("Invalid type of map");
            break;
    }
    /* These are just values for testing.*/
    val_key = VALUE_KEY;
    val_value = (unsigned long)rand_range(0, RAND_MAX);
    CHECK_RC(sockts_bpf_map_set_writable(pco_iut, iut_if->if_name,
                                         bpf_id, MAP_PARAM));
    CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                          bpf_id, MAP_PARAM,
                                          (uint8_t *)&key,
                                          sizeof(key),
                                          (uint8_t *)&val_func,
                                          sizeof(val_func)));
    key++;
    CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                          bpf_id, MAP_PARAM,
                                          (uint8_t *)&key,
                                          sizeof(key),
                                          (uint8_t *)&val_map,
                                          sizeof(val_map)));
    key++;
    CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                          bpf_id, MAP_PARAM,
                                          (uint8_t *)&key,
                                          sizeof(key),
                                          (uint8_t *)&val_key,
                                          sizeof(val_key)));
    key++;
    CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                          bpf_id, MAP_PARAM,
                                          (uint8_t *)&key,
                                          sizeof(key),
                                          (uint8_t *)&val_value,
                                          sizeof(val_value)));

    CHECK_RC(sockts_bpf_map_get_key_size(pco_iut, iut_if->if_name,
                                         bpf_id, map_name, &key_size));
    key_for_map_name = tapi_malloc(key_size);
    memcpy(key_for_map_name, &val_key, key_size);

    TEST_STEP("If @p func is delete: add key/value to @p map_name");
    if (func == FUNC_DELETE)
    {
        CHECK_RC(sockts_bpf_map_set_writable(pco_iut, iut_if->if_name,
                                             bpf_id, map_name));
        CHECK_RC(sockts_bpf_map_update_kvpair(pco_iut, iut_if->if_name,
                                              bpf_id, map_name,
                                              key_for_map_name, key_size,
                                              (uint8_t *)&val_value,
                                              sizeof(val_value)));
        CHECK_RC(sockts_bpf_map_unset_writable(pco_iut, iut_if->if_name,
                                               bpf_id, map_name));

    }

    TEST_STEP("Send packet to IUT from Tester to force the xdp program start");
    rpc_sendto(pco_tst, tst_s, tx_buf, tx_buf_len, 0, iut_addr);
    tst_addr_from_len = sizeof(tst_addr);

    TEST_STEP("Receive packet on IUT to check that packet passed via XDP program");
    rpc_recvfrom(pco_iut, iut_s, rx_buf, rx_buf_len, 0,
                 SA(tst_addr), &tst_addr_from_len);
    CHECK_BUFS_EQUAL(rx_buf, tx_buf, tx_buf_len);

    TEST_STEP("Get code returned by the @p func function.");
    rc = sockts_bpf_map_lookup_kvpair(pco_iut, iut_if->if_name,
                                      bpf_id, MAP_RC,
                                      (uint8_t *)&key_rc,
                                      sizeof(key_rc),
                                      (uint8_t *)&val_rc,
                                      sizeof(val_rc));
    if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
        TEST_VERDICT("There is no return code from XDP program");
    else if (rc != 0)
        TEST_FAIL("Failed to get return code from the XDP program");

    TEST_STEP("Lookup pair from @p map_name");
    rc = sockts_bpf_map_lookup_kvpair(pco_iut, iut_if->if_name,
                                      bpf_id, map_name,
                                      key_for_map_name, key_size,
                                      (uint8_t *)&val_lookup,
                                      sizeof(val_lookup));

    TEST_STEP("Check that @p func works correctly");
    if (func == FUNC_UPDATE)
    {
        if (val_rc != 0)
            TEST_FAIL("XDP program error");
        if (rc != 0)
            TEST_FAIL("Failed to get value");
        TEST_SUBSTEP("If @p func is @c FUNC_UPDATE, then value from lookup "
                        "must match the set value");
        if (val_lookup != val_value)
            TEST_VERDICT("The \"update\" function does not work correctly: "
                            "expected value does not match with specified");
    }
    else
    {
        if (strcmp(map_name, "map_array") == 0)
        {
            if (rc != 0)
                TEST_FAIL("Failed to get value");
            TEST_SUBSTEP("If @p func is @c FUNC_DELETE, then value from lookup "
                            "should not match the set value");
            if (val_rc != -EINVAL)
                TEST_VERDICT("The \"delete\" function does not work correctly: "
                             "expected EINVAL. Delete is not supported for "
                             "BPF_MAP_TYPE_ARRAY ");
        }
        else
        {
            if (val_rc != 0)
                TEST_FAIL("XDP program error");
            TEST_SUBSTEP("If @p func is @c FUNC_DELETE, then the set value "
                         "should not exist in the map");
            if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
                TEST_VERDICT("The \"delete\" function does not work correctly: "
                             "expected ENOENT instead %s", te_rc_err2str(rc));
        }
    }
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf);
    free(rx_buf);
    free(key_for_map_name);
    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name, &xdp_ifaces);
    if (bpf_id != 0)
        CLEANUP_CHECK_RC(sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id));
    TEST_END;
}
