/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * BPF testing
 */

/**
 * @page bpf-xdp_prog_load Loading XDP programs with different types of maps and XDP return values
 *
 * @objective Check support of all BPF maps and XDP codes
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer
 * @param check_type Type of value to be checked
 *      - map_type
 *      - return_value
 * @param prog_name XDP program name to test:
 *      - xdp_mt_hash
 *      - xdp_mt_array
 *      - xdp_mt_prog_array
 *      - xdp_mt_perf_event_array
 *      - xdp_mt_percpu_hash
 *      - xdp_mt_percpu_array
 *      - xdp_mt_stack_trace
 *      - xdp_mt_cgroup_array
 *      - xdp_mt_lru_hash
 *      - xdp_mt_lru_percpu_hash
 *      - xdp_mt_lpm_trie
 *      - xdp_mt_devmap
 *      - xdp_mt_sockmap
 *      - xdp_mt_cpumap
 *      - xdp_mt_xskmap
 *      - xdp_mt_sockhash
 *      - xdp_mt_cgroup_storage
 *      - xdp_mt_reuseport_sockarray
 *      - xdp_rv_aborted
 *      - xdp_rv_tx
 *      - xdp_rv_redirect
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "bpf/xdp_prog_load"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"
#include "tapi_bpf.h"

/* Name of BPF object. */
#define BPF_OBJ_NAME_SFX "_prog"

/* Name of BPF program. */
#define XDP_PROG "xdp_prog"

/* Values types of checks */
typedef enum {
    CHECK_TYPE_MAP,          /*< Check type of map */
    CHECK_TYPE_RETURN_VALUE, /*< Check return value XDP code*/
} types_for_check;

#define CHECK_TYPE_VALUES \
    { "map_type",     CHECK_TYPE_MAP }, \
    { "return_value", CHECK_TYPE_RETURN_VALUE }

/* This array contains the names of programs that have maps
 * of the type on the right. It is resolved program name
 * to type of map
 */
static const char *bpf_map_types[] =
{
    [TAPI_BPF_MAP_TYPE_UNSPEC] =              "xdp_mt_unspec",
    [TAPI_BPF_MAP_TYPE_HASH] =                "xdp_mt_hash",
    [TAPI_BPF_MAP_TYPE_ARRAY] =               "xdp_mt_array",
    [TAPI_BPF_MAP_TYPE_PROG_ARRAY] =          "xdp_mt_prog_array",
    [TAPI_BPF_MAP_TYPE_PERF_EVENT_ARRAY] =    "xdp_mt_perf_event_array",
    [TAPI_BPF_MAP_TYPE_PERCPU_HASH] =         "xdp_mt_percpu_hash",
    [TAPI_BPF_MAP_TYPE_PERCPU_ARRAY] =        "xdp_mt_percpu_array",
    [TAPI_BPF_MAP_TYPE_STACK_TRACE] =         "xdp_mt_stack_trace",
    [TAPI_BPF_MAP_TYPE_CGROUP_ARRAY] =        "xdp_mt_cgroup_array",
    [TAPI_BPF_MAP_TYPE_LRU_HASH] =            "xdp_mt_lru_hash",
    [TAPI_BPF_MAP_TYPE_LRU_PERCPU_HASH] =     "xdp_mt_lru_percpu_hash",
    [TAPI_BPF_MAP_TYPE_LPM_TRIE] =            "xdp_mt_lpm_trie",
    [TAPI_BPF_MAP_TYPE_ARRAY_OF_MAPS] =       "xdp_mt_array_maps",
    [TAPI_BPF_MAP_TYPE_HASH_OF_MAPS] =        "xdp_mt_hash_maps",
    [TAPI_BPF_MAP_TYPE_DEVMAP] =              "xdp_mt_devmap",
    [TAPI_BPF_MAP_TYPE_SOCKMAP] =             "xdp_mt_sockmap",
    [TAPI_BPF_MAP_TYPE_CPUMAP] =              "xdp_mt_cpumap",
    [TAPI_BPF_MAP_TYPE_XSKMAP] =              "xdp_mt_xskmap",
    [TAPI_BPF_MAP_TYPE_SOCKHASH] =            "xdp_mt_sockhash",
    [TAPI_BPF_MAP_TYPE_CGROUP_STORAGE] =      "xdp_mt_cgroup_storage",
    [TAPI_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY] = "xdp_mt_reuseport_sockarray"
};

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    const struct if_nameindex *iut_if = NULL;

    unsigned int        bpf_id = 0;
    const char         *prog_name = NULL;
    char               *bpf_path = NULL;
    te_string           obj_name = TE_STRING_INIT_STATIC(RCF_MAX_PATH);
    tqh_strings         xdp_ifaces = TAILQ_HEAD_INITIALIZER(xdp_ifaces);
    char              **map_name = NULL;
    types_for_check     check_type;
    unsigned int        map_count = 0;
    tapi_bpf_map_type   map_type;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);
    TEST_GET_STRING_PARAM(prog_name);
    TEST_GET_ENUM_PARAM(check_type, CHECK_TYPE_VALUES);

    TEST_STEP("Add and load into the kernel @p prog_name on IUT.");
    te_string_append(&obj_name, "%s%s", prog_name, BPF_OBJ_NAME_SFX);
    bpf_path = sockts_bpf_get_path(pco_iut, iut_if->if_name, obj_name.ptr);
    rc = sockts_bpf_obj_init(pco_iut, iut_if->if_name, bpf_path,
                             TAPI_BPF_PROG_TYPE_XDP, &bpf_id);
    if (rc != 0)
        TEST_VERDICT("Failed to load BPF object into the kernel");

    TEST_STEP("Check that all needed programs are loaded.");
    CHECK_RC(sockts_bpf_prog_name_check(pco_iut, iut_if->if_name,
                                        bpf_id, XDP_PROG));

    if (check_type == CHECK_TYPE_MAP)
    {
        TEST_STEP("Get map type from XDP program name");
        CHECK_RC(te_str_find_index(prog_name, bpf_map_types,
                                   TE_ARRAY_LEN(bpf_map_types),
                                   (unsigned int *)&map_type));
        if (map_type == TAPI_BPF_MAP_TYPE_PERF_EVENT_ARRAY)
        {
            TEST_STEP("Check that there is loaded perf map");
            CHECK_RC(sockts_bpf_perf_map_get_list(pco_iut, iut_if->if_name,
                                                  bpf_id, &map_name,
                                                  &map_count));
            if (map_count == 0)
                TEST_VERDICT("Expected perf_event_array maps are not loaded");
        }
        else
        {
            TEST_STEP("Get list of maps");
            CHECK_RC(sockts_bpf_map_get_list(pco_iut, iut_if->if_name, bpf_id,
                                             &map_name, &map_count));
            if (map_count == 0)
                TEST_VERDICT("Expected maps are not loaded");
            TEST_STEP("Check that expected map type match with real type");
            rc = sockts_bpf_map_check_type(pco_iut, iut_if->if_name, bpf_id,
                                           map_name[0], map_type);
            if (rc != 0)
                TEST_VERDICT("Expected and real type does't match");
        }
    }
    TEST_SUCCESS;

cleanup:
    te_str_free_array(map_name);
    sockts_bpf_unlink_xdp(pco_iut, iut_if->if_name, &xdp_ifaces);
    if (bpf_id != 0)
        CLEANUP_CHECK_RC(sockts_bpf_obj_fini(pco_iut, iut_if->if_name, bpf_id));
    TEST_END;
}
