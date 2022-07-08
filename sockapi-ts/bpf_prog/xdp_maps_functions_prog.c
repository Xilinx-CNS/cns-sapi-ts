/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * XDP programs
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf.h"

/* This enum for get value from map_param */
enum key_param_t {
    KEY_FUNC,
    KEY_MAP_TYPE,
    KEY_KEY,
    KEY_VALUE,
};

/* Macro for get value from map_param */
#define LOOKUP(_param, _val) \
    do {                                               \
        __u64 _key = _param;                           \
        _val = bpf_map_lookup_elem(&map_param, &_key); \
        if (_val == NULL)                              \
            return XDP_PASS;                           \
    } while(0)

struct bpf_map SEC("maps") map_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map SEC("maps") map_array = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map SEC("maps") map_lpm_trie = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 1,
    .map_flags = 1U << 0
};

/*
 * This map stores the test parameters.
 * 0. Function for test: FUNC_UPDATE
 *                       FUNC_DELETE
 * 1. Map type:          BPF_MAP_TYPE_ARRAY
 *                       BPF_MAP_TYPE_HASH
 *                       BPF_MAP_TYPE_LPM_TRIE
 * 2. The key by which to update/delete the value.
 * 3. Value for update
 */
struct bpf_map SEC("maps") map_param = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 4,
};

/* This map stores return code */
struct bpf_map SEC("maps") map_rc = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

/*
 * Enumeration for the first element in map_param.
 * This enumeration is a copy of the enumeration in the test.
 */
enum {
    FUNC_UPDATE = 1,
    FUNC_DELETE,
};

/*
 * Enumeration for the second element in map_param
 * This enumeration is a copy of the enumeration in the test.
 */
enum {
    TEST_MAP_TYPE_ARRAY,
    TEST_MAP_TYPE_HASH,
    TEST_MAP_TYPE_LPM_TRIE
};

SEC("prog")
int xdp_prog(struct xdp_md *ctx)
{
    __u32 *func;
    __u64 *param_map_type;
    __u64 *param_key;
    void  *map;
    __u64 key_error = 0;
    __u64 val_error = 0;

    LOOKUP(KEY_FUNC, func);
    LOOKUP(KEY_MAP_TYPE, param_map_type);

    switch (*param_map_type)
    {
        case TEST_MAP_TYPE_HASH:
            map = &map_hash;
            break;

        case TEST_MAP_TYPE_LPM_TRIE:
            map = &map_lpm_trie;
            break;

        case TEST_MAP_TYPE_ARRAY:
            map = &map_array;
            break;

        default:
            return XDP_PASS;
    }

    LOOKUP(KEY_KEY, param_key);

    if (*func == FUNC_UPDATE)
    {
        __u64 *param_value;
        LOOKUP(KEY_VALUE, param_value);
        val_error = bpf_map_update_elem(map, param_key, param_value, BPF_ANY);
    }
    else if (*func == FUNC_DELETE)
    {
        val_error = bpf_map_delete_elem(map, param_key);
    }
    bpf_map_update_elem(&map_rc, &key_error, &val_error, BPF_ANY);
    return XDP_PASS;
}
