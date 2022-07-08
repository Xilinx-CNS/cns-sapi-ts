/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * XDP programs
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#include <stddef.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf.h"

struct bpf_map  __attribute__((section("maps"), used)) map_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1
};

struct bpf_map  __attribute__((section("maps"), used)) map_array = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1
};

struct bpf_map  __attribute__((section("maps"), used)) map_select = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1
};

__attribute__((section("programs"), used))
int xdp_maps(struct xdp_md *ctx)
{
    __u32   key = 0;
    __u32   hash = 0xAABBCCDD;
    __u32  *val = NULL;

    frame_ptrs frame = FRAME_PTRS_INITIALIZER(ctx);

    if (!proto_is_tcp_or_udp(&frame))
        return XDP_PASS;

    if ((val = bpf_map_lookup_elem(&map_select, &key)) == NULL ||
        (*val != BPF_MAP_TYPE_HASH && *val != BPF_MAP_TYPE_ARRAY))
    {
        return XDP_PASS;
    }

    if (*val == BPF_MAP_TYPE_HASH)
        val = bpf_map_lookup_elem(&map_hash, &hash);
    else
        val = bpf_map_lookup_elem(&map_array, &key);

    if (val != NULL)
        ++*val;

    return XDP_PASS;
}
