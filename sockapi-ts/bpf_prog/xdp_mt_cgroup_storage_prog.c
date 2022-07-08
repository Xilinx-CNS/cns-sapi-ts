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

#ifdef HAVE_BPF_MAP_TYPE_CGROUP_STORAGE
struct bpf_map SEC("maps") map_cgrp_stor = {
    .type = BPF_MAP_TYPE_CGROUP_STORAGE,
    .key_size = sizeof(struct bpf_cgroup_storage_key),
    .value_size = sizeof(__u32),
    .max_entries = 0,
};
#endif

SEC("prog")
int xdp_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}
