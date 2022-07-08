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

struct bpf_map SEC("maps") map_sockmap = {
    .type = BPF_MAP_TYPE_SOCKMAP,
    .key_size = sizeof(__u32),
    .value_size =sizeof(__u32),
    .max_entries = 2,
};

SEC("prog")
int xdp_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}
