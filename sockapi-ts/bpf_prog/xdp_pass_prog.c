/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * XDP programs
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf.h"

struct bpf_map SEC("maps") map_counter = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

SEC("prog")
int xdp_pass(struct xdp_md *ctx)
{
    frame_ptrs  frame = FRAME_PTRS_INITIALIZER(ctx);
    __u32       key = 0;
    __u32      *counter = NULL;

    if (!proto_is_tcp_or_udp(&frame))
        return XDP_PASS;

    if ((counter = bpf_map_lookup_elem(&map_counter, &key)) != NULL)
        ++*counter;

    return XDP_PASS;
}
