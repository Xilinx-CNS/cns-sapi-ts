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

struct bpf_map  __attribute__((section("maps"), used)) pkt_cnt = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1
};

__attribute__((section("programs"), used))
int xdp_drop(struct xdp_md *ctx)
{
    __u32           key = 0;
    __u32          *counter;
    frame_ptrs      frame = FRAME_PTRS_INITIALIZER(ctx);

    if (!proto_is_tcp_or_udp(&frame))
        return XDP_DROP;

    if ((counter = bpf_map_lookup_elem(&pkt_cnt, &key)) != NULL)
        ++*counter;

    return XDP_DROP;
}
