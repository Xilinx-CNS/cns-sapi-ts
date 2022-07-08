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
#include <linux/ipv6.h>
#include "bpf.h"
#include "bpf_helpers.h"

/* Map to store debug information */
struct bpf_map SEC("maps") map_debug = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAP_DEBUG_MAX_ENTRIES,
};

/* Swap source and destination MAC addresses */
static inline void swap_src_dst_mac(frame_ptrs *frame)
{
    __u8   *ptr = frame->data_cur;
    __u8    copy[6];

    memcpy(copy, ptr, sizeof(copy));
    memcpy(ptr, ptr + sizeof(copy), sizeof(copy));
    memcpy(ptr + sizeof(copy), copy, sizeof(copy));
}

SEC("prog")
int xdp_redirect(struct xdp_md *ctx)
{
    __u32                   val;
    __u16                   eth_type;
    __u8                    ip_proto;
    frame_ptrs              frame = FRAME_PTRS_INITIALIZER(ctx);

    eth_type = eth2_get_ethertype(&frame);
    if (eth_type == bpf_htons(ETH_P_IP))
        ip_proto = ipv4_get_next_proto(&frame);
    else if (eth_type == bpf_htons(ETH_P_IPV6))
        ip_proto = ipv6_get_next_proto(&frame);
    else
        return XDP_PASS;

    if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP)
        return XDP_PASS;

    MAP_DEBUG_COUNT(&map_debug);
    MAP_DEBUG_ADD(&map_debug, MAP_DEBUG_DEF_KEY_VAL);

    frame.data_cur = (void *)(__u64)ctx->data;

    /* MAC address length is 6 bytes and there are two MAC addresses */
    CHECK_OUT_OF_DATA(6 * 2);
    swap_src_dst_mac(&frame);

    val = bpf_redirect(1 /* lo: */, 0);
    MAP_DEBUG_ADD(&map_debug, val);

    return val;
}
