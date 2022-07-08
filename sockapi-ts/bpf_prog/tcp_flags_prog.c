/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * XDP programs
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <linux/bpf.h>
#include "bpf.h"
#include "bpf_helpers.h"

#define TCP_HDR_FLAGS_OFFS 13

/* Map to store TCP packet counters */
struct bpf_map __attribute__((section("maps"), used)) tcp_seg_cnt = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 256,
};

struct bpf_map SEC("maps") map_rule = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(bpf_tuple),
    .max_entries = 1,
};

static __u8 get_tcp_flags(const frame_ptrs *frame)
{
    if (frame->data_cur + sizeof(struct tcphdr) > frame->data_end)
        return 0;

    return *((__u8 *)frame->data_cur + TCP_HDR_FLAGS_OFFS);
}

__attribute__((section("programs"), used))
int tcp_flags(struct xdp_md *ctx)
{
    frame_ptrs      frame = FRAME_PTRS_INITIALIZER(ctx);
    __u8            ipproto = 0;
    __u16           ethertype = 0;

    ethertype = eth2_get_ethertype(&frame);

    if (frame_tuple_cmp(&frame, &map_rule) != TUPLE_IS_EQUAL)
        return XDP_PASS;

    if (ethertype == bpf_htons(ETH_P_IP))
        ipproto = ipv4_get_next_proto(&frame);
    else if (ethertype == bpf_htons(ETH_P_IPV6))
        ipproto = ipv6_get_next_proto(&frame);
    else
        return XDP_PASS;

    if (ipproto == IPPROTO_TCP)
    {
        __u32      *counter = NULL;
        __u32       flags = 0;

        flags = get_tcp_flags(&frame);

        counter = bpf_map_lookup_elem(&tcp_seg_cnt, &flags);
        if (counter == NULL)
            return XDP_ABORTED;

        ++*counter;
    }

    return XDP_PASS;
}
