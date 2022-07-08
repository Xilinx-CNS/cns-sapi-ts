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

#define MAX_CPUS 128
#define PERF_EVENT_COOKIE 0xdead

typedef struct perf_event_data {
    __u16 cookie;
    __u16 len;
} perf_event_data;

struct bpf_map SEC("maps") perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = MAX_CPUS,
};

struct bpf_map SEC("maps") map_rule = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(bpf_tuple),
    .max_entries = 1,
};

SEC("prog")
int xdp_perf_event(struct xdp_md *ctx)
{
    perf_event_data metadata = {
        .cookie = PERF_EVENT_COOKIE,
    };
    frame_ptrs frame = FRAME_PTRS_INITIALIZER(ctx);
    __u16 ip_pld_len = 0;
    __u16 ip_hdr_len = 0;
    __u32 l4_hdr_len = 0;

    if (!frame_is_ip(&frame))
        return XDP_PASS;

    if (frame_tuple_cmp(&frame, &map_rule) != TUPLE_IS_EQUAL)
        return XDP_PASS;

    ip_pld_len = get_ip_payload_len(&frame);
    if (ip_pld_len == 0)
        return XDP_PASS;

    ip_hdr_len = get_ip_hdr_size(&frame);
    if (ip_hdr_len == 0)
        return XDP_PASS;

    l4_hdr_len = get_l4_hdr_len(&frame, ip_get_next_proto(&frame));
    if (l4_hdr_len == 0)
        return XDP_PASS;

    metadata.len = ip_pld_len - ip_hdr_len - l4_hdr_len;
    bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &metadata,
                          sizeof(metadata));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
