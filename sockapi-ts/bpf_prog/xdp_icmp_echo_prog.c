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
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include "bpf_helpers.h"
#include "bpf.h"

struct bpf_map SEC("maps") pkt_cnt = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1
};

SEC("prog")
int xdp_icmp_echo(struct xdp_md *ctx)
{
    __u16      eth_type;
    __u8       ipproto;
    __u32      key = 0;
    __u32     *counter;
    frame_ptrs frame = FRAME_PTRS_INITIALIZER(ctx);

    eth_type = eth2_get_ethertype(&frame);
    if (eth_type == bpf_htons(ETH_P_IP))
        ipproto = ipv4_get_next_proto(&frame);
    else if (eth_type == bpf_htons(ETH_P_IPV6))
        ipproto = ipv6_get_next_proto(&frame);
    else
        return XDP_PASS;

    CHECK_OUT_OF_DATA(1);
    if ((ipproto == IPPROTO_ICMP && *(__u8*)frame.data_cur == ICMP_ECHO) ||
        (ipproto == IPPROTO_ICMPV6 && *(__u8*)frame.data_cur == ICMPV6_ECHO_REQUEST))
    {
        if ((counter = bpf_map_lookup_elem(&pkt_cnt, &key)) != NULL)
            ++*counter;
    }
    return XDP_PASS;
}
