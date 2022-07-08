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
#include "bpf_helpers.h"
#include "bpf.h"

/* Map to store IPv4 address to be changed  */
struct bpf_map SEC("maps") map_ipv4_addr = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

/* Map to store IPv6 address to be changed  */
struct bpf_map SEC("maps") map_ipv6_addr = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct in6_addr),
    .value_size = sizeof(struct in6_addr),
    .max_entries = 1,
};

static __always_inline __u16 csum_fold_helper(__u32 sum)
{
    sum = (sum & 0xffff) + (sum >> 16);
    return ~((sum & 0xffff) + (sum >> 16));
}

SEC("prog")
int xdp_change_addr(struct xdp_md *ctx)
{
    __u16      eth_type;
    frame_ptrs frame = FRAME_PTRS_INITIALIZER(ctx);

    eth_type = eth2_get_ethertype(&frame);
    if (eth_type == bpf_htons(ETH_P_IP))
    {
        __u32           csum;
        __u32          *val;
        struct iphdr   *iph = frame.data_cur;

        CHECK_OUT_OF_DATA(sizeof(*iph));

        if ((val = bpf_map_lookup_elem(&map_ipv4_addr, &iph->saddr)) == NULL)
            return XDP_PASS;

        /* Recalculate IPv4 header's checksum */
        csum = bpf_csum_diff(&iph->saddr, sizeof(iph->saddr), val,
                             sizeof(iph->saddr), ~iph->check);
        iph->check = csum_fold_helper(csum);
        iph->saddr = *val;
    }
    else if (eth_type == bpf_htons(ETH_P_IPV6))
    {
        struct in6_addr *val;
        struct ipv6hdr  *ip6h = frame.data_cur;

        CHECK_OUT_OF_DATA(sizeof(*ip6h));

        if ((val = bpf_map_lookup_elem(&map_ipv6_addr, &ip6h->saddr)) == NULL)
            return XDP_PASS;

        memcpy(&ip6h->saddr, val, sizeof(*val));
    }

    return XDP_PASS;
}
