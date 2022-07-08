/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * XDP programs
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#include <stddef.h>
#include <sys/socket.h>
#include <linux/bpf.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"
#include "bpf.h"

#define IPV6_FLOWINFO_MASK __cpu_to_be32(0x0FFFFFFF)

/* This was derived from the bpf_fib_lookup function */
char __license[] SEC("license") = "GPL";

/* Map to store debug information */
struct bpf_map SEC("maps") map_debug = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAP_DEBUG_MAX_ENTRIES,
};

SEC("prog")
int xdp_fib_lookup(struct xdp_md *ctx)
{
    int                     rc;
    struct bpf_fib_lookup   par = {};
    __u16                   eth_type;
    __u8                    ip_proto;
    frame_ptrs              frame = FRAME_PTRS_INITIALIZER(ctx);

    MAP_DEBUG_COUNT(&map_debug);
    MAP_DEBUG_ADD(&map_debug, MAP_DEBUG_DEF_KEY_VAL);
    par.ifindex = ctx->ingress_ifindex;

    eth_type = eth2_get_ethertype(&frame);
    if (eth_type == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = frame.data_cur;

        CHECK_OUT_OF_DATA(sizeof(*iph));

        par.family = AF_INET;
        par.tos = iph->tos;
        par.tot_len = bpf_ntohs(iph->tot_len);
        par.ipv4_src = iph->saddr;
        par.ipv4_dst = iph->daddr;

        ip_proto = ipv4_get_next_proto(&frame);
    }
    else if (eth_type == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = frame.data_cur;

        CHECK_OUT_OF_DATA(sizeof(*ip6h));

        par.family = AF_INET6;
        par.flowinfo = *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
        par.tot_len = bpf_ntohs(ip6h->payload_len);

        memcpy(par.ipv6_dst, &ip6h->saddr, sizeof(par.ipv6_dst));
        memcpy(par.ipv6_dst, &ip6h->daddr, sizeof(par.ipv6_dst));

        ip_proto = ipv6_get_next_proto(&frame);
    }
    else
    {
        return XDP_PASS;
    }

    if (ip_proto == IPPROTO_TCP)
    {
        par.l4_protocol = IPPROTO_TCP;
        par.sport = 0;
        par.dport = 0;
    }
    else if (ip_proto == IPPROTO_UDP)
    {
        par.l4_protocol = IPPROTO_UDP;
        par.sport = 0;
        par.dport = 0;
    }
    else
    {
        return XDP_PASS;
    }

/* On some platforms BPF_FIB_LOOKUP_* can be declared using the BIT() macro,
 * which is not included in the /usr/include directory.
 */
#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

    rc = bpf_fib_lookup(ctx, &par, sizeof(par), BPF_FIB_LOOKUP_DIRECT |
                                                BPF_FIB_LOOKUP_OUTPUT);
    MAP_DEBUG_ADD(&map_debug, rc);
    return XDP_PASS;
}
