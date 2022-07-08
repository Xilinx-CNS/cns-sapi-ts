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

/* Map to store debug information */
struct bpf_map SEC("maps") map_debug = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAP_DEBUG_MAX_ENTRIES,
};


SEC("prog")
int xdp_sk_lookup(struct xdp_md *ctx)
{
#if defined(HAVE_BPF_FUNC_sk_lookup_tcp) && \
    defined(HAVE_BPF_FUNC_sk_lookup_udp) && \
    defined(HAVE_BPF_FUNC_sk_release)

    struct bpf_sock        *sk = NULL;
    struct bpf_sock_tuple   tuple = {};
    __u32                   val;
    __u32                   tuple_size;
    __u16                   eth_type;
    __u8                    ip_proto;
    frame_ptrs              frame = FRAME_PTRS_INITIALIZER(ctx);

    eth_type = eth2_get_ethertype(&frame);
    if (eth_type == bpf_htons(ETH_P_IP))
    {
        struct iphdr *iph = frame.data_cur;

        CHECK_OUT_OF_DATA(sizeof(*iph));

        tuple.ipv4.saddr = iph->saddr;
        tuple.ipv4.daddr = iph->daddr;

        ip_proto = ipv4_get_next_proto(&frame);
    }
    else if (eth_type == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6h = frame.data_cur;

        CHECK_OUT_OF_DATA(sizeof(*ip6h));

        memcpy(tuple.ipv6.saddr, &ip6h->saddr, sizeof(tuple.ipv6.saddr));
        memcpy(tuple.ipv6.daddr, &ip6h->daddr, sizeof(tuple.ipv6.daddr));

        ip_proto = ipv6_get_next_proto(&frame);
    }
    else
    {
        return XDP_PASS;
    }

    if (ip_proto == IPPROTO_TCP)
    {
        struct tcphdr *tcph = frame.data_cur;

        CHECK_OUT_OF_DATA(sizeof(*tcph));
        if (eth_type == bpf_htons(ETH_P_IP))
        {
            tuple.ipv4.sport = tcph->source;
            tuple.ipv4.dport = tcph->dest;
            tuple_size = sizeof(tuple.ipv4);
        }
        else
        {
            tuple.ipv6.sport = tcph->source;
            tuple.ipv6.dport = tcph->dest;
            tuple_size = sizeof(tuple.ipv6);
        }

        sk = bpf_sk_lookup_tcp(ctx, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
    }
    else if (ip_proto == IPPROTO_UDP)
    {
        struct udphdr *udph = frame.data_cur;

        CHECK_OUT_OF_DATA(sizeof(*udph));

        if (eth_type == bpf_htons(ETH_P_IP))
        {
            tuple.ipv4.sport = udph->source;
            tuple.ipv4.dport = udph->dest;
            tuple_size = sizeof(tuple.ipv4);
        }
        else
        {
            tuple.ipv6.sport = udph->source;
            tuple.ipv6.dport = udph->dest;
            tuple_size = sizeof(tuple.ipv6);
        }

        sk = bpf_sk_lookup_udp(ctx, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
    }
    else
    {
        return XDP_PASS;
    }

    if (sk != NULL)
    {
        val = sk->protocol;
        bpf_sk_release(sk);
    }
    else
    {
        val = 0;
    }
    MAP_DEBUG_COUNT(&map_debug);
    MAP_DEBUG_ADD(&map_debug, val);

    return XDP_PASS;
#else
    /* bpf_sk_lookup_* and bpf_sk_release is not supported
     * by kernel: count packets only */
    MAP_DEBUG_COUNT(&map_debug);
    MAP_DEBUG_ADD(&map_debug, MAP_DEBUG_DEF_KEY_VAL);

    return XDP_PASS;
#endif
}
