/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * XDP programs
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stddef.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf.h"

#define IP4_ADDR_PREFIX_FULL    32
#define IP6_ADDR_PREFIX_FULL    128

typedef struct lpm_trie_key {
    __u32   prefixlen;
    __u32   addr[4];
} lpm_trie_key;

struct bpf_map __attribute__((section("maps"), used)) lpm_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(lpm_trie_key),
    .value_size = sizeof(enum xdp_action),
    .max_entries = 50,
    .map_flags = BPF_F_NO_PREALLOC,
};

__attribute__((section("prog"), used))
int xdp_lpm_rule(struct xdp_md *ctx)
{
    enum xdp_action    *action;
    lpm_trie_key        key = {0};
    frame_ptrs          frame = FRAME_PTRS_INITIALIZER(ctx);
    __u16               ethertype = 0;

    ethertype = eth2_get_ethertype(&frame);

    if (ethertype == bpf_htons(ETH_P_IP))
    {
        __be32 src_addr = ipv4_get_src_addr(&frame);

        if (src_addr == 0)
            return XDP_PASS;

        key.prefixlen = IP4_ADDR_PREFIX_FULL;
        key.addr[0] = src_addr;
    }
    else if (ethertype == bpf_htons(ETH_P_IPV6))
    {
        struct in6_addr *src_addr = ipv6_get_src_addr(&frame);

        if (src_addr == NULL)
            return XDP_PASS;

        key.prefixlen = IP6_ADDR_PREFIX_FULL;
        memcpy(key.addr, src_addr, sizeof(*src_addr));
    }
    else
    {
        return XDP_PASS;
    }

    action = bpf_map_lookup_elem(&lpm_map, &key);
    if (action == NULL)
        return XDP_PASS;

    return *action;
}
