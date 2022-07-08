/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * XDP programs
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdbool.h>
#include <linux/bpf.h>
#include "bpf.h"
#include "bpf_helpers.h"

/* Map contaning the 4-tuple rule. */
struct bpf_map __attribute__((section("maps"), used)) map_rule = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(bpf_tuple),
    .max_entries = 1,
};

__attribute__((section("prog"), used))
int one_rule_filter(struct xdp_md *ctx)
{
    frame_ptrs      frame = FRAME_PTRS_INITIALIZER(ctx);
    __u16           ethertype = 0;

    ethertype = eth2_get_ethertype(&frame);

    if (ethertype == bpf_htons(ETH_P_IP) || ethertype == bpf_htons(ETH_P_IPV6))
    {
        frame_tuple_cmp_rc rc = frame_tuple_cmp(&frame, &map_rule);

        if (rc == TUPLE_IS_EQUAL)
            return XDP_PASS;
        else
            return XDP_DROP;
    }

    return XDP_PASS;
}
