/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * XDP programs
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf.h"

/*
 * Type for action values which are used in test_action map.
 * The same enum must be declared in a test.
 */
typedef enum test_bpf_action {
    TEST_BPF_DROP,
    TEST_BPF_PASS,
} test_bpf_action;

/* Map to get XDP action from the test. XDP program shouldn't write to it. */
struct bpf_map __attribute__((section("maps"), used)) test_action = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

/* Map to count processed packets. */
struct bpf_map __attribute__((section("maps"), used)) pkt_cnt = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

static inline void count_pkt(void)
{
    __u32 key = 0;
    __u32 *count;

    count = bpf_map_lookup_elem(&pkt_cnt, &key);
    if (count)
        *count += 1;
}

__attribute__((section("programs"), used))
int xdp_actions(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32 *action;

    frame_ptrs frame = FRAME_PTRS_INITIALIZER(ctx);

    if (!proto_is_tcp_or_udp(&frame))
        return XDP_PASS;

    action = bpf_map_lookup_elem(&test_action, &key);
    if (action)
    {
        switch (*action)
        {
            case TEST_BPF_DROP:
                count_pkt();
                return XDP_DROP;

            case TEST_BPF_PASS:
                count_pkt();
                return XDP_PASS;

            default:
                break;
        }
    }

    return XDP_PASS;
}
