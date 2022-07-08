/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include "bpf_helpers.h"

/*
 * Type for action values which are used in test_action map.
 * The same enum must be declared in a test.
 */
typedef enum test_bpf_action {
    TEST_BPF_DROP,
    TEST_BPF_PASS,
} test_bpf_action;

struct bpf_map SEC("maps") test_action = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

struct bpf_map SEC("maps") pkt_cnt = {
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

SEC("classifier")
int tc_actions(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u32 *action;

    action = bpf_map_lookup_elem(&test_action, &key);
    if (action)
    {
        switch (*action)
        {
            case TEST_BPF_DROP:
                count_pkt();
                return TC_ACT_SHOT;

            case TEST_BPF_PASS:
                count_pkt();
                return TC_ACT_OK;

            default:
                break;
        }
    }

    return TC_ACT_OK;
}
