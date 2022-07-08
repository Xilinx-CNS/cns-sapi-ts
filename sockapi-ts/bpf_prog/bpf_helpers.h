/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief BPF/XDP Test Suite
 *
 * Auxilliary functions and structures for BPF programs.
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#ifndef __BPF_PROGRAMS_BPF_HELPERS_H__
#define __BPF_PROGRAMS_BPF_HELPERS_H__

#ifndef NULL
#define NULL (void *)0
#endif /* NULL */

/**
 * Enable/disable debug mode - print debug messages.
 * The output is located in /sys/kernel/debug/tracing/trace
 */
#ifndef TC_DEBUG
#define TC_DEBUG 0
#endif /* TC_DEBUG */

/**
 * Macro to declare BPF helper functions.
 */
#define BPF_HELPER_DECL(_rettype, _name, ...) \
    static _rettype (*bpf_##_name)(__VA_ARGS__) = (void *) BPF_FUNC_##_name

/* helper macro to place programs, maps, license */
#define SEC(NAME) __attribute__((section(NAME), used))

/* Structure of maps used in BPF programs */
struct bpf_map {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int inner_map_idx;
};

/* Kernel functions to work with maps */
BPF_HELPER_DECL(void *, map_lookup_elem, void *map, void *key);
BPF_HELPER_DECL(int, map_update_elem, void *map, void *key, void *value,
                unsigned long long flags);
BPF_HELPER_DECL(int, map_delete_elem, void *map, void *key);
BPF_HELPER_DECL(int, perf_event_output, void *ctx, void *map, int index,
                void *data, int size);

#ifdef HAVE_BPF_FUNC_sk_lookup_tcp
BPF_HELPER_DECL(struct bpf_sock *, sk_lookup_tcp, void *ctx,
                struct bpf_sock_tuple *tuple, int size,
                unsigned long long netns_id, unsigned long long flags);
#endif

#ifdef HAVE_BPF_FUNC_sk_lookup_udp
BPF_HELPER_DECL(struct bpf_sock *, sk_lookup_udp, void *ctx,
                struct bpf_sock_tuple *tuple, int size,
                unsigned long long netns_id, unsigned long long flags);
#endif

#ifdef HAVE_BPF_FUNC_sk_release
BPF_HELPER_DECL(int, sk_release, struct bpf_sock *sk);
#endif

BPF_HELPER_DECL(int, fib_lookup, void *ctx, struct bpf_fib_lookup *params,
                int plen, __u32 flags);
BPF_HELPER_DECL(int, redirect, int ifindex, int flags);
BPF_HELPER_DECL(int, csum_diff, void *from, int from_size, void *to,
                int to_size, int seed);
BPF_HELPER_DECL(int, clone_redirect, struct __sk_buff *skb,
                                     __u32 ifindex,
                                     __u64 flags);
BPF_HELPER_DECL(int, skb_load_bytes, const struct __sk_buff *skb, __u32 offset,
                                     void *to, __u32 len);
BPF_HELPER_DECL(int, skb_store_bytes, const struct __sk_buff *skb, __u32 offset,
                                      const void *from, __u32 len, __u64 flags);
BPF_HELPER_DECL(int, skb_change_tail, const struct __sk_buff *skb, __u32 len,
                                      __u64 flags);

#if TC_DEBUG
BPF_HELPER_DECL(int, trace_printk, const char *fmt, __u32 fmt_size, ...);

#define printk(fmt, ...)                                \
        ({                                              \
            char ____fmt[] = fmt;                       \
            bpf_trace_printk(____fmt, sizeof(____fmt),  \
                     ##__VA_ARGS__);                    \
        })
#else
#define printk(...)
#endif /* TC_DEBUG */

#endif /* !__BPF_PROGRAMS_BPF_HELPERS_H__ */
