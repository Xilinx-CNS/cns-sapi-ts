/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief BPF/XDP Test Suite
 *
 * Common functions and structures to use in XDP programs.
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */
#ifndef __BPF_PROGRAMS_BPF_H__
#define __BPF_PROGRAMS_BPF_H__

#include <stddef.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"

#define SA(_p)      ((struct sockaddr *)(_p))
#define SIN(_p)     ((struct sockaddr_in *)(_p))
#define SIN6(_p)    ((struct sockaddr_in6 *)(_p))

/**
 * Structure describing a connection 5-tuple.
 * The same is defined in sockapi-ts/lib/sockapi-ts_bpf.h
 */
typedef struct bpf_tuple {
    struct sockaddr_storage src_addr;   /**< Source IP address. */
    struct sockaddr_storage dst_addr;   /**< Destination IP address. */
    __u8                    proto;      /**< Protocol specificator. */
} bpf_tuple;

/**
 * Return code for @ref frame_tuple_cmp.
 */
typedef enum {
    TUPLE_IS_EQUAL,     /**< Packet 5-tuple is equal to the storing in
                             map one. */
    TUPLE_IS_NOT_EQUAL, /**< Packet 5-tuple is not equal to the storing in
                             map one. */
    TUPLE_PARSE_ERR,    /**< Fail to get tuple from frame. */
} frame_tuple_cmp_rc;

/** Structure to store incoming frame pointers. */
typedef struct frame_ptrs {
    void        *data_cur;  /**<
                             * Pointer to the current position in packet. The
                             * pointer value is changeable by a frame parsing
                             * functions.
                             */
    void * const data_end;  /**< Constant pointer to the end of packet. */
} frame_ptrs;

/**
 * Initializer for @ref frame_ptrs structure.
 * @param _ctx  Pointer to user data (struct xdp_md), that is passed
 *              to XDP program.
 */
#define FRAME_PTRS_INITIALIZER(_ctx) {                  \
            .data_cur = (void *)(__u64)_ctx->data,      \
            .data_end = (void *)(__u64)_ctx->data_end   \
        }

/**
 * Macro to check whether @p _hdr_type is an extension IPv6 header.
 * @param _hdr_type     IPv6 header type code to check.
 */
#define IS_IPV6_EXT_HDR(_hdr_type)      \
    ((_hdr_type) == IPPROTO_HOPOPTS ||  \
    (_hdr_type) == IPPROTO_ROUTING ||   \
    (_hdr_type) == IPPROTO_FRAGMENT ||  \
    (_hdr_type) == IPPROTO_DSTOPTS)

/**
 * Maximum number of IPv6 extension headers.
 * The value is calculated assuming that every header type,
 * checked in @ref IS_IPV6_EXT_HDR macro, appears only once
 * in packet.
 */
#define IPV6_MAX_HEADERS 4

/** IPv6 fragment extension header length. */
#define IPV6_EXT_FRAG_HDR_LEN 8

/**
 * Parse ethernet header and return value of ethertype field
 * in network byte order.
 *
 * @note This function changes @b data_cur field of @p frame
 * and sets it to a next header.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of ethernet header.
 *
 * @return @c ethertype field or zero in case of error.
 */
static inline __u16
eth2_get_ethertype(frame_ptrs *frame)
{
    /*
     * Declare this structure inside the function because it does
     * not have to be used anywhere else.
     */
    typedef struct vlanhdr {
        __be16 h_vlan_TCI;
        __be16 h_vlan_ethertype;
    } vlanhdr;

    struct ethhdr *eth = frame->data_cur;
    __u16          eth_type = 0;

    if (frame->data_cur + sizeof(*eth) > frame->data_end)
        return 0;

    frame->data_cur += sizeof(*eth);
    eth_type = eth->h_proto;

    /* Handle VLAN tagged packet */
    if (eth_type == bpf_htons(ETH_P_8021Q) ||
        eth_type == bpf_htons(ETH_P_8021AD))
    {
        vlanhdr *vlan_hdr = frame->data_cur;

        if (frame->data_cur + sizeof(*vlan_hdr) > frame->data_end)
            return 0;

        frame->data_cur += sizeof(*vlan_hdr);
        eth_type = vlan_hdr->h_vlan_ethertype;
    }

    /* Handle double VLAN tagged packet */
    if (eth_type == bpf_htons(ETH_P_8021Q) ||
        eth_type == bpf_htons(ETH_P_8021AD))
    {
        vlanhdr *vlan_hdr = frame->data_cur;

        if (frame->data_cur + sizeof(*vlan_hdr) > frame->data_end)
            return 0;

        frame->data_cur += sizeof(*vlan_hdr);
        eth_type = vlan_hdr->h_vlan_ethertype;
    }

    return eth_type;
}

/**
 * Parse IPv4 header and return value of protocol field.
 *
 * @note This function changes @b data_cur field of @p frame
 * and sets it to a next header.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IPv4 header.
 *
 * @return @c protocol field or zero in case of error.
 */
static inline __u8
ipv4_get_next_proto(frame_ptrs *frame)
{
    struct iphdr *iph = frame->data_cur;
    __u8          hdr_len = 0;

    if (frame->data_cur + sizeof(*iph) > frame->data_end)
        return 0;

    /* IHL field is the length of the IPv4 header in 32 bit words. */
    hdr_len = iph->ihl * 4;
    frame->data_cur += hdr_len;

    return iph->protocol;
}

/**
 * Parse IPv6 header and return value of Next Header field.
 *
 * @note This function changes @b data_cur field of @p frame
 * and sets it to a next header.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IPv6 header.
 *
 * @return Next Header field or zero in case of error.
 */
__attribute__((always_inline))
static inline __u8
ipv6_get_next_proto(frame_ptrs *frame)
{
    struct ipv6hdr *ip6h = frame->data_cur;
    __u8            next_hdr = 0;
    __u32           hdr_len = 0;
    int             i = 0;

    if (frame->data_cur + sizeof(*ip6h) > frame->data_end)
        return 0;

    frame->data_cur += sizeof(*ip6h);
    next_hdr = ip6h->nexthdr;

    for (i = 0; i < IPV6_MAX_HEADERS; i++)
    {
        switch (next_hdr)
        {
            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING:
                if (frame->data_cur + sizeof(struct ipv6_opt_hdr) > frame->data_end)
                    return 0;
                next_hdr = ((struct ipv6_opt_hdr *)frame->data_cur)->nexthdr;
                hdr_len = ((struct ipv6_opt_hdr *)frame->data_cur)->hdrlen;
                /*
                 * Length is defined in 8-octet units, not including
                 * the first 8 octets.
                 */
                frame->data_cur += hdr_len * 8 + 8;
                if (!IS_IPV6_EXT_HDR(next_hdr))
                    return next_hdr;
                break;

            case IPPROTO_FRAGMENT:
                if (frame->data_cur + IPV6_EXT_FRAG_HDR_LEN > frame->data_end)
                    return 0;
                /*
                 * Type of next header is located at zero offset within
                 * a fragment extension header.
                 */
                next_hdr = *(__u8 *)frame->data_cur;
                frame->data_cur += IPV6_EXT_FRAG_HDR_LEN;
                if (!IS_IPV6_EXT_HDR(next_hdr))
                    return next_hdr;
                break;

            default:
                break;
        }
    }

    return next_hdr;
}

/**
 * Get source IPv4 address.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IPv4 header.
 *
 * @return Source IPv4 address or zero in case of error.
 */
static inline __be32
ipv4_get_src_addr(const frame_ptrs *frame)
{
    struct iphdr *iph = frame->data_cur;

    if (frame->data_cur + sizeof(*iph) > frame->data_end)
        return 0;

    return iph->saddr;
}

/**
 * Get destination IPv4 address.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IPv4 header.
 *
 * @return Destination IPv4 address or zero in case of error.
 */
static inline __be32
ipv4_get_dst_addr(const frame_ptrs *frame)
{
    struct iphdr *iph = frame->data_cur;

    if (frame->data_cur + sizeof(*iph) > frame->data_end)
        return 0;

    return iph->daddr;
}

/**
 * Get source IPv6 address.
 * @attention Always check return pointer against @c NULL, because otherwise
 *            XDP program will not be loaded.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IPv6 header.
 *
 * @return Pointer to the source IPv6 address or @c NULL in case of error.
 */
static inline struct in6_addr *
ipv6_get_src_addr(const frame_ptrs *frame)
{
    struct ipv6hdr *ip6h = frame->data_cur;

    if (frame->data_cur + sizeof(*ip6h) > frame->data_end)
        return NULL;

    return &ip6h->saddr;
}

/**
 * Get destination IPv6 address.
 * @attention Always check return pointer against @c NULL, because otherwise
 *            XDP program will not be loaded.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IPv6 header.
 *
 * @return Pointer to the destination IPv6 address or @c NULL in case of error.
 */
static inline struct in6_addr *
ipv6_get_dst_addr(const frame_ptrs *frame)
{
    struct ipv6hdr *ip6h = frame->data_cur;

    if (frame->data_cur + sizeof(*ip6h) > frame->data_end)
        return NULL;

    return &ip6h->daddr;
}

/**
 * Get source port from TCP/UDP header of incoming packet.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of L4 protocol header.
 * @param l4proto   Determine the L4 protocol - @c IPPROTO_TCP and
 *                  @c IPPROTO_UDP are supported.
 *
 * @return Source port value in network byte order, or zero in case of error.
 */
static inline __be16
l4_get_src_port(const frame_ptrs *frame, __u8 l4proto)
{
    if (l4proto == IPPROTO_TCP)
    {
        struct tcphdr *tcp = frame->data_cur;

        if (frame->data_cur + sizeof(*tcp) > frame->data_end)
            return 0;

        return tcp->source;
    }
    else if (l4proto == IPPROTO_UDP)
    {
        struct udphdr *udp = frame->data_cur;

        if (frame->data_cur + sizeof(*udp) > frame->data_end)
            return 0;

        return udp->source;
    }

    return 0;
}

/**
 * Get destination port from TCP/UDP header of incoming packet.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of L4 protocol header.
 * @param l4proto   Determine the L4 protocol - @c IPPROTO_TCP and
 *                  @c IPPROTO_UDP are supported.
 *
 * @return  Destination port value in network byte order, or zero in case of
 *          error.
 */
static inline __be16
l4_get_dst_port(const frame_ptrs *frame, __u8 l4proto)
{
    if (l4proto == IPPROTO_TCP)
    {
        struct tcphdr *tcp = frame->data_cur;

        if (frame->data_cur + sizeof(*tcp) > frame->data_end)
            return 0;

        return tcp->dest;
    }
    else if (l4proto == IPPROTO_UDP)
    {
        struct udphdr *udp = frame->data_cur;

        if (frame->data_cur + sizeof(*udp) > frame->data_end)
            return 0;

        return udp->dest;
    }

    return 0;
}

/**
 * Compare two memory buffers byte by byte.
 *
 * @param buf1  Pointer to the first buffer to be compared.
 * @param buf2  Pointer to the secong buffer to be compared.
 * @param len   Length of the buffers.
 *
 * @return 0 if the buffers are equal, otherwise returns -1.
 */
static inline int
byte2byte_cmp(const void *buf1, const void *buf2, size_t len)
{
    size_t  i;
    char   *p1 = (char *)buf1;
    char   *p2 = (char *)buf2;

    for (i = 0; i < len; ++i)
    {
        if (*p1++ != *p2++)
            return -1;
    }
    return 0;
}

/*
 * Since BPF programs cannot perform any function calls other
 * than those to BPF helpers, common library code needs to be
 * implemented as inline functions.
 */
#ifndef memcmp
#define memcmp(s1, s2, n)  byte2byte_cmp((s1), (s2), (n))
#endif

/**
 * It useful when copying IPv6 addresses
 */
#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

/**
 * Check that xdp program does not try to read/write over upper memory limit
 */
#define CHECK_OUT_OF_DATA(_len)             \
if (frame.data_cur + _len > frame.data_end) \
    return XDP_PASS;

/**
 * Maximum number of entries for debug map, used in some tests.
 * We must define maximum entries of the map as a macro, because access
 * to @b max_entries field may be unavailable on new kernels (approx. >= 5.9).
 * See ST-2340.
 */
#define MAP_DEBUG_MAX_ENTRIES 16

/**
 * Increment first key in the @p _map
 *
 * param _map   Pointer to bpf_map with type @c BPF_MAP_TYPE_ARRAY
 */
#define MAP_DEBUG_COUNT(_map) \
    do {                                                        \
        __u32 _key = 0;                                         \
        __u32 *_val;                                            \
        if ((_val = bpf_map_lookup_elem(_map, &_key)) != NULL)  \
            ++*_val;                                            \
    } while(0)

/**
 * Write @p _value to key[key[0]], do nothing if key[0] is over maximum
 * entries in the @p _map.
 * It can be used to store in the @p _map total packets number in
 * the first key[0] and store some info about each packet in following
 * keys, for example: size of packet, ethernet type, IP version.
 *
 * param _map   Pointer to bpf_map with type @c BPF_MAP_TYPE_ARRAY
 * param _value Value to store
 */
#define MAP_DEBUG_ADD(_map, _value) \
    do {                                                        \
        __u32 _key = 0;                                         \
        __u32 *_val;                                            \
        if ((_val = bpf_map_lookup_elem(_map, &_key)) != NULL)  \
        {                                                       \
            _key = *_val;                                       \
            if (_key < MAP_DEBUG_MAX_ENTRIES)                   \
            {                                                   \
                _val = bpf_map_lookup_elem(_map, &_key);        \
                if (_val != NULL)                               \
                    *_val = _value;                             \
            }                                                   \
        }                                                       \
    } while (0)

/**
 * Default key value in debug map for keys > 0. If this value is
 * appeared in the map after xdp program was finished it means that
 * testing function (for example bpf_sk_lookup_tcp) was not launched.
 * @sa MAP_DEBUG_ADD
 */
#define MAP_DEBUG_DEF_KEY_VAL 255

/**
 * Check L4 protocol to be TCP or UDP.
 *
 * @note This function changes @b data_cur field of @p frame
 * and sets it to a TCP/UDP header.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points to the start of ethernet header.
 *
 * @return @c true if L4 protocol is TCP or UDP, otherwise returns @c false.
 */
static inline bool
proto_is_tcp_or_udp(frame_ptrs *frame)
{
    __u16      eth_type = 0;
    __u8       ipproto = 0;

    eth_type = eth2_get_ethertype(frame);
    if (eth_type == bpf_htons(ETH_P_IP))
        ipproto = ipv4_get_next_proto(frame);
    else if (eth_type == bpf_htons(ETH_P_IPV6))
        ipproto = ipv6_get_next_proto(frame);
    else
        return false;

    if (ipproto != IPPROTO_TCP && ipproto != IPPROTO_UDP)
        return false;

    return true;
}

/**
 * Return IP header version.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IP header.
 *
 * @return Version of IP protocol defined in first 4 bits of the header,
 *         or @c 0 if an error occured.
 */
static inline __u8
get_ip_version(const frame_ptrs *frame)
{
    if (frame->data_cur + 1 > frame->data_end)
        return 0;
    return *(__u8 *)frame->data_cur >> 4;
}

/**
 * Return IP payload length in bytes including header and data.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IP header.
 *
 * @return Payload length in host byte order or @c 0 if an error occured.
 */
static inline __u16
get_ip_payload_len(const frame_ptrs *frame)
{
    __u8 ver = get_ip_version(frame);

    if (ver == 4)
    {
        struct iphdr *iph = frame->data_cur;
        if (frame->data_cur + sizeof(*iph) > frame->data_end)
            return 0;
        return bpf_ntohs(iph->tot_len);
    }
    else if (ver == 6)
    {
        struct ipv6hdr *ip6h = frame->data_cur;
        if (frame->data_cur + sizeof(*ip6h) > frame->data_end)
            return 0;
        return bpf_ntohs(ip6h->payload_len) + sizeof(*ip6h);
    }
    else
    {
        return 0;
    }
}

/**
 * Return IP header length in bytes.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IP header.
 *
 * @return Header length in host byte order or @c 0 if an error occured.
 */
static inline __u16
get_ip_hdr_size(const frame_ptrs *frame)
{
    __u8 ver = get_ip_version(frame);
    __u16 hdr_size = 0;
    void *data_cur = frame->data_cur;

    if (ver == 4)
    {
        struct iphdr *ip4 = data_cur;
        if (data_cur + sizeof(*ip4) > frame->data_end)
            return 0;
        hdr_size = ip4->ihl * sizeof(__u32);
    }
    else if (ver == 6)
    {
        struct ipv6hdr *ip6h = data_cur;
        __u8 next_hdr = 0;
        int i = 0;

        if (data_cur + sizeof(*ip6h) > frame->data_end)
            return 0;

        hdr_size = sizeof(*ip6h);
        next_hdr = ip6h->nexthdr;
        data_cur += hdr_size;

        for (i = 0; i < IPV6_MAX_HEADERS; i++)
        {
            __u32 ext_hdr_len = 0;

            switch (next_hdr)
            {
                case IPPROTO_HOPOPTS:
                case IPPROTO_DSTOPTS:
                case IPPROTO_ROUTING:
                    if (data_cur + sizeof(struct ipv6_opt_hdr) > frame->data_end)
                        return 0;
                    next_hdr = ((struct ipv6_opt_hdr *)data_cur)->nexthdr;
                    /*
                     * Length is defined in 8-octet units, not including
                     * the first 8 octets.
                     */
                    ext_hdr_len = 8;
                    ext_hdr_len += ((struct ipv6_opt_hdr *)data_cur)->hdrlen * 8;
                    data_cur += ext_hdr_len;
                    break;

                case IPPROTO_FRAGMENT:
                    if (data_cur + IPV6_EXT_FRAG_HDR_LEN > frame->data_end)
                        return 0;
                    /* Type of next header is located at zero offset. */
                    next_hdr = *(__u8 *)data_cur;
                    ext_hdr_len = IPV6_EXT_FRAG_HDR_LEN;
                    data_cur += ext_hdr_len;
                    break;

                default:
                    break;
            }

            hdr_size += ext_hdr_len;

            if (!IS_IPV6_EXT_HDR(next_hdr))
                break;
        }
    }

    return hdr_size;
}

/**
 * Parse ethernet header and check whether the frame is IPv4 or IPv6.
 *
 * @note This function changes @b data_cur field of @p frame
 * and sets it to a next header.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of ethernet header.
 *
 * @return @c true if imcoming frame is IP, @c false otherwise.
 */
static inline bool
frame_is_ip(frame_ptrs *frame)
{
    __u16 etype = eth2_get_ethertype(frame);

    return (etype == bpf_htons(ETH_P_IP) || etype == bpf_htons(ETH_P_IPV6));
}

/**
 * Parse IP header and return next protocol number.
 *
 * @note This function changes @b data_cur field of @p frame
 * and sets it to a next header.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of IP header.
 *
 * @return Next protocol or zero in case of error.
 */
static inline __u8
ip_get_next_proto(frame_ptrs *frame)
{
    __u8 ver = get_ip_version(frame);

    if (ver == 4)
        return ipv4_get_next_proto(frame);
    else if (ver == 6)
        return ipv6_get_next_proto(frame);
    else
        return 0;
}

/**
 * Return TCP/UDP header length in bytes.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points the start of TCP/UDP header.
 * @param proto     The protocol - may be @c IPPROTO_TCP or @c IPPROTO_UDP.
 *
 * @return Header length or @c 0 if an error occured.
 */
static inline __u32
get_l4_hdr_len(const frame_ptrs *frame, __u8 proto)
{
    if (proto == IPPROTO_TCP)
    {
        struct tcphdr *tcp = frame->data_cur;
        if (frame->data_cur + sizeof(*tcp) > frame->data_end)
            return 0;
        return tcp->doff * sizeof(__u32);
    }
    else if (proto == IPPROTO_UDP)
    {
        return sizeof(struct udphdr);
    }
    else
    {
        return 0;
    }
}

/**
 * Compare 2 socket IPv4 or IPv6 addresses.
 *
 * @param addr1     Address 1.
 * @param addr2     Address 2.
 *
 * @return 0 if addresses are equal, -1 otherwise.
 */
static inline int
sockaddr_cmp(const struct sockaddr *addr1, const struct sockaddr *addr2)
{
    if (addr1->sa_family != addr2->sa_family)
        return -1;

    if (addr1->sa_family == AF_INET)
    {
        if (SIN(addr1)->sin_addr.s_addr != SIN(addr2)->sin_addr.s_addr)
            return -1;

        if (SIN(addr1)->sin_port != SIN(addr2)->sin_port)
            return -1;
    }
    else if (addr1->sa_family == AF_INET6)
    {
        if (memcmp(&SIN6(addr1)->sin6_addr, &SIN6(addr2)->sin6_addr,
                   sizeof(struct in6_addr)) != 0)
        {
            return -1;
        }

        if (SIN6(addr1)->sin6_port != SIN6(addr2)->sin6_port)
            return -1;
    }
    else
    {
        return -1;
    }

    return 0;
}

/**
 * Compare two instances of @ref bpf_tuple type.
 *
 * @param t1    Tuple 1.
 * @param t2    Tuple 2.
 *
 * @return Status.
 * @retval 0    Tuples are equal.
 * @retval -1   Tuples are not equal.
 */
static inline int
bpf_tuple_cmp(const bpf_tuple *t1, const bpf_tuple *t2)
{
    if (t1->proto != t2->proto)
        return -1;

    if (sockaddr_cmp(SA(&t1->src_addr), SA(&t2->src_addr)) != 0)
        return -1;

    if (sockaddr_cmp(SA(&t1->dst_addr), SA(&t2->dst_addr)) != 0)
        return -1;

    return 0;
}

/**
 * Obtain a 5-tuple from a frame pointed by @p frame.
 *
 * @param[in]  frame  Pointer to the incoming frame, where @p frame->data_cur
 *                    field points to the start of IP header.
 * @param[out] t      Result tuple.
 *
 * @return 0, or -1 in case of error.
 */
static inline int
bpf_tuple_get_from_frame(const frame_ptrs *frame, bpf_tuple *t)
{
    __u8 ver = get_ip_version(frame);
    frame_ptrs tmp_frame = *frame;
    __u8 proto;

    if (ver == 4)
    {
        t->src_addr.ss_family = AF_INET;
        t->dst_addr.ss_family = AF_INET;

        SIN(&t->src_addr)->sin_addr.s_addr = ipv4_get_src_addr(frame);
        SIN(&t->dst_addr)->sin_addr.s_addr = ipv4_get_dst_addr(frame);

        proto = ipv4_get_next_proto(&tmp_frame);
        t->proto = proto;
        SIN(&t->src_addr)->sin_port = l4_get_src_port(&tmp_frame, proto);
        SIN(&t->dst_addr)->sin_port = l4_get_dst_port(&tmp_frame, proto);
    }
    else if (ver == 6)
    {
        struct sockaddr_in6 *tuple_addr_src = SIN6(&t->src_addr);
        struct sockaddr_in6 *tuple_addr_dst = SIN6(&t->dst_addr);
        struct in6_addr *packet_addr_src = ipv6_get_src_addr(frame);
        struct in6_addr *packet_addr_dst = ipv6_get_dst_addr(frame);

        tuple_addr_src->sin6_family = AF_INET6;
        tuple_addr_dst->sin6_family = AF_INET6;

        if (packet_addr_src == NULL || packet_addr_dst == NULL)
            return -1;

        memcpy(&tuple_addr_src->sin6_addr, packet_addr_src,
               sizeof(struct in6_addr));
        memcpy(&tuple_addr_dst->sin6_addr, packet_addr_dst,
               sizeof(struct in6_addr));

        proto = ipv6_get_next_proto(&tmp_frame);
        t->proto = proto;
        tuple_addr_src->sin6_port = l4_get_src_port(&tmp_frame, proto);
        tuple_addr_dst->sin6_port = l4_get_dst_port(&tmp_frame, proto);
    }
    else
    {
        return -1;
    }

    return 0;
}

/**
 * Compare user-defined rule with current connection 5-tuple
 * obtained from incoming frame.
 *
 * @param frame     Pointer to the incoming frame, where @p frame->data_cur
 *                  field points to the start of IP header.
 * @param rule_map  @c BPF_MAP_TYPE_ARRAY map, containing 5-tuple rule
 *                  (@ref bpf_tuple type) in the zero key.
 *
 * @return Result code.
 */
static inline frame_tuple_cmp_rc
frame_tuple_cmp(const frame_ptrs *frame, struct bpf_map *rule_map)
{
    bpf_tuple curr_conn_tuple;
    bpf_tuple *rule = NULL;
    __u32  key = 0;

    if ((rule = bpf_map_lookup_elem(rule_map, &key)) == NULL)
        return TUPLE_PARSE_ERR;

    if (bpf_tuple_get_from_frame(frame, &curr_conn_tuple) != 0)
        return TUPLE_PARSE_ERR;

    if (bpf_tuple_cmp(rule, &curr_conn_tuple) != 0)
        return TUPLE_IS_NOT_EQUAL;

    return TUPLE_IS_EQUAL;
}

#endif /* !__BPF_PROGRAMS_BPF_H__ */
