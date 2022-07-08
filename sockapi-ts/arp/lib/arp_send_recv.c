/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief ARP Test Suite
 *
 * ARP test suite library
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 *
 * $Id$
 */

#include "te_config.h"

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#include <stdio.h>
#include <assert.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

/** User name of ARP send/receive library */
#define TE_LGR_USER     "ARP sender"
#include "logger_api.h"

#include "te_defs.h"
#include "te_stdint.h"
#include "te_errno.h"
#include "rcf_api.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_arp.h"
#include "tapi_sockaddr.h"
#include "tapi_sockaddr.h"
#include "tapi_ip4.h"

#include "sockapi-ts.h"
#include "sockapi-ts_env.h"

#include "arp_send_recv.h"
#include "arp_test_macros.h"
#include "icmp_send.h"

/** Macro to create session */
#define CREATE_SESSION(ta_, dev_, sid_, rc_) \
    do                                                      \
    {                                                       \
        rc_ = rcf_ta_create_session(ta_, sid_);             \
        if (rc_)                                            \
        {                                                   \
            ERROR("%s() failed to create new session",      \
                  __FUNCTION__);                            \
            break;                                          \
        }                                                   \
     } while (0)

/** Macro to create ARP csap */
#define CREATE_ARP_CSAP(ta_, dev_, sid_, receive_mode_, csap_, rc_) \
    do {                                                            \
        rc_ = tapi_arp_eth_csap_create_ip4(ta_, sid_, dev_,         \
                                           receive_mode_,           \
                                           NULL, NULL, csap_);      \
        if (rc_ != 0)                                               \
        {                                                           \
            ERROR("%s() failed to create ethernet csap, "           \
                  "error %X", __FUNCTION__, rc_);                   \
            break;                                                  \
        }                                                           \
    } while (0)

/** UDP port to be used for sending/receiving UDP packets */
#define ARP_SEND_RECV_SRC_PORT 1706

uint8_t mac_broadcast[ETHER_ADDR_LEN] = 
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* See description in arp_send_recv.h */
int
get_mapping(const uint8_t *proto_addr, uint8_t **hw_addr,
            int map_list_len, proto2hw_addr_map *map_list)
{
    int                i;
    proto2hw_addr_map *current = map_list;
    
    for (i = 0; i < map_list_len; i++, current++)
    {
        if (memcmp(proto_addr, current->proto_addr, 4 /* FIXME */) == 0)
        {
            *hw_addr = current->hw_addr;
            break;
        }
    }
    if (i == map_list_len)
    {
        ERROR("%s(): couldn't find address in mapping list",
              __FUNCTION__);
        return 1;
    }
    return 0;
}

/* See description in arp_send_recv.h */
proto2hw_addr_map *
generate_map_list(tapi_env_net *net, int *num, te_bool macs_only)
{
    proto2hw_addr_map *map_list;
    proto2hw_addr_map *curr;
    int                addr_num;
    struct sockaddr   *new_addr;
    int                i;

    int rc;

    if (*num <= 0)
    {
        WARN("%s: Cannot generate fake addresses", __FUNCTION__);
        return NULL;
    }

    if ((map_list = (proto2hw_addr_map *)
                        calloc(*num, sizeof(proto2hw_addr_map))) == NULL)
    {
        ERROR("%s() cannot allocate memory for fake addresses",
              __FUNCTION__);
        return NULL;
    }
    
    curr = map_list;
    for (addr_num = 0; addr_num < *num; addr_num++, curr++)
    {
        if (!macs_only)
        {
            rc = tapi_env_allocate_addr(net, AF_INET, &new_addr, NULL);
            if (rc)
            {
                WARN("%s: tapi_env_allocate_address() failed, error %r", 
                      __FUNCTION__, rc);
                break;
            }
            curr->proto_addr = (uint8_t *)te_sockaddr_get_netaddr(new_addr);
            {
                struct in_addr in;
                in.s_addr = *(uint32_t *)(curr->proto_addr);
                INFO("Generated address is %s", 
                     inet_ntoa(in));
            }     
        }
        /* Generate fake MAC address */
        curr->hw_addr[0] = 0x00;
        curr->hw_addr[1] = 0x0A;
        for (i = 2; i < ETHER_ADDR_LEN; i++)
            curr->hw_addr[i] = random();
    }
    *num = addr_num;
    return map_list;
}

/* See description in arp_send_recv.h */
int 
arp_sender(const char *ta_name, const char *device, 
           const uint8_t *eth_src, const uint8_t *eth_dst,
           uint16_t opcode, 
           const uint8_t *snd_proto, const uint8_t *snd_hw,
           const uint8_t *tgt_proto, const uint8_t *tgt_hw,
           int nums, proto2hw_addr_map *map_list)
{
    int rc;
    int i;
    
    int           sid;
    csap_handle_t arp_csap;
    
    tapi_arp_frame_t   frame;
    asn_value         *templ;
    proto2hw_addr_map *current = map_list;
    uint8_t            request_tgt_hw[ETHER_ADDR_LEN] = {0,};

    if (snd_proto == NULL && tgt_proto == NULL)
        WARN("ARP sender got both NULL snd and tgt addresses, strange");

    if (nums <= 0)
    {
        WARN("Number of ARP requests/replies should be sent is zero");
        return 0;
    }

    CREATE_SESSION(ta_name, device, &sid, rc);
    /* Do not enable PROMISC mode for sending CSAP */
    CREATE_ARP_CSAP(ta_name, device, sid,
                    (TAD_ETH_RECV_DEF & ~TAD_ETH_RECV_OTHER) |
                    TAD_ETH_RECV_NO_PROMISC,
                    &arp_csap, rc);

    if (eth_dst == NULL && opcode == ARPOP_REQUEST)
    {
        eth_dst = mac_broadcast;
        tgt_hw = request_tgt_hw; 
    }
    if (tgt_hw == NULL && opcode == ARPOP_REQUEST)
        tgt_hw = request_tgt_hw;

/* Doxygen generates warning here. There is no any good way to avoid it. */
#ifndef DOXYGEN_TEST_SPEC
/** Macro to get address used in ARP packet */ 
#define GET_ADDR_TO_USE(addr_, addr_to_use_) \
        (addr_) ? (addr_) : (addr_to_use_)
#endif

    if ((eth_src == NULL || eth_dst == NULL || 
         snd_hw == NULL || snd_proto == NULL ||
         tgt_hw == NULL || tgt_proto == NULL) &&
         current == NULL)
    {
        ERROR("%s: Wrong parameters passed to function");
        (void)tapi_tad_csap_destroy(ta_name, sid, arp_csap);
        return -1;
    }
    
    for (i = 0; i < nums; i++, current++)
    {
        TAPI_ARP_FILL_ETH_HDR(&frame, 
                              GET_ADDR_TO_USE(eth_src, current->hw_addr), 
                              GET_ADDR_TO_USE(eth_dst, current->hw_addr));
        TAPI_ARP_FILL_HDR(&frame, opcode, 
                          GET_ADDR_TO_USE(snd_hw, current->hw_addr), 
                          GET_ADDR_TO_USE(snd_proto, current->proto_addr),
                          GET_ADDR_TO_USE(tgt_hw, current->hw_addr),
                          GET_ADDR_TO_USE(tgt_proto, current->proto_addr));

        rc = tapi_arp_prepare_template(&frame, &templ);
        if (rc != 0)
        {
            ERROR("%s(): tapi_arp_prepare_template() failed, error %r",
                  __FUNCTION__, rc);
            (void)tapi_tad_csap_destroy(ta_name, sid, arp_csap);
            return rc;
        }
        rc = tapi_tad_trsend_start(ta_name, sid, arp_csap, templ,
                                   RCF_MODE_BLOCKING);
        if (rc != 0)
        {
            ERROR("%s(): tapi_tad_trsend_start() failed, error %r", 
                  __FUNCTION__, rc);
            (void)tapi_tad_csap_destroy(ta_name, sid, arp_csap);
            return rc;    
        }
    }
#undef GET_ADDR_TO_USE

    return tapi_tad_csap_destroy(ta_name, sid, arp_csap);
}

/* See decription in arp_send_recv.h */
te_errno
arp_filter_with_hdr(const char *ta_name, const char *device,
                    const uint8_t *eth_src_mac,
                    const uint8_t *eth_dst_mac,
                    uint16_t opcode,
                    unsigned int receive_mode,
                    const uint8_t *snd_proto_addr,
                    const uint8_t *snd_hw_addr,
                    const uint8_t *tgt_proto_addr,
                    const uint8_t *tgt_hw_addr,
                    int num,
                    csap_handle_t *handle)
{
    te_errno       rc;
    csap_handle_t  arp_csap;
    asn_value     *pattern = NULL;

    rc = tapi_arp_eth_csap_create_ip4(ta_name, 0, device,
                                      receive_mode,
                                      NULL, NULL, &arp_csap);
    if (rc != 0)
    {
        ERROR("%s(): Cannot create ARP csap, error %r", __FUNCTION__, rc);
        return rc;
    }

    rc = tapi_arp_add_pdu_eth_ip4(&pattern, TRUE, &opcode, 
                                  snd_hw_addr, snd_proto_addr,
                                  tgt_hw_addr, tgt_proto_addr);
    if (rc != 0)
    {
        ERROR("%s(): Cannot prepare ARP PDU pattern, error %r",
              __FUNCTION__, rc);
        asn_free_value(pattern);
        (void)tapi_tad_csap_destroy(ta_name, 0, arp_csap);
        return rc;
    }
    rc = tapi_eth_add_pdu(&pattern, NULL, TRUE, eth_dst_mac, eth_src_mac, NULL,
                          TE_BOOL3_ANY /* tagged/untagged */,
                          TE_BOOL3_ANY /* Ethernet2/LLC */);
    if (rc != 0)
    {
        ERROR("%s(): Cannot prepare Ethernet PDU pattern, error %r",
              __FUNCTION__, rc);
        asn_free_value(pattern);
        (void)tapi_tad_csap_destroy(ta_name, 0, arp_csap);
        return rc;
    }

    rc = tapi_tad_trrecv_start(ta_name, 0, arp_csap, pattern,
                               TAD_TIMEOUT_INF, num, RCF_TRRECV_PACKETS);
    asn_free_value(pattern);
    if (rc != 0)
    {
        ERROR("%s(): Cannot start arp receiver, error %r", __FUNCTION__, rc);
        (void)tapi_tad_csap_destroy(ta_name, 0, arp_csap);
        return rc;
    }

    *handle = arp_csap;

    return 0;
}

static int
prepare_eth_pattern(const uint8_t *src_mac, const uint8_t *dst_mac,
                    uint16_t eth_type, asn_value **pattern)
{
    asn_value            *frame_hdr;
    ndn_eth_header_plain  eth_hdr;
    int                   syms;
    int                   rc;

    if (pattern == NULL)
        return TE_EINVAL;

    memset(&eth_hdr, 0, sizeof(eth_hdr));

    if (src_mac != NULL)
        memcpy(eth_hdr.src_addr, src_mac, sizeof(eth_hdr.src_addr));
    if (dst_mac != NULL)
        memcpy(eth_hdr.dst_addr, dst_mac, sizeof(eth_hdr.dst_addr));

    eth_hdr.len_type = eth_type;

    frame_hdr = ndn_eth_plain_to_packet(&eth_hdr);
    if (frame_hdr == NULL)
        return TE_ENOMEM;

    if (src_mac == NULL)
    {
        rc = asn_free_subvalue(frame_hdr, "src-addr");
        if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_EASNINCOMPLVAL)
            WARN("asn_free_subvalue returns %r", rc);
    }
    
    if (dst_mac == NULL)
    {
        rc = asn_free_subvalue(frame_hdr, "dst-addr");
        if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_EASNINCOMPLVAL)
            WARN("asn_free_subvalue returns %r", rc);
    }

    rc = asn_parse_value_text("{{ pdus { eth:{ }}}}",
                              ndn_traffic_pattern,
                              pattern, &syms);
    if (rc != 0)
    {
        ERROR("asn_parse_value_text fails %r\n", rc);
        return rc;
    }
    rc = asn_write_component_value(*pattern,
                                   frame_hdr, "0.pdus.0.#eth");
    if (rc != 0)
    {
        ERROR("asn_write_component_value fails %r\n", rc);
        return rc;
    }

    return 0;
}


/* See description in arp_send_recv.h */
int
eth_filter(const char *ta_name, const char *device,
           unsigned int      receive_mode,
           const uint8_t    *eth_src_mac,
           const uint8_t    *eth_dst_mac,
           uint16_t          eth_type,
           int               num, 
           csap_handle_t    *handle,
           int              *sid_param,
           rcf_trrecv_mode   trrecv_mode)
{
    int rc;
    
    asn_value     *pattern;
    csap_handle_t  eth_csap;
    int            sid;

    if (sid_param == NULL)
    {
        sid = 0;
    }
    else
    {
        rc = rcf_ta_create_session(ta_name, &sid);
        if (rc != 0)
        {
            ERROR("%s() failed to create new session", __FUNCTION__);
            return rc;
        }
    }
    
    rc = tapi_eth_csap_create(ta_name, sid, device,
                              receive_mode,
                              NULL, NULL,
                              &eth_type, &eth_csap);
    if (rc != 0)
    {
        ERROR("Ethernet csap creation failed, error %r", rc);
        return rc;
    }
    rc = prepare_eth_pattern(eth_src_mac, eth_dst_mac,
                             eth_type, &pattern);
    if (rc != 0)
    {
        ERROR("Preparation of Ethernet pattern failed, error %r", rc);
        (void)tapi_tad_csap_destroy(ta_name, sid, eth_csap);
        return rc; 
    }
    rc = tapi_tad_trrecv_start(ta_name, sid, eth_csap, pattern,
                               TAD_TIMEOUT_INF, num, trrecv_mode);
    if (rc != 0)
    {
        ERROR("Receiving on Ethernet csap failed, error %r", rc);
        (void)tapi_tad_csap_destroy(ta_name, sid, eth_csap);
        return rc;
    }                         
    *handle = eth_csap;
    if (sid_param != NULL)
        *sid_param = sid;
    return 0;
}

/* See description in arp_send_recv.h */
void *
launch_dgram_receiver(void *args)
{
    struct dgram_receiver_args *dgram_receiver_args =
        (struct dgram_receiver_args *)args;

    long int rc;
    int      sid;

    const char     *ta_name = dgram_receiver_args->ta_name;
    const char     *device  = dgram_receiver_args->device;
    const uint8_t  *src_hw  = dgram_receiver_args->src_hw;
    const uint8_t  *src_proto = dgram_receiver_args->src_proto;

    CREATE_SESSION(ta_name, device, &sid, rc);
    if (rc != 0)
        return (void *)rc;
    
    rc = tapi_ip4_eth_csap_create(ta_name, sid, device,
                                  TAD_ETH_RECV_DEF, NULL, 
                                  src_hw, htonl(INADDR_ANY),
                                  *(in_addr_t *)src_proto, 
                                  IPPROTO_UDP,
                                  dgram_receiver_args->csap);
    if (rc != 0)
    {
        ERROR("%s(): tapi_ip4_eth_csap_create() failed, "
              "error %r", __FUNCTION__, rc);
        return (void *)rc;
    }
    rc = tapi_tad_trrecv_start(ta_name, sid, *dgram_receiver_args->csap,
                               NULL, TAD_TIMEOUT_INF, 0, RCF_TRRECV_COUNT);
    if (rc != 0)
    {
        ERROR("%s(): tapi_tad_trrecv_start() failed, "
              "error %r", __FUNCTION__, rc);
        return (void *)rc;
    }
 
    /* Wait process */
    rc = rcf_ta_trrecv_wait(ta_name, sid, *dgram_receiver_args->csap, 
                            NULL, NULL,
                            (unsigned int *)
                            dgram_receiver_args->dgrams_received);
    if (TE_RC_GET_ERROR(rc) != TE_EINTR)
    {
         ERROR("%s() failed to waiting process "
               "on Ethernet csap, error %r", __FUNCTION__, rc);
         return (void *)rc;
    }
    
    return (void *)0;
}

/**
 * Structure to contain arguments for arp_responder_cb()
 */ 
struct arp_responder_cb_args {
    csap_handle_t      csap;           /**< Csap Id */
    const char        *ta_name;        /**< Test agent name */
    int                session_id;     /**< Session Id */
    int                map_list_len;   /**< Mapping list size */
    proto2hw_addr_map *map_list;       /**< Mapping list */
};    

/**
 * Callback for arp responder, send ARP reply
 */ 
static void
arp_responder_cb(const tapi_arp_frame_t *header, void *userdata)
{
    struct arp_responder_cb_args *args =
         (struct arp_responder_cb_args *)userdata;
    
    csap_handle_t      arp_reply_csap = args->csap;
    const char        *ta_name        = args->ta_name; 
    const int          session_id     = args->session_id;
    int                map_list_len   = args->map_list_len;
    proto2hw_addr_map *map_list       = args->map_list;
    
    const uint8_t     *eth_src;
    const uint8_t     *eth_dst;
    const uint8_t     *tgt_proto_addr;
    const uint8_t     *tgt_hw_addr;
    const uint8_t     *snd_proto_addr;
    uint8_t           *snd_hw_addr;

    tapi_arp_frame_t   arp_frame;
    asn_value         *templ;

    int rc;

    INFO("ARP responder got an ARP request");

    eth_dst        = header->arp_hdr.snd_hw_addr;
    tgt_proto_addr = header->arp_hdr.snd_proto_addr;
    tgt_hw_addr    = header->arp_hdr.snd_hw_addr;
    snd_proto_addr = header->arp_hdr.tgt_proto_addr;

    /* Take sender HW address from mapping_list */
    rc = get_mapping(snd_proto_addr, &snd_hw_addr, 
                     map_list_len, map_list);
    if (rc != 0)
    {
        struct in_addr snd_addr;
        struct in_addr tgt_addr;
        snd_addr.s_addr = *(in_addr_t *)snd_proto_addr;
        tgt_addr.s_addr = *(in_addr_t *)tgt_proto_addr;
        WARN("%s() failed to get mapping for address %s, "
             "request was sent by %s, error %r",
              __FUNCTION__, inet_ntoa(snd_addr), 
              inet_ntoa(tgt_addr), rc);
        return;
    }
    /* After that fill eth_src */
    eth_src = snd_hw_addr;

    TAPI_ARP_FILL_ETH_HDR(&arp_frame, eth_src, eth_dst);
    TAPI_ARP_FILL_HDR(&arp_frame, ARPOP_REPLY, snd_hw_addr, snd_proto_addr,
                     tgt_hw_addr, tgt_proto_addr);
    rc = tapi_arp_prepare_template(&arp_frame, &templ);
    if (rc != 0)
    {
        ERROR("%s() failed to prepare template, error %r", 
              __FUNCTION__, rc);
        return;
    }
    rc = tapi_tad_trsend_start(ta_name, session_id, arp_reply_csap, templ,
                               RCF_MODE_BLOCKING);
    if (rc != 0)
    {
        ERROR("%s() failed to send arp reply, error %r", __FUNCTION__, rc);
        return;
    }
    return;
}

/* See description in arp_send_recv.h */
void *
launch_arp_responder(void * args)
{
    struct arp_responder_args *arp_responder_args = 
        (struct arp_responder_args *)args;
    const char        *ta_name        = arp_responder_args->ta_name;
    const char        *device         = arp_responder_args->device;
    const uint8_t     *eth_src        = arp_responder_args->eth_src;
    const uint8_t     *snd_proto_addr = arp_responder_args->snd_proto;
    const uint8_t     *snd_hw_addr    = arp_responder_args->snd_hw;
    int                map_list_len   = arp_responder_args->map_list_len;
    proto2hw_addr_map *map_list       = arp_responder_args->map_list;

    struct arp_responder_cb_args arp_responder_cb_args;

    csap_handle_t      arp_responder_csap;
    int                arp_responder_session_id;
    csap_handle_t      arp_responder_cb_csap;
    int                arp_responder_cb_session_id;
    asn_value         *pattern = NULL;
    uint16_t           opcode = ARPOP_REQUEST;
    unsigned int       number_of_arps;
    
    long int           rc;
    CREATE_SESSION(ta_name, device, &arp_responder_session_id, rc);
    if (rc != 0)
        return (void *)rc; 

    /* Do not use PROMISC mode for ARP Reply CSAP */
    CREATE_ARP_CSAP(ta_name, device, arp_responder_session_id,
                    (TAD_ETH_RECV_DEF & ~TAD_ETH_RECV_OTHER) |
                    TAD_ETH_RECV_NO_PROMISC,
                    &arp_responder_csap, rc);
    if (rc != 0)
        return (void *)rc;    
    /* 
     * Save CSAP in function args to stop waiting process and destroy 
     * from the test.
     */
    *(arp_responder_args->csap) = arp_responder_csap;
 
    CREATE_SESSION(ta_name, device, &arp_responder_cb_session_id, rc);
    if (rc != 0)
        return (void *)rc;
    
    /* Use PROMISC mode for receiving ARP requests */
    CREATE_ARP_CSAP(ta_name, device, arp_responder_cb_session_id,
                    TAD_ETH_RECV_DEF, &arp_responder_cb_csap, rc);
    if (rc != 0)
    {
        return (void *)rc; 
    }
    
    rc = tapi_arp_add_pdu_eth_ip4(&pattern, TRUE, &opcode, 
                                  snd_hw_addr, snd_proto_addr,
                                  NULL, NULL);
    if (rc != 0)
    {
        ERROR("%s(): Cannot prepare ARP PDU pattern, error %r",
              __FUNCTION__, rc);
        asn_free_value(pattern);
        (void)tapi_tad_csap_destroy(ta_name, arp_responder_cb_session_id,
                                  arp_responder_cb_csap);
        return (void *)rc; 
    }
    rc = tapi_eth_add_pdu(&pattern, NULL, TRUE, NULL, eth_src, NULL,
                          TE_BOOL3_ANY /* tagged/untagged */,
                          TE_BOOL3_ANY /* Ethernet2/LLC */);
    if (rc != 0)
    {
        ERROR("%s(): Cannot prepare Ethernet PDU pattern, error %r",
              __FUNCTION__, rc);
        asn_free_value(pattern);
        (void)tapi_tad_csap_destroy(ta_name, arp_responder_cb_session_id,
                                  arp_responder_cb_csap);
        return (void *)rc; 
    }

    /* Fill arguments for callback */
    arp_responder_cb_args.ta_name     = ta_name;
    arp_responder_cb_args.session_id  = arp_responder_cb_session_id;
    arp_responder_cb_args.csap        = arp_responder_cb_csap;
    arp_responder_cb_args.map_list_len = map_list_len;
    arp_responder_cb_args.map_list    = map_list;
    
    rc = tapi_tad_trrecv_start(ta_name, arp_responder_session_id,
                               arp_responder_csap, pattern, 
                               TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS);
    if (rc != 0)
    {
        ERROR("%s() failed to start receiving process "
              "on Ethernet csap, error %r", __FUNCTION__, rc);
        (void)tapi_tad_csap_destroy(ta_name, arp_responder_cb_session_id,
                                  arp_responder_cb_csap);
        return (void *)rc;
    }

    rc = tapi_tad_trrecv_wait(ta_name, arp_responder_session_id,
                              arp_responder_csap,
                              tapi_arp_trrecv_cb_data(arp_responder_cb,
                                  &arp_responder_cb_args),
                              &number_of_arps);
    if (TE_RC_GET_ERROR(rc) != TE_EINTR)
    {
        ERROR("%s() failed to waiting process "
               "on Ethernet csap, error %r", __FUNCTION__, rc);
        (void)tapi_tad_csap_destroy(ta_name, arp_responder_cb_session_id,
                                  arp_responder_cb_csap);
        return (void *)rc;
    }
    
    *(arp_responder_args->number_of_arps) = number_of_arps;

    rc = tapi_tad_csap_destroy(ta_name, arp_responder_cb_session_id,
                             arp_responder_cb_csap);
    if (rc != 0)
    {
        ERROR("%s() failed to destroy CSAP %u: %r", __FUNCTION__,
              arp_responder_cb_csap, rc);
        return (void *)rc;
    }

    return (void *)0;
}



/* Send UDP datagram with given parameters */
static int
send_dgrams(const char *ta_name, int sid, csap_handle_t csap_id,
            uint16_t src_port, uint16_t dst_port,
            const uint8_t *src_proto, const uint8_t *dst_proto,
            const uint8_t *src_hw, const uint8_t *dst_hw,
            int module, int *dgrams_sent)
{
    uint8_t            transp_proto_data[10] = {1,2,3,4,5,6,7,8,9,10};
    uint8_t            ip_data[1024];
    int                ip_data_len = sizeof(ip_data);
    uint8_t            eth_data[1024];
    int                eth_data_len = sizeof(eth_data);

    asn_value         *template;
    int                datagram_gen_num;
    int                datagram_sent_num = 0;

    int rc; 

    create_udp(src_port, dst_port,
               transp_proto_data, sizeof(transp_proto_data),
               ip_data, &ip_data_len);
    create_ip((uint8_t *)src_proto, (uint8_t *)dst_proto, IPPROTO_UDP,
              ip_data, ip_data_len, eth_data, &eth_data_len);
    /* Prepare ETH traffic template */
    if (test_prepare_template((uint8_t *)src_hw, (uint8_t *)dst_hw,
                              eth_data, eth_data_len, &template) != 0)
    {
        assert(0);
    }
    datagram_gen_num = random() % module;
    /* Send at least one datagram */
    if (datagram_gen_num == 0)
        datagram_gen_num++;
    while (datagram_gen_num--)
    {
        rc = tapi_tad_trsend_start(ta_name, sid, csap_id, template,
                                   RCF_MODE_BLOCKING);
        if (rc)
        {
            ERROR("%s() failed to send UDP datagram, error %r",
                  __FUNCTION__, rc);
            return rc;
        }
        datagram_sent_num++;
    }
    *dgrams_sent += datagram_sent_num;
    return 0;
}


/**
 * Structure to contain arguments for arp_reply_catcher_cb() 
 */
struct arp_reply_catcher_cb_args {
    const char   *ta_name;       /**< Test agent name */
    int           sid;           /**< Session Id */
    csap_handle_t csap;          /**< Csap Id */
    uint16_t      dst_port;      /**< Destionation port UDP 
                                      datagrams should be sent to */
    int           module;        /**< Maximum number of UDP datagrams
                                      should be sent for one ARP reply */
    int          *dgrams_sent;   /**< Total number of UDP datagrams sent */
};

/** Callback for arp_reply_catcher: for an ARP reply received
 * send UDP datagram towards sender address from that reply
 */
void
arp_reply_catcher_cb(const tapi_arp_frame_t *header, void *userdata)
{
    struct arp_reply_catcher_cb_args *args = 
        (struct arp_reply_catcher_cb_args *)userdata;
    
    const char    *ta_name     = args->ta_name;
    int            sid         = args->sid;
    csap_handle_t  csap_id     = args->csap;
    uint16_t       dst_port    = args->dst_port;
    int            module      = args->module;
    

    const uint8_t *src_hw;
    const uint8_t *dst_hw;
    const uint8_t *src_proto;
    const uint8_t *dst_proto;
    uint16_t       src_port = ARP_SEND_RECV_SRC_PORT;
    
    int rc;

    INFO("arp reply catcher got a frame");
    src_hw = header->arp_hdr.tgt_hw_addr;
    dst_hw = header->arp_hdr.snd_hw_addr;
    src_proto = header->arp_hdr.tgt_proto_addr;
    dst_proto = header->arp_hdr.snd_proto_addr;

    rc = send_dgrams(ta_name, sid, csap_id,
                     src_port, dst_port, src_proto, dst_proto,
                     src_hw, dst_hw, module, args->dgrams_sent);
    if (rc != 0)
    {
        ERROR("%s(): send_dgrams() failed, error %r", __FUNCTION__, rc);
        return;
    }    
    return;
}


/* See description in arp_send_recv.h */
void *
launch_arp_reply_catcher(void *args)
{
     struct arp_reply_catcher_args *arp_reply_catcher_args =
         (struct arp_reply_catcher_args *)args;

    const char        *ta_name         = arp_reply_catcher_args->ta_name;
    const char        *device          = arp_reply_catcher_args->device;
    const uint8_t     *eth_src         = arp_reply_catcher_args->eth_src;
    const uint8_t     *snd_proto_addr  = arp_reply_catcher_args->snd_proto;
    const uint8_t     *snd_hw_addr     = arp_reply_catcher_args->snd_hw;
    uint16_t           dst_port        = arp_reply_catcher_args->dst_port;
    int                module          = arp_reply_catcher_args->dgrams_num;
    sem_t             *sem             = arp_reply_catcher_args->sem;
    uint16_t           opcode          = ARPOP_REPLY;
    
    struct arp_reply_catcher_cb_args arp_reply_catcher_cb_args;

    csap_handle_t  arp_reply_catcher_csap;
    int            arp_reply_catcher_session_id;
    csap_handle_t  arp_reply_catcher_cb_csap;
    int            arp_reply_catcher_cb_session_id;
    asn_value     *pattern = NULL;
    unsigned int   arp_replies_received;
    int            dgrams_sent = 0;

    long int rc;

    INFO("Launch ARP reply catcher"); 

    CREATE_SESSION(ta_name, device, &arp_reply_catcher_session_id, rc);
    if (rc != 0)
        return (void *)rc;
    /*
     * Use PROMISC mode for receiving ARP replies, because they can have
     * random MAC addresses. E.g., these addresses can generated using the
     * macro @c GENERATE_MAP_LIST.
     */
    CREATE_ARP_CSAP(ta_name, device, arp_reply_catcher_session_id,
                    TAD_ETH_RECV_DEF, &arp_reply_catcher_csap, rc);
    if (rc != 0)
        return (void *)rc;

    CREATE_SESSION(ta_name, device, &arp_reply_catcher_cb_session_id, rc);
    if (rc != 0)
    {
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_session_id,
                                  arp_reply_catcher_csap);
        return (void *)rc;
    }
    rc = tapi_eth_csap_create(ta_name, arp_reply_catcher_cb_session_id,
                              device,
                              TAD_ETH_RECV_DEF |
                              TAD_ETH_RECV_NO_PROMISC,
                              NULL, NULL, NULL,
                              &arp_reply_catcher_cb_csap);
    if (rc != 0)
    {
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_session_id,
                                  arp_reply_catcher_csap);
        return (void *)rc;
    }

    rc = tapi_arp_add_pdu_eth_ip4(&pattern, TRUE, &opcode, 
                                  snd_hw_addr, snd_proto_addr,
                                  NULL, NULL);
    if (rc != 0)
    {
        ERROR("%s(): Cannot prepare ARP PDU pattern, error %r",
              __FUNCTION__, rc);
        asn_free_value(pattern);
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_cb_session_id,
                                  arp_reply_catcher_cb_csap);
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_session_id,
                                  arp_reply_catcher_csap);
        return (void *)rc; 
    }
    rc = tapi_eth_add_pdu(&pattern, NULL, TRUE, NULL, eth_src, NULL,
                          TE_BOOL3_ANY /* tagged/untagged */,
                          TE_BOOL3_ANY /* Ethernet2/LLC */);
    if (rc != 0)
    {
        ERROR("%s(): Cannot prepare Ethernet PDU pattern, error %r",
              __FUNCTION__, rc);
        asn_free_value(pattern);
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_cb_session_id,
                                  arp_reply_catcher_cb_csap);
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_session_id,
                                  arp_reply_catcher_csap);
        return (void *)rc; 
    }

    INFO("%s: before fill arguments", __FUNCTION__);
    /* Fill arguments for callback */
    arp_reply_catcher_cb_args.ta_name   = ta_name;
    arp_reply_catcher_cb_args.csap      = arp_reply_catcher_cb_csap;
    arp_reply_catcher_cb_args.sid       = arp_reply_catcher_cb_session_id;
    arp_reply_catcher_cb_args.dst_port  = dst_port;
    arp_reply_catcher_cb_args.module    = module;
    arp_reply_catcher_cb_args.dgrams_sent = &dgrams_sent;
    
    INFO("%s: Before recv start", __FUNCTION__);
    rc = tapi_tad_trrecv_start(ta_name, arp_reply_catcher_session_id,
                               arp_reply_catcher_csap, pattern,
                               TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS);
    if (rc != 0)
    {
        ERROR("%s() failed to start receiving process "
              "on ARP csap, error %r", __FUNCTION__, rc);
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_cb_session_id,
                                  arp_reply_catcher_cb_csap);
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_session_id,
                                  arp_reply_catcher_csap);
        if (sem_post(sem) != 0)
        {
            ERROR("%s(): sem_post() failed, errno %s",
                  __FUNCTION__, strerror(errno));
        }
        return (void *)rc;
    }

    rc = sem_post(sem);
    if (rc != 0)
    {
        ERROR("%s(): sem_post() failed, errno %s",
              __FUNCTION__, strerror(errno));
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_cb_session_id,
                                  arp_reply_catcher_cb_csap);
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_session_id,
                                  arp_reply_catcher_csap);
        return (void *)rc;
    }

    INFO("%s: Before wait", __FUNCTION__);
    /* Save csap in function args to stop infinite waiting process from test */
    *(arp_reply_catcher_args->csap) = arp_reply_catcher_csap;
    rc = tapi_tad_trrecv_wait(ta_name, arp_reply_catcher_session_id,
                              arp_reply_catcher_csap,
                              tapi_arp_trrecv_cb_data(arp_reply_catcher_cb,
                                  &arp_reply_catcher_cb_args),
                              &arp_replies_received);
    if (TE_RC_GET_ERROR(rc) != TE_EINTR)
    {
        ERROR("%s() failed to waiting process on ARP csap, error %r",
              __FUNCTION__, rc);
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_cb_session_id,
                                  arp_reply_catcher_cb_csap);
        (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_session_id,
                                  arp_reply_catcher_csap);
        return (void *)rc;
    }
    
    (void)tapi_tad_csap_destroy(ta_name, arp_reply_catcher_cb_session_id,
                              arp_reply_catcher_cb_csap);

    INFO("%s: after wait", __FUNCTION__);
    *(arp_reply_catcher_args->arp_replies_received) = arp_replies_received;
    *(arp_reply_catcher_args->dgrams_sent) = dgrams_sent;
    
    return (void *)0;
}

/* See description in arp_send_recv.h */
void *
launch_arp_sender(void *args)
{
    struct arp_sender_args *arp_sender_args = 
        (struct arp_sender_args *)args;
    const char     *ta_name      = arp_sender_args->ta_name;
    const char     *device       = arp_sender_args->device;
    const uint8_t  *eth_src      = arp_sender_args->eth_src;
    const uint8_t  *eth_dst      = arp_sender_args->eth_dst;
    uint16_t        opcode       = arp_sender_args->opcode;
    const uint8_t  *snd_proto    = arp_sender_args->snd_proto;
    const uint8_t  *snd_hw       = arp_sender_args->snd_hw;
    const uint8_t  *tgt_proto    = arp_sender_args->tgt_proto;
    const uint8_t  *tgt_hw       = arp_sender_args->tgt_hw;
    int             map_list_len = arp_sender_args->map_list_len;
    
    proto2hw_addr_map *map_list = arp_sender_args->map_list;

    long int rc;
    
    rc = arp_sender(ta_name, device, eth_src, eth_dst, opcode, 
                    snd_proto, snd_hw, tgt_proto, tgt_hw,
                    map_list_len, map_list);
    if (rc != 0)
    {
        ERROR("%s(): launch_arp_sender() failed, error %r", __FUNCTION__, rc);
        return (void *)rc;
    }
    return (void *)0;
}

/* See description in arp_send_recv.h */
void *
launch_dgram_sender(void *args)
{
    struct dgram_sender_args *dgram_sender_args =
        (struct dgram_sender_args *)args;     

    const char        *ta_name         = dgram_sender_args->ta_name;
    const char        *device          = dgram_sender_args->device;
    uint16_t           dst_port        = dgram_sender_args->dst_port;
    const uint8_t     *dst_proto       = dgram_sender_args->dst_proto;
    const uint8_t     *dst_hw          = dgram_sender_args->dst_hw;
    int                module          = dgram_sender_args->dgrams_num;
    int                map_list_len    = dgram_sender_args->map_list_len;
    proto2hw_addr_map *map_list        = dgram_sender_args->map_list;
    uint8_t           *src_proto;
    uint8_t           *src_hw;
    uint16_t           src_port = ARP_SEND_RECV_SRC_PORT;

    csap_handle_t      csap_id;
    int                sid;
    uint16_t           eth_type = ETHERTYPE_IP;

    proto2hw_addr_map *current;

    long int           rc;

    if (map_list == NULL)
    {
        ERROR("%s() got invalid NULL value for parameter map_list",
              __FUNCTION__);
        return (void *)TE_EWRONGPTR;
    }
    current = map_list;
    
    rc = rcf_ta_create_session(ta_name, &sid);
    if (rc != 0)
    {
        ERROR("%s() failed to create new session, error %r",
              __FUNCTION__, rc);
        return (void *)rc;
    }
    rc = tapi_eth_csap_create(ta_name, sid, device,
                              (TAD_ETH_RECV_DEF & ~TAD_ETH_RECV_OTHER) |
                              TAD_ETH_RECV_NO_PROMISC,
                              NULL, NULL,
                              &eth_type, &csap_id);
    if (rc != 0)
    {
        ERROR("%s() failed to create ethernet csap, error %r", 
              __FUNCTION__, rc);
        return (void *)rc;
    }
    while (map_list_len--)
    {   
        src_proto = current->proto_addr;
        src_hw = current->hw_addr;
        rc = send_dgrams(ta_name, sid, csap_id,
                         src_port, dst_port, 
                         src_proto, dst_proto,
                         src_hw, dst_hw,
                         module, dgram_sender_args->datagram_sent);
        current++;
    }
    rc = tapi_tad_csap_destroy(ta_name, sid,
                                  csap_id);
    return (void *)rc;
}

/**
 * Define common variables for testing TCP connection
 * establishment.
 */
#define TCP_COMMON_VARS \
    rcf_rpc_server   *rpcs_srv = NULL;              \
    rcf_rpc_server   *rpcs_clnt = NULL;             \
                                                    \
    int *s_listener = NULL;                         \
    int *s_clnt = NULL;                             \
    int *s_srv = NULL;                              \
                                                    \
    const struct sockaddr *srv_addr = NULL;         \
    const struct sockaddr *clnt_addr = NULL;        \
                                                    \
    UNUSED(s_srv);                                  \
    UNUSED(clnt_addr);                              \
                                                    \
    if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)        \
    {                                               \
        rpcs_srv = pco_tst;                         \
        rpcs_clnt = pco_iut;                        \
        srv_addr = tst_addr;                        \
        clnt_addr = iut_addr;                       \
                                                    \
        s_listener = tst_s_listener;                \
        s_srv = tst_s;                              \
        s_clnt = iut_s;                             \
    }                                               \
    else                                            \
    {                                               \
        rpcs_srv = pco_iut;                         \
        rpcs_clnt = pco_tst;                        \
        srv_addr = iut_addr;                        \
        clnt_addr = tst_addr;                       \
                                                    \
        s_listener = iut_s_listener;                \
        s_srv = iut_s;                              \
        s_clnt = tst_s;                             \
    }

/* See description in arp_send_recv.h */
int
sockts_connection_begin(rcf_rpc_server *pco_iut,
                        rcf_rpc_server *pco_tst,
                        const struct sockaddr *iut_addr,
                        const struct sockaddr *tst_addr,
                        sockts_socket_type sock_type,
                        int *iut_s,
                        int *iut_s_listener,
                        int *tst_s,
                        int *tst_s_listener,
                        te_dbuf *iut_sent)
{
    rpc_socket_domain   domain;
    int                 rc;

    domain = rpc_socket_domain_by_addr(iut_addr);

    te_dbuf_free(iut_sent);

    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)
    {
        char    buf[SOCKTS_MSG_DGRAM_MAX];
        size_t  send_len;

        *iut_s = rpc_socket(pco_iut, domain,
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        *tst_s = rpc_socket(pco_tst, domain,
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);

        rpc_bind(pco_iut, *iut_s, iut_addr);
        if (sock_type == SOCKTS_SOCK_UDP)
            rpc_connect(pco_iut, *iut_s, tst_addr);

        rpc_bind(pco_tst, *tst_s, tst_addr);
        rpc_connect(pco_tst, *tst_s, iut_addr);

        send_len = rand_range(1, SOCKTS_MSG_DGRAM_MAX);
        te_fill_buf(buf, send_len);

        if (sock_type == SOCKTS_SOCK_UDP)
            rc = rpc_send(pco_iut, *iut_s, buf, send_len, 0);
        else
            rc = rpc_sendto(pco_iut, *iut_s, buf, send_len, 0, tst_addr);

        if (rc != (int)send_len)
            TEST_FAIL("send() returned unexpected result on IUT");

        te_dbuf_append(iut_sent, buf, send_len);
    }
    else
    {
        TCP_COMMON_VARS;

        *s_listener = rpc_socket(rpcs_srv, domain,
                                 RPC_SOCK_STREAM,
                                 RPC_PROTO_DEF);
        rpc_bind(rpcs_srv, *s_listener, srv_addr);
        rpc_listen(rpcs_srv, *s_listener, SOCKTS_BACKLOG_DEF);

        *s_clnt = rpc_socket(rpcs_clnt, domain,
                             RPC_SOCK_STREAM,
                             RPC_PROTO_DEF);
        rpc_bind(rpcs_clnt, *s_clnt, clnt_addr);

        rpcs_clnt->op = RCF_RPC_CALL;
        rpc_connect(rpcs_clnt, *s_clnt, srv_addr);
    }

    return 0;
}

/* See description in arp_send_recv.h */
te_bool
sockts_connection_finished(rcf_rpc_server *pco_iut,
                           rcf_rpc_server *pco_tst,
                           sockts_socket_type sock_type,
                           int iut_s,
                           int iut_s_listener,
                           int tst_s,
                           int tst_s_listener)
{
    te_bool answer = FALSE;

    UNUSED(iut_s);

    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)
        RPC_GET_READABILITY(answer, pco_tst, tst_s, 0);
    else if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        RPC_GET_READABILITY(answer, pco_tst, tst_s_listener, 0);
    else
        RPC_GET_READABILITY(answer, pco_iut, iut_s_listener, 0);

    return answer;
}

/* See description in arp_send_recv.h */
int
sockts_connection_end(rcf_rpc_server *pco_iut,
                      rcf_rpc_server *pco_tst,
                      const struct sockaddr *iut_addr,
                      const struct sockaddr *tst_addr,
                      sockts_socket_type sock_type,
                      int *iut_s,
                      int *iut_s_listener,
                      int *tst_s,
                      int *tst_s_listener,
                      te_dbuf *iut_sent)
{
    int   rc;

    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)
    {
        char    buf[SOCKTS_MSG_DGRAM_MAX];

        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, *tst_s, buf, sizeof(buf), 0);

        if (rc < 0)
            TEST_VERDICT("recv() on Tester unexpectedly "
                         "failed with errno %r",
                         RPC_ERRNO(pco_tst));

        if (rc != (int)iut_sent->len ||
            memcmp(buf, iut_sent->ptr, iut_sent->len) != 0)
            TEST_VERDICT("Data received on Tester does not "
                         "match data sent");
    }
    else
    {
        TCP_COMMON_VARS;

        RPC_AWAIT_ERROR(rpcs_clnt);
        rc = rpc_connect(rpcs_clnt, *s_clnt, srv_addr);
        if (rc < 0)
            TEST_VERDICT("connect() failed with errno %r",
                         RPC_ERRNO(rpcs_clnt));

        RPC_AWAIT_ERROR(rpcs_srv);
        *s_srv = rpc_accept(rpcs_srv, *s_listener, NULL, NULL);
        if (*s_srv < 0)
            TEST_VERDICT("accept() failed with errno %r",
                         RPC_ERRNO(rpcs_srv));

        if (sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL)
            RPC_CLOSE(rpcs_srv, *s_listener);
    }

    return 0;
}

/* See description in arp_send_recv.h */
void
sockts_alloc_addr_without_arp_entry(tapi_env_net *net,
                                    rcf_rpc_server *rpcs,
                                    const char *if_name,
                                    struct sockaddr **addr)
{
    struct sockaddr *new_addr = NULL;
    struct sockaddr  link_addr;
    int              arp_flags = 0;
    te_bool          arp_entry_exist;

    UNUSED(arp_flags);

    do {
        CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &new_addr, NULL));

        TEST_GET_ARP_ENTRY(rpcs, new_addr, if_name,
                           &link_addr, arp_flags, arp_entry_exist);
        if (!arp_entry_exist)
            break;

        free(new_addr);
        new_addr = NULL;
    } while (TRUE);

    *addr = new_addr;
}
