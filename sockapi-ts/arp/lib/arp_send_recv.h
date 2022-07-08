/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* @file
 * @brief ARP Test Suite
 *
 * ARP test suite library to send/receive ARP packets
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_ARP_SEND_RECV_H__
#define __TS_ARP_SEND_RECV_H__

#if HAVE_SEMAPHORE_H
#include <semaphore.h>
#endif
#if HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "tapi_arp.h"
#include "tapi_env.h"


#ifdef __cplusplus
extern "C" {
#endif

/** 
 * Structure representing mapping from protocol (IP) address
 * to hardware address
 */ 
typedef struct proto2hw_addr_map {
    uint8_t *proto_addr;                /**< Protocol address */
    uint8_t  hw_addr[ETHER_ADDR_LEN];   /**< Hardware address */
} proto2hw_addr_map;    

/**
 * Broadcast MAC address
 */ 
extern uint8_t mac_broadcast[ETHER_ADDR_LEN];

/**
 * Generate list of mappings from protocol (IP) address
 * to hardware one. 
 * Protocol addresses belong to a given network.
 * 
 * @param net         Net for which protocol addresses to be generated
 * @param num         Number of mappings to be generated (INT, OUT)
 * @param macs_only   Fill only MAC addresses, do not allocate IP
 *                    addresses
 *
 * @return generated list of mappings in success or NULL
 */ 
extern proto2hw_addr_map * generate_map_list(tapi_env_net *net, int *num,
                                             te_bool macs_only);

/**
 * Find hardware address by a protocol address in mapping list.
 *
 * @param proto_addr     protocol address
 * @param hw_addr        pointer to hardware address (OUT)
 * @param map_list_len   number of mappings in mapping list
 * @param map_list       mapping list
 *
 * @return Status code.
 */
extern int get_mapping(const uint8_t *proto_addr, uint8_t **hw_addr,
                       int map_list_len, proto2hw_addr_map *map_list);

/**
 * Generate and send nums ARP requests/replies with given 
 * protocol and hardware addresses.
 * If an address (protocol or hardware) passed to function is NULL, 
 * addresses from map_list is used (protocol or hardware).
 *
 * @param ta_name           test agent name
 * @param device            device name
 * @param eth_src           Ethernet source address
 * @param eth_dst           Ethernet destination address
 * @param opcode            ARPOP_REQUEST or ARPOP_REPLY
 * @param snd_proto_addr    sender protocol address, may be NULL
 * @param snd_hw_addr       sender hardware address, may be NULL
 * @param tgt_proto_addr    target protocol address, may be NULL
 * @param tgt_hw_addr       target hardware address, may be NULL
 * @param nums              number of ARP packets to be sent
 * @param map_list          list of mappings obtained by generate_map_list()
 *
 * @return zero on success, otherwise standard or common TE error code.
 */
extern int arp_sender(const char *ta_name, const char *device,
                      const uint8_t *eth_src, const uint8_t *eth_dst,
                      uint16_t opcode,
                      const uint8_t *snd_proto_addr,
                      const uint8_t *snd_hw_addr,
                      const uint8_t *tgt_proto_addr,
                      const uint8_t *tgt_hw_addr,
                      int nums, proto2hw_addr_map *map_list);

/**
 * Catch ARP packets with given Ethernet source and destination
 * MAC addresses, opcode, sender and target protocol and hardware addresses.
 * given source and destination mac addresses.
 *
 * @param ta_name            test agent name
 * @param device             device name
 * @param eth_src_mac        source MAC address
 * @param eth_dst_mac        destination MAC address
 * @param opcode             ARPOP_REQUEST or ARPOP_REPLY
 * @param receive_mode       Receive mode for CSAP
 * @param snd_proto_addr     Sender protocol address
 * @param snd_hw_addr        sender hardware address
 * @param tgt_proto_addr     target protocol address
 * @param tgt_hw_addr        target hardware address
 * @param num                number of packets to be caught
 * @param handle             csap handle (OUT)
 *
 * @return zero on success, otherwise standard or common TE error code.
 */
extern int arp_filter_with_hdr(const char *ta_name, const char *device,
                               const uint8_t *eth_src_mac,
                               const uint8_t *eth_dst_mac,
                               uint16_t opcode,
                               unsigned int receive_mode,
                               const uint8_t *snd_proto_addr,
                               const uint8_t *snd_hw_addr,
                               const uint8_t *tgt_proto_addr,
                               const uint8_t *tgt_hw_addr,
                               int num,
                               csap_handle_t *handle);

/**
 * Catch Ethernet frames with given ethernet type,
 * given source and destination mac addresses.
 *
 * @param ta_name            test agent name
 * @param device             device name
 * @param receive_mode       Receive mode for Ethernet CSAP on the Interface
 * @param eth_src_mac        source MAC address
 * @param eth_dst_mac        destination MAC address
 * @param eth_type           ethernet type
 * @param num                number of frames to be caught
 * @param handle             csap handle (OUT)
 * @param sid                RCF session id (OUT)
 * @param trrecv_mode        RCF traffic receive mode
 *
 * @return zero on success, otherwise standard or common TE error code.
 */
extern int eth_filter(const char *ta_name, const char *device,
                      unsigned int   receive_mode,
                      const uint8_t *eth_src_mac,
                      const uint8_t *eth_dst_mac,
                      uint16_t eth_type,
                      int num,
                      csap_handle_t *handle, 
                      int *sid,
                      rcf_trrecv_mode trrecv_mode);

/**
 * Structure to contain argument for launch_arp_responder()
 */ 
struct arp_responder_args {
    const char        *ta_name;          /**< test agent name */
    const char        *device;           /**< device */
    csap_handle_t     *csap;             /**< csap handle (OUT) */
    const uint8_t     *eth_src;          /**< Ethernet source address */
    const uint8_t     *snd_proto;        /**< Sender protocol address */
    const uint8_t     *snd_hw;           /**< Sender HW address */
    int                map_list_len;     /**< number of addresses 
                                             in clients address list */
    proto2hw_addr_map *map_list;         /**< Mapping list of protocol 
                                             addresses to HW addresses
                                             used as sender addresses
                                             in ARP replies */
    int               *number_of_arps;   /**< Number of ARP requests
                                              caught by csap (OUT) */   
};    

/**
 * Macro to fill arp responder arguments
 */ 
#define FILL_ARP_RESPONDER_ARGS(args_,                       \
                                ta_, dev_, csap_, eth_src_,  \
                                snd_proto_, snd_hw_, len_,   \
                                list_, num_)                 \
    do {                                                     \
        (args_)->ta_name = (ta_);                            \
        (args_)->device = (dev_);                            \
        (args_)->csap = (csap_);                             \
        (args_)->eth_src = (eth_src_);                       \
        (args_)->snd_proto = (snd_proto_);                   \
        (args_)->snd_hw = (snd_hw_);                         \
        (args_)->map_list_len = (len_);                      \
        (args_)->map_list = (list_);                         \
        (args_)->number_of_arps = (num_);                    \
    } while (0)    

/**
 * Receive ARP requests and send ARP replies for them according
 * to list of mappings (protocol address -> HW address), which is
 * a parameter to the function.
 * Called as start routine in pthread_create().
 */ 
extern void *launch_arp_responder(void *arp_responder_args);

/**
 * Structure to contain arguments for launch_dgram_sender()
 */ 
struct dgram_sender_args {
    const char        *ta_name;         /**< test agent name */
    const char        *device;          /**< device */
    uint16_t           dst_port;        /**< destination port */
    const uint8_t     *dst_proto;       /**< destination protocol address */
    const uint8_t     *dst_hw;          /**< destination HW address */
    int                dgrams_num;      /**< maximum number of datagrams
                                             which should be sent from 
                                             one client */
    int                map_list_len;    /**< number of addresses 
                                             in clients address list */
    proto2hw_addr_map *map_list;        /**< clients address list */
    int               *datagram_sent;   /**< number of sent datagrams (OUT) */
};    

/**
 * Macro to fill dgram sender arguments
 */ 
#define FILL_DGRAM_SENDER_ARGS(args_,                        \
                                ta_, dev_, dst_port_,        \
                                dst_proto_, dst_hw_,         \
                                dgrams_num_, len_,           \
                                list_, num_)                 \
    do {                                                     \
        (args_)->ta_name = (ta_);                            \
        (args_)->device = (dev_);                            \
        (args_)->dst_port = (dst_port_);                     \
        (args_)->dst_proto = (dst_proto_);                   \
        (args_)->dst_hw = (dst_hw_);                         \
        (args_)->dgrams_num = (dgrams_num_);                 \
        (args_)->map_list_len = (len_);                      \
        (args_)->map_list = (list_);                         \
        (args_)->datagram_sent = (num_);                     \
    } while (0)    


/**
 * Send UDP datagrams, using as source addresses addresses from 
 * the list of clients addresses, which is a parameter to the function.
 * Called as start routine in pthread_create().
 */ 
extern void *launch_dgram_sender(void *dgram_sender_args);

/**
 * Structure to contain arguments for launch_dgram_receiver()
 */ 
struct dgram_receiver_args {
    const char        *ta_name;         /**< test agent name */
    const char        *device;          /**< device */
    const uint8_t     *src_hw;          /**< source hw address */
    const uint8_t     *src_proto;       /**< source protocol address */
    csap_handle_t     *csap;            /**< csap handle (OUT) */
    int               *dgrams_received; /**< number of received datagrams */
};

/**
 * Macro to fill dgram receiver arguments
 */ 
#define FILL_DGRAM_RECEIVER_ARGS(args_,                      \
                                ta_, dev_, csap_, src_hw_,   \
                                src_proto_, num_)            \
    do {                                                     \
        (args_)->ta_name = (ta_);                            \
        (args_)->device = (dev_);                            \
        (args_)->csap = (csap_);                             \
        (args_)->src_hw = (src_hw_);                         \
        (args_)->src_proto = (src_proto_);                   \
        (args_)->dgrams_received = (num_);                    \
    } while (0)    

/**
 * Receive UDP datagrams by their source hardware
 * and source protocol addresses.
 * Called as start routine in pthread_create().
 */ 
extern void *launch_dgram_receiver(void *args);

/**
 * Structure to contain arguments for launch_arp_reply_catcher()
 */ 
struct arp_reply_catcher_args {
    const char        *ta_name;        /**< test agent name */
    const char        *device;         /**< device */
    csap_handle_t     *csap;           /**< csap handle (OUT) */
    const uint8_t     *eth_src;        /**< source ethernet address */
    const uint8_t     *snd_proto;      /**< source protocol address */
    const uint8_t     *snd_hw;         /**< source hw address */
    uint16_t           dst_port;       /**< destination port */
    int                dgrams_num;     /**< maximum number of datagrams 
                                            which should be sent for one
                                            reply */
    sem_t             *sem;            /**< POSIX semaphor to interoperate
                                            with ARP request sender */
    int               *arp_replies_received;
                                       /**< number of arp replies 
                                            received (OUT) */
    int               *dgrams_sent;    /**< total number of sent 
                                            datagrams (OUT) */
};

/**
 * Macro to fill arp reply catcher arguments
 */ 
#define FILL_ARP_REPLY_CATCHER_ARGS(args_,                   \
                                ta_, dev_, csap_, eth_src_,  \
                                snd_proto_, snd_hw_,         \
                                dst_port_, dgrams_num_,      \
                                sem_,                        \
                                arp_replies_received_,       \
                                dgrams_sent_)                \
    do {                                                     \
        (args_)->ta_name = (ta_);                            \
        (args_)->device = (dev_);                            \
        (args_)->csap = (csap_);                             \
        (args_)->eth_src = (eth_src_);                       \
        (args_)->snd_proto = (snd_proto_);                   \
        (args_)->snd_hw = (snd_hw_);                         \
        (args_)->dst_port = (dst_port_);                     \
        (args_)->dgrams_num = (dgrams_num_);                 \
        (args_)->sem = (sem_);                               \
        (args_)->arp_replies_received =                      \
            (arp_replies_received_);                         \
        (args_)->dgrams_sent = (dgrams_sent_);               \
    } while (0)    


/**
 * Catch ARP replies and send UDP datagrams forwards
 * sender proto address and sender HW address from reply.
 * Called as start routine in pthread_create().
 */ 
extern void *launch_arp_reply_catcher(void *arp_reply_catcher_args);

/**
 * Structure to contain arguments for launch_arp_sender()
 */ 
struct arp_sender_args {
    const char        *ta_name;         /**< test agent name */
    const char        *device;          /**< device */
    const uint8_t     *eth_src;         /**< Ethernet source address */
    const uint8_t           *eth_dst;         /**< Ethernet destination address */
    uint16_t           opcode;          /**< ARPOP_REQUEST or ARPOP_REPLY */
    const uint8_t     *snd_proto;       /**< sender protocol address */
    const uint8_t     *snd_hw;          /**< sender hw address */
    const uint8_t     *tgt_proto;       /**< target protocol address */
    const uint8_t     *tgt_hw;          /**< target hw address */
    int                map_list_len;    /**< number of elements in map_list */
    proto2hw_addr_map *map_list;        /**< Mapping list of protocol 
                                             addresses to HW addresses
                                             used as sender addresses
                                             in ARP requests */
};

/**
 * Fill arguments for launch_arp_sender().
 */ 
#define FILL_ARP_SENDER_ARGS(args_, \
                             ta_, dev_,                   \
                             eth_src_, eth_dst_,          \
                             opcode_,                     \
                             snd_proto_, snd_hw_,         \
                             tgt_proto_, tgt_hw_,         \
                             len_, list_);                \
    do {                                                  \
        (args_)->ta_name = (ta_);                         \
        (args_)->device = (dev_);                         \
        (args_)->eth_src = (eth_src_);                    \
        (args_)->eth_dst = (eth_dst_);                    \
        (args_)->snd_proto = (snd_proto_);                \
        (args_)->snd_hw = (snd_hw_);                      \
        (args_)->tgt_proto = (tgt_proto_);                \
        (args_)->tgt_hw = (tgt_hw_);                      \
        (args_)->opcode = (opcode_);                      \
        (args_)->map_list_len = (len_);                   \
        (args_)->map_list = (list_);                      \
    } while (0)

/**
 * Send ARP requests/replies according to given aruments.
 * Called as start routine in pthread_create().
 */ 
extern void *launch_arp_sender(void *args);

/** Convert protocol address to be used in tapi_arp */
#define CVT_PROTO_ADDR(addr_) \
    (const uint8_t *)&(SIN(addr_)->sin_addr.s_addr)

/**
 * Macro around generate_map_list()
 *
 * @param net_         Net for which protocol addresses to be generated
 * @param num_         Number of mappings to be generated (INT, OUT)
 * @param list_        Where to save pointer to generated list
 * @param exact_num_   If TRUE, fail the testing if the function
 *                     was unable to generate requested number of items
 *                     in the list.
 * @param macs_only_   Fill only MAC addresses, do not allocate IP
 *                     addresses
 */ 
#define GENERATE_MAP_LIST(net_, num_, list_, exact_num_, macs_only_) \
    do {                                                      \
        int saved_num_ = num_;                                \
        if ((list_= generate_map_list(net_,                   \
                                      &num_,                  \
                                      macs_only_)) == NULL)   \
        {                                                     \
            TEST_FAIL("Cannot generate fake address list");   \
        }                                                     \
        if (exact_num_ && num_ != saved_num_)                 \
        {                                                     \
            TEST_FAIL("Failed to generate requested number "  \
                      "of items in address list");            \
        }                                                     \
    } while (0)

/**
 * Macro around arp_sender
 */ 
#define START_ARP_SENDER(ta_, dev_, eth_src_, eth_dst_,       \
                         op_, snd_proto_, snd_hw_,            \
                         tgt_proto_, tgt_hw_, nums_, list_)   \
    do {                                                      \
        if (arp_sender(ta_, dev_, eth_src_, eth_dst_,         \
                       op_, snd_proto_, snd_hw_,              \
                       tgt_proto_, tgt_hw_,                   \
                       nums_, list_) != 0)                    \
        {                                                     \
            TEST_FAIL("Cannot start arp sender");             \
        }                                                     \
    } while (0)


/**
 * Macro around arp_filter_with_hdr()
 */
#define START_ARP_FILTER_WITH_HDR(ta_, dev_, eth_src_, eth_dst_,        \
                                  op_, recv_mode_, snd_proto_, snd_hw_, \
                                  tgt_proto_, tgt_hw_, num_, handle_)   \
    do {                                                                \
        if (arp_filter_with_hdr(ta_, dev_, eth_src_, eth_dst_,          \
                                op_, recv_mode_, snd_proto_, snd_hw_,   \
                                tgt_proto_, tgt_hw_, num_,              \
                                &handle_) != 0)                         \
        {                                                               \
            TEST_FAIL("Cannot start ethernet filter");                  \
        }                                                               \
    } while (0)


/**
 * Macro around eth_filter()
 */
#define START_ETH_FILTER(ta_, dev_, recv_mode_, eth_src_, \
                         eth_dst_, type_, num_, handle_)  \
    do {                                                    \
        if (eth_filter(ta_, dev_,  recv_mode_, eth_src_,    \
                       eth_dst_, type_, num_, &handle_,     \
                       NULL, RCF_TRRECV_COUNT) != 0)        \
        {                                                   \
            TEST_FAIL("Cannot start ethernet sniffer");     \
        }                                                   \
    } while (0)


/**
 * Macro around rcf_ta_trrecv_stop()
 */
#define STOP_ETH_FILTER(ta_, handle_, received_) \
    do {                                                                  \
        int rc_;                                                          \
                                                                          \
        if ((rc_ = rcf_ta_trrecv_stop(ta_, 0, handle_, NULL, NULL,        \
                                      &received_)) != 0)                  \
        {                                                                 \
            TEST_FAIL("Cannot stop ethernet filter, error %X", rc_);      \
        }                                                                 \
        RING("Ethernet filter caught %d packets", received_);             \
        CHECK_RC(tapi_tad_csap_destroy(ta_, 0, handle_));                   \
        (handle_) = CSAP_INVALID_HANDLE;                                  \
    } while (0)

/**
 * First part of establishing/checking connection between two sockets.
 * Sockets are created, then in case of TCP nonblocking connect()
 * is called, and in case of UDP send() is called on IUT.
 *
 * @param pco_iut         RPC server on IUT.
 * @param pco_tst         RPC server on Tester.
 * @param iut_addr        Network address on IUT.
 * @param tst_addr        Network address on Tester.
 * @param sock_type       Socket type.
 * @param iut_s           Where to save IUT socket.
 * @param iut_s_listener  Where to save IUT listener socket.
 * @param tst_s           Where to save Tester socket.
 * @param tst_s_listener  Where to save Tester listener socket.
 * @param iut_sent        Where to save data sent from IUT.
 *
 * @return 0 on success, -1 on failure.
 */
extern int sockts_connection_begin(rcf_rpc_server *pco_iut,
                                   rcf_rpc_server *pco_tst,
                                   const struct sockaddr *iut_addr,
                                   const struct sockaddr *tst_addr,
                                   sockts_socket_type sock_type,
                                   int *iut_s,
                                   int *iut_s_listener,
                                   int *tst_s,
                                   int *tst_s_listener,
                                   te_dbuf *iut_sent);

/**
 * Check that the last operation in sockts_connection_begin()
 * is finished (TCP connection is established or UDP packet is received).
 *
 * @param pco_iut         RPC server on IUT.
 * @param pco_tst         RPC server on Tester.
 * @param sock_type       Socket type.
 * @param iut_s           IUT socket.
 * @param iut_s_listener  IUT listener socket.
 * @param tst_s           Tester socket.
 * @param tst_s_listener  Tester listener socket.
*
 * @return TRUE if finished, FALSE otherwise.
 */
extern te_bool sockts_connection_finished(rcf_rpc_server *pco_iut,
                                          rcf_rpc_server *pco_tst,
                                          sockts_socket_type sock_type,
                                          int iut_s,
                                          int iut_s_listener,
                                          int tst_s,
                                          int tst_s_listener);

/**
 * Second part of establishing/checking connection between two sockets.
 * In case of TCP connection establishment is finished, in case of
 * UDP data is received on Tester.
 *
 * @param pco_iut         RPC server on IUT.
 * @param pco_tst         RPC server on Tester.
 * @param iut_addr        Network address on IUT.
 * @param tst_addr        Network address on Tester.
 * @param sock_type       Socket type.
 * @param iut_s           Where IUT socket should be stored.
 * @param iut_s_listener  Where IUT listener socket should be stored.
 * @param tst_s           Where Tester socket should be stored.
 * @param tst_s_listener  Where Tester listener socket should be stored.
 * @param iut_sent        Data sent from IUT previously.
 *
 * @return 0 on success, -1 on failure.
 */
extern int sockts_connection_end(rcf_rpc_server *pco_iut,
                                 rcf_rpc_server *pco_tst,
                                 const struct sockaddr *iut_addr,
                                 const struct sockaddr *tst_addr,
                                 sockts_socket_type sock_type,
                                 int *iut_s,
                                 int *iut_s_listener,
                                 int *tst_s,
                                 int *tst_s_listener,
                                 te_dbuf *iut_sent);

/**
 * Allocate IPv4 address for which there is no entry in ARP table.
 *
 * @param net       Network in which to allocate address.
 * @param rpcs      RPC server handle on which to check ARP table.
 * @param if_name   Interface name (on which to look for ARP table entry).
 * @param addr      Where to save pointer to allocated address.
 */
extern void sockts_alloc_addr_without_arp_entry(tapi_env_net *net,
                                                rcf_rpc_server *rpcs,
                                                const char *if_name,
                                                struct sockaddr **addr);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif
