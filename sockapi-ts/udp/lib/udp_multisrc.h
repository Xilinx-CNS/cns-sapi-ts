/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief UDP Test Suite
 *
 * Common definitions for checking datagrams reception from multiple
 * sources.
 */

#include "sockapi-test.h"

#ifndef __TS_UDP_MULTISRC_H__
#define __TS_UDP_MULTISRC_H__

#ifdef __cplusplus
extern "C" {
#endif

/** Peer sending datagrams */
typedef struct udp_multisrc_peer {
    rcf_rpc_server *rpcs;                 /**< RPC server handle */
    struct sockaddr_storage peer_addr;    /**< Source address */
    int s;                                /**< Peer socket */
    void *packet;                         /**< Pointer to sent packet
                                               description */
} udp_multisrc_peer;

/**
 * Allocate and assign new addresses if necessary. Create, bind and
 * connect sockets on IUT and Tester(s).
 *
 * @param pco_iut             RPC server on IUT.
 * @param pco_tst1            RPC server on Tester1.
 * @param pco_tst2            RPC server on Tester2 (may be @c NULL).
 * @param net1                The first network.
 * @param net2                The second network (may be @c NULL).
 * @param tst1_if             Network interface on Tester1.
 * @param tst2_if             Network interface on Tester2 (may be @c NULL).
 * @param iut_addr1           The first network address on IUT.
 * @param iut_addr2           The second network address on IUT (may be
 *                            @c NULL).
 * @param tst1_addr           Network address on Tester1.
 * @param tst2_addr           Network address on Tester2 (may be @c NULL).
 * @param diff_addrs          If @c TRUE, different network address
 *                            should be used for each Tester peer.
 * @param max_data_len        Maximum length of datagram payload to be
 *                            tested.
 * @param iut_s               Where to save IUT socket FD.
 * @param peers               Array of peer structures to fill.
 * @param peers_num           Number of peers.
 */
extern void udp_multisrc_create_peers(rcf_rpc_server *pco_iut,
                                      rcf_rpc_server *pco_tst1,
                                      rcf_rpc_server *pco_tst2,
                                      tapi_env_net *net1,
                                      tapi_env_net *net2,
                                      const struct if_nameindex *tst1_if,
                                      const struct if_nameindex *tst2_if,
                                      const struct sockaddr *iut_addr1,
                                      const struct sockaddr *iut_addr2,
                                      const struct sockaddr *tst1_addr,
                                      const struct sockaddr *tst2_addr,
                                      te_bool diff_addrs, int max_data_len,
                                      int *iut_s, udp_multisrc_peer *peers,
                                      int peers_num);

/**
 * Send a packet from every Tester socket; receive and check all packets
 * on the IUT socket.
 *
 * @param pco_iut             RPC server on IUT.
 * @param iut_s               IUT socket.
 * @param peers               Peers on Tester(s).
 * @param peers_num           Number of peers.
 * @param max_data_len        Maximum length of UDP payload.
 * @param recv_func           Receiving function to use
 *                            (see @ref sockts_recv_func).
 */
extern void udp_multisrc_send_receive(rcf_rpc_server *pco_iut, int iut_s,
                                      udp_multisrc_peer *peers,
                                      int peers_num, int max_data_len,
                                      int recv_func);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __TS_UDP_MULTISRC_H__ */
