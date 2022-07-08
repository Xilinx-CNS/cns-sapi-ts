/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Creating network connections with VLAN, MACVLAN or IPVLAN
 *
 * Test API to create new network connections based on VLAN,
 * MACVLAN or IPVLAN interfaces.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#ifndef __TS_SOCKAPI_TS_NET_CONNS_H__
#define __TS_SOCKAPI_TS_NET_CONNS_H__

#include "te_config.h"

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NET_IF_H
#include <net/if.h>
#endif

#include "conf_api.h"
#include "te_defs.h"
#include "rcf_rpc.h"

/**
 * Structure describing a connected pair of interfaces.
 */
typedef struct sockts_net_conn {
    cfg_handle        net_handle;               /**< Configurator handle
                                                     for a network to which
                                                     addresses belong. */
    unsigned int      net_prefix;               /**< Network prefix
                                                     length. */
    cfg_handle        iut_addr_handle;          /**< Configurator handle of
                                                     IUT address. */
    cfg_handle        tst_addr_handle;          /**< Configurator handle of
                                                     Tester address. */
    cfg_handle        tst_addr_handle2;         /**< Configurator handle of
                                                     Tester address as
                                                     assigned to a specific
                                                     interface. */

    struct sockaddr  *iut_addr;                 /**< IUT address. */
    struct sockaddr  *tst_addr;                 /**< Tester address. */

    struct if_nameindex         iut_new_if;     /**< Name of the newly
                                                     created interface on
                                                     IUT. */
    struct if_nameindex         tst_new_if;     /**< Name of the newly
                                                     created interface on
                                                     Tester. */
    int               vlan_id;                  /**< VLAN ID. */
    te_bool           iut_new_if_configured;    /**< Whether new interface
                                                     was configured on
                                                     IUT. */
    te_bool           tst_new_if_configured;    /**< Whether new interface
                                                     was configured on
                                                     Tester. */
} sockts_net_conn;

/** Initializer for sockts_net_conn structure. */
#define SOCKTS_NET_CONN_INIT \
    { CFG_HANDLE_INVALID, 0, \
      CFG_HANDLE_INVALID, CFG_HANDLE_INVALID, CFG_HANDLE_INVALID, \
      NULL, NULL, { 0, NULL }, { 0, NULL}, -1, FALSE, FALSE}

/**
 * A structure for storing one or two network connections
 * (described by sockts_net_conn structures).
 */
typedef struct sockts_net_conns {
    te_interface_kind            if_type;       /**< Type of created
                                                     interfaces */

    rcf_rpc_server              *pco_iut;       /**< RPC server on IUT. */
    rcf_rpc_server              *pco_tst;       /**< RPC server on
                                                     Tester. */
    const struct if_nameindex   *iut_if;        /**< Base network interface
                                                     on IUT. */
    const struct if_nameindex   *tst_if;        /**< Base network interface
                                                     on Tester. */

    sockts_net_conn              conn1;         /**< The first additional
                                                     connection. */
    sockts_net_conn              conn2;         /**< The second additional
                                                     connection. */

    int               old_iut_if_rp_filter;     /**< Saved value of
                                                     rp_filter property
                                                     of IUT base
                                                     interface. */
    int               old_iut_if_arp_ignore;    /**< Saved value of
                                                     arp_ignore property
                                                     of IUT base
                                                     interface. */
} sockts_net_conns;

/** Initializer for sockts_net_conns structure. */
#define SOCKTS_NET_CONNS_INIT \
    { TE_INTERFACE_KIND_VLAN, NULL, NULL, NULL, NULL, \
      SOCKTS_NET_CONN_INIT, SOCKTS_NET_CONN_INIT, \
      -1, -1 }

/**
 * Configure one or two new network connections.
 *
 * @param pco_iut             RPC server on IUT.
 * @param pco_tst             RPC server on Tester.
 * @param iut_if              Base network interface on IUT.
 * @param tst_if              Base network interface on Tester.
 * @param if_id1              An ID for the first new interface.
 * @param if_id2              An ID for the second new interface.
 * @param af                  Address family of assigned addresses
 *                            (@c AF_INET or @c AF_INET6).
 * @param if_type             Type of interfaces which should be
 *                            created (@c TE_INTERFACE_KIND_VLAN,
 *                            @c TE_INTERFACE_KIND_MACVLAN or
 *                            @c TE_INTERFACE_KIND_IPVLAN).
 * @param conns               Where to save information
 *                            about newly created objects
 *                            and configuration changes.
 */
extern void sockts_configure_net_conns(rcf_rpc_server *pco_iut,
                                       rcf_rpc_server *pco_tst,
                                       const struct if_nameindex *iut_if,
                                       const struct if_nameindex *tst_if,
                                       int if_id1, int if_id2, int af,
                                       te_interface_kind if_type,
                                       sockts_net_conns *conns);

/**
 * Rollback configuration changes made to create network
 * connections, release allocated memory.
 *
 * @param conns     Pointer to sockts_net_conns structure.
 *
 * @return Status code.
 */
extern te_errno sockts_destroy_net_conns(sockts_net_conns *conns);

/**
 * Allocate a new IPv4 or IPv6 network in Configuration tree.
 *
 * @param net_handle      Where to save network handle.
 * @param net_prefix      Where to save network prefix.
 * @param af              Address family.
 */
extern void sockts_allocate_network(cfg_handle *net_handle,
                                    unsigned int *net_prefix,
                                    int af);

#endif /* __TS_SOCKAPI_TS_NET_CONNS_H__ */
