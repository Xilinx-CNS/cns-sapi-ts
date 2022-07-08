/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Auxilliary functions incapsulating some common actions needed for
 * VLAN test purposes.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru> 
 *
 * $Id$
 */

#ifndef __VLAN_COMMON_H__
#define __VLAN_COMMON_H__

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "te_defs.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "rcf_rpc.h"

#include "te_sockaddr.h"
#include "tapi_rpc_socket.h"
#include "tapi_rpc_ifnameindex.h"

#include "sockapi-ts_env.h"

/**
 * Create and configure VLAN interface (wrapper macros)
 *
 * @param _pco           PCO
 * @param _net           Configurator handle of new network 
 * @param _addr_entry    Where to save address configuration handle
 * @param _addr          IP address to be allocated and set to
 *                       VLAN interface
 * @param _pref          Network prefix length of IP address
 * @param _if            Interface on PCO
 * @param _vlan_id       ID of VLAN interface to be created
 * @param _vlan_if_name  Name of VLAN interface (it will be set after
 *                       creation)
 * @param _created       It will be set to TRUE after successful creation
 *                       of VLAN interface (can be used for cleanup
 *                       purpose)
 */
#define CREATE_CONFIGURE_VLAN(_pco, _net, _addr_entry, _addr, _pref, _if, \
                              _vlan_id, _vlan_if_name, _created)          \
    CREATE_CONFIGURE_VLAN_EXT(_pco, _net, _addr_entry, _addr, _pref, _if, \
                              _vlan_id, _vlan_if_name, _created, FALSE)

/**
 * Create and configure VLAN interface
 *
 * @param _pco           PCO
 * @param _net           Configurator handle of new network 
 * @param _addr_entry    Where to save address configuration handle
 * @param _addr          IP address to be allocated and set to
 *                       VLAN interface
 * @param _pref          Network prefix length of IP address
 * @param _if            Interface on PCO
 * @param _vlan_id       ID of VLAN interface to be created
 * @param _vlan_if_name  Name of VLAN interface (it will be set after
 *                       creation)
 * @param _created       It will be set to TRUE after successful creation
 *                       of VLAN interface (can be used for cleanup
 *                       purpose)
 * @param _no_sleep      Disable sleeping in the mcaros if it's @c TRUE.
 */
#define CREATE_CONFIGURE_VLAN_EXT(_pco, _net, _addr_entry, _addr, _pref, \
                                  _if, _vlan_id, _vlan_if_name, _created,  \
                                  _no_sleep)                               \
do {                                                                       \
        CHECK_RC(tapi_cfg_alloc_net_addr(_net, &_addr_entry,               \
                                         &_addr));                         \
        RING("Configure vlan with id=%d on %s interface %s",               \
             _vlan_id, #_pco, _if->if_name);                               \
        CHECK_RC(tapi_cfg_base_if_add_get_vlan(_pco->ta,                   \
                                               _if->if_name,               \
                                               (uint16_t)_vlan_id,         \
                                               &_vlan_if_name));           \
        _created = TRUE;                                                   \
        CHECK_RC(tapi_cfg_base_if_up(_pco->ta,                             \
                                     _vlan_if_name));                      \
        if (tapi_cfg_base_if_add_net_addr(_pco->ta,                        \
                                          _vlan_if_name,                   \
                                          _addr,                           \
                                          _pref, TRUE, NULL) != 0)         \
        {                                                                  \
            ERROR("Cannot add an address to the %s interface",             \
                  _vlan_if_name);                                          \
            free(_vlan_if_name);                                           \
            TEST_STOP;                                                     \
        }                                                                  \
        if (_no_sleep == FALSE)                                            \
            CFG_WAIT_CHANGES;                                              \
    } while(0)

/**
 * Create if_nameindex structure describing interface with a given
 * name. Create datagram sockets on both sides, 
 *
 * @param _pco              RPC server
 * @param _if_nameindex     Pointer to structure to be created
 * @param _if_name          Interface name
 */
#define GET_NAMEINDEX(_pco, _if_nameindex, _if_name) \
    do {                                                                \
        _if_nameindex = calloc(1, sizeof(struct if_nameindex));         \
        (_if_nameindex)->if_name = _if_name;                            \
        (_if_nameindex)->if_index = rpc_if_nametoindex(_pco, _if_name); \
    } while (0)

/**
 * Create two vlan interfaces on IUT and TESTER with
 * IP addresses from a new network.
 *
 * @param pco_iut           RPC server on IUT
 * @param pco_tst           RPC server on TESTER
 * @param iut_if            Interface on IUT
 * @param tst_if            Interface on TESTER
 * @param new_net_handle    Here new network handle will be returned
 * @param iut_addr_handle   Here new IUT network address handle will be
 *                          returned
 * @param tst_addr_handle   Here new TESTER network address handle will be
 *                          returned
 * @param iut_addr          Address on IUT interface (it will be
 *                          allocated if VLAN is used)
 * @param tst_addr          Address on TESTER interface (it will be
 *                          allocated if VLAN is used)
 * @param iut_vlan_if       IUT vlan interface to be created
 * @param tst_vlan_if       TESTER vlan interface to be created
 * @param vlan_id           VLAN id
 * @param iut_is_configured It will be set to TRUE if VLAN interface
 *                          on IUT was successfully created, FALSE
 *                          otherwise
 * @param tst_is_configured It will be set to TRUE if VLAN interface
 *                          on TESTER was successfully created, FALSE
 *                          otherwise
 */
extern void
create_vlan_pair(struct rcf_rpc_server *pco_iut,
                 struct rcf_rpc_server *pco_tst,
                 const struct if_nameindex *iut_if,
                 const struct if_nameindex *tst_if,
                 cfg_handle *new_net_handle,
                 cfg_handle *iut_addr_handle,
                 cfg_handle *tst_addr_handle,
                 struct sockaddr **iut_addr,
                 struct sockaddr **tst_addr,
                 struct if_nameindex **iut_vlan_if,
                 struct if_nameindex **tst_vlan_if,
                 int vlan_id,
                 te_bool *iut_is_configured,
                 te_bool *tst_is_configured);

/**
 * If required, create two vlan interfaces on IUT and TESTER with
 * IP addresses from a new network. Set outgoing interface for 
 * multicast packets for sending socket, bind receiving socket to
 * wildcard address and port the same as in address of multicast group.
 *
 * @param pco_iut           RPC server on IUT
 * @param pco_tst           RPC server on TESTER
 * @param iut_if            Interface on IUT
 * @param tst_if            Interface on TESTER
 * @param new_net_handle    Here new network handle will be returned
 *                          (if VLAN is used)
 * @param iut_addr_handle   Here new IUT network address handle will be
 *                          returned if VLAN is used
 * @param tst_addr_handle   Here new TESTER network address handle will be
 *                          returned is VLAN is used
 * @param iut_addr          Address on IUT interface (it will be
 *                          allocated if VLAN is used)
 * @param tst_addr          Address on TESTER interface (it will be
 *                          allocated if VLAN is used)
 * @param mcast_addr        Multicast group address
 * @param sock_func         Socket creation function to be used on IUT
 * @param iut_s             IUT socket to be created
 * @param tst_s             TESTER socket to be created
 * @param iut_rcv           Whether socket on IUT receives or sends
 *                          datagrams
 * @param is_vlan           Whether VLAN interfaces should be created
 * @param iut_vlan_if       IUT vlan interface to be created
 * @param tst_vlan_if       TESTER vlan interface to be created
 * @param vlan_id           VLAN id
 * @param iut_is_configured It will be set to TRUE if VLAN interface
 *                          on IUT was successfully created, FALSE
 *                          otherwise
 * @param tst_is_configured It will be set to TRUE if VLAN interface
 *                          on TESTER was successfully created, FALSE
 *                          otherwise
 */
extern void
create_net_channel(struct rcf_rpc_server *pco_iut,
                   struct rcf_rpc_server *pco_tst,
                   const struct if_nameindex *iut_if,
                   const struct if_nameindex *tst_if,
                   cfg_handle *new_net_handle,
                   cfg_handle *iut_addr_handle,
                   cfg_handle *tst_addr_handle,
                   struct sockaddr **iut_addr,
                   struct sockaddr **tst_addr,
                   const struct sockaddr *mcast_addr,
                   sockts_socket_func sock_func,
                   int *iut_s,
                   int *tst_s,
                   te_bool iut_rcv,
                   te_bool is_vlan,
                   struct if_nameindex **iut_vlan_if,
                   struct if_nameindex **tst_vlan_if,
                   int vlan_id,
                   te_bool *iut_is_configured,
                   te_bool *tst_is_configured);

/**
 * Remove VLAN interface in a cleanup part of test
 *
 * @param _pco          PCO
 * @param _if           Master interface on PCO
 * @param _vlan_id      ID of VLAN interface to be removed
 * @param _created      Whether VLAN interface was created successfully or
                        not
 */
#define CLEANUP_REMOVE_VLAN(_pco, _if, _vlan_id, _created) \
    do {                                                                   \
        if (_created)                                                      \
        {                                                                  \
            RING("Remove vlan with id=%d on %s interface %s",              \
                 _vlan_id, #_pco, _if->if_name);                           \
            CLEANUP_CHECK_RC(                                              \
                tapi_cfg_base_if_del_vlan(_pco->ta,                        \
                                          _if->if_name, _vlan_id));        \
        }                                                                  \
    } while (0)

/**
 * Check that correct amount of data was received from expected peer
 *
 * @param _ret_len      Actual length of returned data
 * @param _exp_len      Expected length of returned data
 * @param _addr         Actual address from which data was received
 * @param _exp_addr     Expected address from which data should be received
 * @param _macro_len    Macro used to write a record in a log about
 *                      unexpected length
 * @param _macro_peer   Macro used to write a record in a log about
 *                      unexpected peer
 * @param _peer_names   Array linking addresses and corresponding peer
 *                      names
 * @param _unexp_len    Pointer to boolean variable to be set if
 *                      length of received data is unexpected
 * @param _unexp_peer   Pointer to boolean variable to be set if
 *                      peer from which data was received is
 *                      unexpected
 */
#define CHECK_RETURNED_LEN(_ret_len, _exp_len, _addr, _exp_addr, \
                           _macro_len, _macro_peer, \
                           _peer_names, _unexp_len, _unexp_peer, \
                           _sock_name) \
    do {                                                           \
        if (te_sockaddrcmp(SA(_addr),                              \
                           te_sockaddr_get_size(SA(_addr)),        \
                           SA(_exp_addr),                          \
                           te_sockaddr_get_size(                   \
                                        SA(_exp_addr))) != 0)      \
        {                                                          \
            _macro_peer("%s receives data from %s "                \
                        "but it is expected to receive from %s",   \
                        _sock_name,                                \
                        get_name_by_addr(SA(_addr), _peer_names),  \
                        get_name_by_addr(SA(_exp_addr),            \
                                         _peer_names));            \
            if (ptr_is_not_null(_unexp_peer))                      \
                *(te_bool *)_unexp_peer = TRUE;                    \
        }                                                          \
        else if ((int)_ret_len != (int)_exp_len)                   \
        {                                                          \
            _macro_len("%s receives unexpected number of "         \
                       "bytes from %s", _sock_name,                \
                       get_name_by_addr(SA(_addr), _peer_names));  \
            if (ptr_is_not_null(_unexp_len))                       \
                *(te_bool *)_unexp_len = TRUE;                     \
        }                                                          \
    } while (0)

/** Structure describing a peer for VLAN tests */
typedef struct peer_name_t {
   struct sockaddr **addr; /**< Peer address */
   char *name;             /**< Peer name */
} peer_name_t;

/**
 * Get peer name by its address
 *
 * @param addr          Peer address
 * @param peer_names    Array linking addresses and corresponding peer
 *                      names.
 *
 * @return Peer name on success or "unknown peer" if peer address
 *         is not found
 */
extern char *
get_name_by_addr(struct sockaddr *addr, peer_name_t *names);

/** Structure describing socket names */
typedef struct sock_name_t {
    int *sock; /**< Socket descriptor */
    rcf_rpc_server **pco; /**< RPC server */
    char *name; /** Socket name */
} sock_name_t;

/**
 * Get socket name by its descriptor and RPC server
 *
 * @param s             Socket desriptor
 * @param peer_names    Array linking socket descriptors/RPC servers
 *                      and corresponding socket names.
 *
 * @return Socket name on success or "unknown socket"
 */
extern char *
get_name_by_sock(int s, rcf_rpc_server *pco, sock_name_t *names);

#endif /* !__VLAN_COMMON_H__ */
