/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros for SO_REUSEPORT socket option tests 
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __SOCKOPTS_REUSEPORT_H__
#define __SOCKOPTS_REUSEPORT_H__

#include "tapi_route_gw.h"

/**
 * Name of Onload cluster.
 */
#define SOCKTS_CLUSTER_NAME "clus"

/**
 * Use different process or thread for the socket
 */
typedef enum {
    TP_NONE = 0,        /**< Sockets in single thread */
    TP_THREAD,          /**< Sockets in different threads */
    TP_PROCESS,         /**< Sockets in different processes */
} thread_process_type;

#define THREAD_PROCESS  \
    { "none", TP_NONE },       \
    { "thread", TP_THREAD },   \
    { "process", TP_PROCESS }

/**
 * Sockets closing iteration argument.
 */
typedef enum {
    REUSEPORT_CLOSE_ALIVE = 0, /**< Listener and accepted sockets alive. */
    REUSEPORT_CLOSE_LISTENER,  /**< Close listener socket. */
    REUSEPORT_CLOSE_ACCEPTED,  /**< Close accepted socket. */
} reuseport_close_type;

#define REUSEPORT_CLOSE  \
    { "alive", REUSEPORT_CLOSE_ALIVE },          \
    { "listener", REUSEPORT_CLOSE_LISTENER },    \
    { "accepted", REUSEPORT_CLOSE_ACCEPTED }

/**
 * Structure storing a single IUT socket, its peer (or accepted socket
 * and its peer) and related information.
 */
typedef struct reuseport_socket_ctx {
    rcf_rpc_server *pco_iut;              /**< IUT RPC server */
    rcf_rpc_server *pco_tst;              /**< Tester RPC server */
    const struct sockaddr *iut_addr;      /**< IUT address */
    const struct sockaddr *iut_addr_bind; /**< Address to bind IUT socket */
    const struct sockaddr *tst_addr;      /**< Tester address */
    int iut_acc;                          /**< Accepted IUT socket */
    int count;                            /**< Accepted sockets counter */
    int iut_s;                            /**< IUT (listener if TCP)
                                               socket */
    int tst_s;                            /**< Tester socket */

    struct sockaddr_storage new_tst_addr; /**< New address allocated on
                                               Tester */
} reuseport_socket_ctx;

/**
 * Initializer for reuseport_socket_ctx structure.
 */
#define REUSEPORT_SOCKET_CTX_INIT \
    { .pco_iut = NULL, .pco_tst = NULL, .iut_addr = NULL, \
      .iut_addr_bind = NULL, .tst_addr = NULL, \
      .iut_acc = -1, .count = 0, .iut_s = -1, .tst_s = -1 }

/**
 * Initialize socket context
 *
 * @param pco_iut     IUT RPC server
 * @param tst_iut     Tester RPC server
 * @param iut_addr    IUT address
 * @param tst_addr    Tester address
 * @param s           Socket context
 */
static inline void
reuseport_init_socket_ctx(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                          const struct sockaddr *iut_addr,
                          const struct sockaddr *tst_addr,
                          reuseport_socket_ctx *s)
{
    s->pco_iut = pco_iut;
    s->pco_tst = pco_tst;
    s->iut_addr = iut_addr;
    s->iut_addr_bind = iut_addr;
    s->tst_addr = tst_addr;
    s->iut_acc = -1;
    s->count = 0;
    s->iut_s = -1;
    s->tst_s = -1;
}

/**
 * Initialize @p child RPC in dependence on parameter @p thread_process
 * 
 * @param parent            Parent RPC server
 * @param child             Location for child RPC server
 * @param thread_process    Determines how to initialize @p child
 */
extern void init_aux_rpcs(rcf_rpc_server *parent, rcf_rpc_server **child,
                          thread_process_type thread_process);

/**
 * Establish connection between a couple of sockets, set SO_REUSEPOR in
 * dependence on @p set_reuseport
 * 
 * @param pco_iut            First RPC server
 * @param tst_iut            Second RPC server
 * @param sock_type          Sockets type
 * @param iut_addr           Local address of the first socket
 * @param tst_addr           Local address of the second socket
 * @param set_reuseport      Set SO_REUSEPORT if @c TRUE
 * @param set_reuseport_tst  Set SO_REUSEPORT on second socket if @c TRUE
 * @param iut_s              Location for the first socket
 * @param tst_s              Location for the second socket
 */
extern void reuseport_connection(rcf_rpc_server *pco_iut,
                                 rcf_rpc_server *pco_tst,
                                 rpc_socket_type sock_type,
                                 const struct sockaddr *iut_addr,
                                 const struct sockaddr *tst_addr,
                                 te_bool set_reuseport,
                                 te_bool set_reuseport_tst, 
                                 int *iut_s, int *tst_s);

/**
 * Close connected TCP sockets (not listener) stored in reuseport_socket_ctx
 * so that there is no socket in TIME_WAIT state left on IUT side.
 *
 * @param s     Socket context.
 */
extern void reuseport_close_tcp_conn(reuseport_socket_ctx *s);

/**
 * Close sockets stored in a reuseport_socket_ctx structure.
 *
 * @param s         Socket context.
 * @param cleanup   Whether close is done from test's cleanup.
 */
extern void reuseport_close_sockets(reuseport_socket_ctx *s,
                                    te_bool cleanup);

/**
 * Close all sockets stored in two reuseport_socket_ctx structures.
 *
 * @param s1          The first socket context.
 * @param s2          The second socket context.
 */
extern void reuseport_close_pair(reuseport_socket_ctx *s1,
                                 reuseport_socket_ctx *s2);

/**
 * Create two IUT sockets bound to the same address:port with
 * SO_REUSEPORT. For each of them obtain a connected Tester socket.
 *
 * @note This works correctly only for TCP sockets; for UDP use
 *       reuseport_pair_connection2().
 *
 * @param sock_type   Socket type
 * @param s1          The first socket context
 * @param s2          The second socket context
 */
extern void reuseport_pair_connection(rpc_socket_type sock_type,
                                      reuseport_socket_ctx *s1,
                                      reuseport_socket_ctx *s2);

/**
 * Create two IUT sockets bound to the same address:port with
 * SO_REUSEPORT. For each of them obtain a connected Tester socket.
 *
 * @param sock_type     Socket type.
 * @param tst_if        Network interface on Tester (required for UDP).
 * @param net           Network from which to allocate new IP addresses
 *                      on Tester (used in case of UDP where source address
 *                      determines which UDP socket receives a packet).
 * @param s1            The first socket context.
 * @param s2            The second socket context.
 * @param connect_iut   If @c TRUE, connect IUT sockets to their peers
 *                      (parameter makes sense only for UDP).
 */
extern void reuseport_pair_connection2(rpc_socket_type sock_type,
                                       const struct if_nameindex *tst_if,
                                       tapi_env_net *net,
                                       reuseport_socket_ctx *s1,
                                       reuseport_socket_ctx *s2,
                                       te_bool connect_iut);

/**
 * Try to establish connections via both IUT listeners bound
 * to the same address:port (so that each of them accepts
 * at least one connection).
 *
 * @param s1          The first sockets context.
 * @param s2          The second sockets context.
 */
extern void try_connect_pair(reuseport_socket_ctx *s1,
                             reuseport_socket_ctx *s2);

/**
 * Try to obtain a connected socket on Tester for each of two
 * UDP IUT sockets bound to the same address with SO_REUSEPORT.
 * Tester sockets will have to be bound to different addresses,
 * because decision which IUT socket receives a given packet
 * is based on its source address here.
 *
 * @param tst_if              Tester network interface.
 * @param net                 Network to allocate new IP addresses.
 * @param s1                  The first socket context.
 * @param s2                  The second socket context.
 * @param connect_iut         If @c TRUE, connect IUT sockets to
 *                            their peers.
 */
extern void try_connect_udp_pair(const struct if_nameindex *tst_if,
                                 tapi_env_net *net,
                                 reuseport_socket_ctx *s1,
                                 reuseport_socket_ctx *s2,
                                 te_bool connect_iut);

/**
 * Attempt to accept connection.
 * 
 * @param pco_iut     RPC server
 * @param sock        Listener socket
 * 
 * @return Accepted socket or @c -1
 */
extern int reuseport_try_accept(rcf_rpc_server *pco_iut, int sock);

/**
 * Create and bind socket, set SO_REUSEPORT optionaly.
 * 
 * @param rpcs       RPC server
 * @param sock_type  Socket type
 * @param iut_addr   Address to bind
 * @param reuseport  Set SO_REUSEPORT socket option
 * 
 * @return The new socket
 */
static inline int
reuseport_create_bind_socket(rcf_rpc_server *rpcs,
                            rpc_socket_type sock_type,
                            const struct sockaddr *iut_addr,
                            te_bool reuseport)
{
    int sock;

    sock = rpc_socket(rpcs, rpc_socket_domain_by_addr(iut_addr),
                      sock_type, RPC_PROTO_DEF);
    if (reuseport)
        rpc_setsockopt_int(rpcs, sock, RPC_SO_REUSEPORT, 1);

    RPC_AWAIT_IUT_ERROR(rpcs);
    if (rpc_bind(rpcs, sock, iut_addr) != 0)
        TEST_VERDICT("bind() failed with %r", RPC_ERRNO(rpcs));

    return sock;
}

/**
 * Add new IP address to the interface @p if_idx, create UDP socket
 * and bind it to the new address.
 *
 * @param rpcs          RPC server handler
 * @param if_idx        Interface context
 * @param net           Network handler
 * @param new_addr      Where to save new IP address
 * @param addr_handle   Where to save address configurator handle
 *                      (may be used for address removal)
 * @param any_port      Bind to port @c 0 or not
 *
 * @return The socket descriptor
 */
extern int reuseport_create_tst_udp_sock_gen(
    rcf_rpc_server *rpcs, const struct if_nameindex *if_idx,
    tapi_env_net *net,  struct sockaddr_storage *new_addr,
    cfg_handle *addr_handle, te_bool any_port);

/**
 * Add new IP address to the interface @p if_idx, create UDP socket
 * and bind it to the new address with non-zero port.
 *
 * @param rpcs          RPC server handler
 * @param if_idx        Interface context
 * @param net           Network handler
 * @param new_addr      Where to save new IP address
 * @param addr_handle   Where to save address configurator handle
 *                      (may be used for address removal)
 *
 * @return The socket descriptor
 */
static inline int
reuseport_create_tst_udp_sock(
    rcf_rpc_server *rpcs, const struct if_nameindex *if_idx,
    tapi_env_net *net,  struct sockaddr_storage *new_addr,
    cfg_handle *addr_handle)
{
    return reuseport_create_tst_udp_sock_gen(rpcs, if_idx, net, new_addr,
                                             addr_handle, FALSE);
}

/**
 * Add new IP address to the interface @p if_idx, create UDP socket
 * and bind it to the new address with zero port.
 *
 * @param rpcs          RPC server handler
 * @param if_idx        Interface context
 * @param net           Network handler
 * @param new_addr      Where to save new IP address
 * @param addr_handle   Where to save address configurator handle
 *                      (may be used for address removal)
 *
 * @return The socket descriptor
 */
static inline int
reuseport_create_tst_udp_sock_any_port(
    rcf_rpc_server *rpcs, const struct if_nameindex *if_idx,
    tapi_env_net *net,  struct sockaddr_storage *new_addr,
    cfg_handle *addr_handle)
{
    return reuseport_create_tst_udp_sock_gen(rpcs, if_idx, net, new_addr,
                                             addr_handle, TRUE);
}

/**
 * Try to accept connection and fill the socket pair context
 * if connection was accepted.
 *
 * @param s           Socket context.
 * @param tst_s       Tester socket from which connect() was called.
 *
 * @return @c TRUE if success
 */
extern te_bool reuseport_try_accept_pair(reuseport_socket_ctx *s,
                                         int tst_s);

/**
 * Check if socket is expectedly destroyed or not.
 *
 * @param pco_iut   IUT rpc server
 * @param iut_addr  IUT address
 * @param tst_addr  Tester address
 * @param destroyed The socket should be destroyed if @c TRUE
 */
extern void reuseport_check_sockets_closing(rcf_rpc_server *pco_iut,
                                            const struct sockaddr *iut_addr,
                                            const struct sockaddr *tst_addr,
                                            te_bool destroyed);

/**
 * Prepare network channel and/or close tester sockets to get required TCP
 * closing state.
 *
 * @param gateway   Gateway network API handle
 * @param state     Required TCP state
 * @param s1        The first socket context or @c NULL
 * @param s2        The second socket context or @c NULL
 */
extern void reuseport_close_state_prepare(tapi_route_gateway *gateway,
                                          rpc_tcp_state state,
                                          reuseport_socket_ctx *s1,
                                          reuseport_socket_ctx *s2);

/**
 * Final activity on the network channel and/or tester sockets to get required
 * TCP closing state.
 *
 * @param state     Required TCP state
 * @param s1        The first socket context or @c NULL
 * @param s2        The second socket context or @c NULL
 */
extern void reuseport_close_state_finish(rpc_tcp_state state,
                                         reuseport_socket_ctx *s1,
                                         reuseport_socket_ctx *s2);

/**
 * Fix connection between hosts which could be broken to get required IUT
 * socket state.
 *
 * @param state     Tested socket state
 * @param gateway   Gateway connection context
 */
extern void reuseport_fix_connection(rpc_tcp_state state,
                                     tapi_route_gateway *gateway);

#endif  /* !__SOCKOPTS_REUSEPORT_H__ */
