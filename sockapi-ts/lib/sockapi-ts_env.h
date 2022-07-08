/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Common Test API to process test arguments and environment
 *
 * Definition of test API to process common test arguments and environments
 * along with accompanying API like common macros for connection
 * estblishment.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#ifndef __SOCKAPI_TS_ENV_H__
#define __SOCKAPI_TS_ENV_H__

#include "rcf_rpc.h"
#include "te_rpc_types.h"

/**
 * Types of sockets.
 */
typedef enum {
    SOCKTS_SOCK_UDP = 0,        /**< UDP socket. */
    SOCKTS_SOCK_UDP_NOTCONN,    /**< Not connected UDP socket. */
    SOCKTS_SOCK_TCP_ACTIVE,     /**< Actively opened TCP socket. */
    SOCKTS_SOCK_TCP_PASSIVE,    /**< Passively opened TCP socket. */
    SOCKTS_SOCK_TCP_PASSIVE_CL, /**< Passively opened TCP socket, but
                                     listener is closed just after
                                     connection establishing. */
} sockts_socket_type;

/**
 * List of socket types, can be passed to macro @b TEST_GET_ENUM_PARAM.
 */
#define SOCKTS_SOCK_TYPES \
    { "udp",                SOCKTS_SOCK_UDP },          \
    { "udp_notconn",        SOCKTS_SOCK_UDP_NOTCONN },  \
    { "tcp_active",         SOCKTS_SOCK_TCP_ACTIVE },   \
    { "tcp_passive",        SOCKTS_SOCK_TCP_PASSIVE },  \
    { "tcp_passive_close",  SOCKTS_SOCK_TCP_PASSIVE_CL }

/**
 * Get socket type.
 */
#define SOCKTS_GET_SOCK_TYPE(_sock_type) \
    TEST_GET_ENUM_PARAM(_sock_type, SOCKTS_SOCK_TYPES)

/**
 * Return generic socket type corresponding to
 * sockts_socket_type.
 *
 * @param sock_type    Value of type sockts_socket_type.
 *
 * @return @c RPC_SOCK_STREAM or @c RPC_SOCK_DGRAM.
 */
extern rpc_socket_type sock_type_sockts2rpc(sockts_socket_type sock_type);

/**
 * Create sockets, bind and connect them in accordance to the parameters.
 *
 * @param pco_iut_       IUT RPC server handle.
 * @param pco_tst_       Tester RPC server handle.
 * @param iut_addr_      IUT address.
 * @param tst_addr_      Tester address.
 * @param sock_type_     Socket type @b sockts_socket_type.
 * @param bind_wildcard_ Bind IUT socket to wildcard address.
 * @param iut_s_         IUT socket location.
 * @param tst_s_         Tester socket location.
 * @param iut_l_         IUT listener socket location or @c NULL.
 */
#define SOCKTS_CONNECTION_WILD(pco_iut_, pco_tst_, iut_addr_,              \
                               tst_addr_, sock_type_, bind_wildcard_,      \
                               iut_s_, tst_s_, iut_l_)                     \
    do {                                                                   \
        te_bool fake = FALSE;                                              \
        const struct sockaddr  *gw_addr = NULL;                            \
        CHECK_ADDR_FAKE(iut_addr_, fake);                                  \
        if (fake)                                                          \
            TEST_GET_ADDR_NO_PORT(gw_addr);                                \
        sockts_connection(pco_iut_, pco_tst_, iut_addr_, tst_addr_,        \
                          sock_type_, bind_wildcard_, FALSE, gw_addr,      \
                          iut_s_, tst_s_, iut_l_,                          \
                          SOCKTS_SOCK_FUNC_SOCKET);                        \
    } while (0)

/**
 * Create sockets, bind and connect them in accordance to the parameters.
 *
 * @param pco_iut_      IUT RPC server handle.
 * @param pco_tst_      Tester RPC server handle.
 * @param iut_addr_     IUT address.
 * @param tst_addr_     Tester address.
 * @param sock_type_    Socket type @b sockts_socket_type.
 * @param iut_s_        IUT socket location.
 * @param tst_s_        Tester socket location.
 * @param iut_l_        IUT listener socket location or @c NULL.
 */
#define SOCKTS_CONNECTION(pco_iut_, pco_tst_, iut_addr_, tst_addr_,     \
                          sock_type_, iut_s_, tst_s_, iut_l_)           \
    SOCKTS_CONNECTION_WILD(pco_iut_, pco_tst_, iut_addr_, tst_addr_,    \
                           sock_type_, FALSE, iut_s_, tst_s_, iut_l_)

/**
 * Analogue of the macro @c SOCKTS_CONNECTION_WILD, but this one takes
 * @b rpc_socket_type as the socket type.
 *
 * @param srvr_             Server RPC server handle.
 * @param clnt_             Client RPC server handle.
 * @param sock_type_        Socket type @b rpc_socket_type.
 * @param srvr_addr_        Server address.
 * @param clnt_addr_        Client address.
 * @param srvr_s_           Server socket location.
 * @param clnt_s_           Client socket location.
 * @param bind_wildcard_    Bind IUT socket to wildcard address.
 */
#define GEN_CONNECTION_WILD_FAKE(srvr_, clnt_, sock_type_, proto_,         \
                                 srvr_addr_, clnt_addr_, srvr_s_,          \
                                 clnt_s_, bind_wildcard_)                  \
    SOCKTS_CONNECTION_WILD(clnt_, srvr_, clnt_addr_, srvr_addr_,           \
                           sock_type_ == RPC_SOCK_DGRAM ?                  \
                               SOCKTS_SOCK_UDP : SOCKTS_SOCK_TCP_ACTIVE,   \
                           bind_wildcard_, clnt_s_, srvr_s_, NULL)

#define GEN_CONNECTION_FAKE(srvr_, clnt_, sock_type_, proto_,       \
                            srvr_addr_, clnt_addr_, srvr_s_,        \
                            clnt_s_)                                \
    GEN_CONNECTION_WILD_FAKE(srvr_, clnt_, sock_type_, proto_,      \
                             srvr_addr_, clnt_addr_, srvr_s_,       \
                             clnt_s_, FALSE)

/**
 * Unset environment after @c SET_TRANSPARENT
 *
 * @param iut_addr_ Remote address for PCO on IUT
 * @param pco_tst_  Tester PCO
 * @param tst_addr_ Address on @p pco_tst_
 */
#define CHECK_CLEAR_TRANSPARENT(iut_addr_, pco_tst_, tst_addr_)    \
do {                                                               \
    int fake = FALSE;                                              \
    CHECK_ADDR_FAKE(iut_addr_, fake);                              \
    if (fake)                                                      \
    {                                                              \
        const struct sockaddr  *gw_addr = NULL;                    \
        rpc_socket_domain       domain;                            \
        int                     af;                                \
        int                     route_prefix;                      \
                                                                   \
        TEST_GET_ADDR_NO_PORT(gw_addr);                            \
                                                                   \
        domain = rpc_socket_domain_by_addr(iut_addr_);             \
        af = addr_family_rpc2h(domain);                            \
        route_prefix = te_netaddr_get_size(addr_family_rpc2h(      \
                        domain)) * 8;                              \
                                                                   \
        tapi_cfg_del_route_tmp(pco_tst_->ta, af,                   \
                               te_sockaddr_get_netaddr(iut_addr_), \
                               route_prefix,                       \
                               te_sockaddr_get_netaddr(gw_addr),   \
                               NULL,                               \
                               te_sockaddr_get_netaddr(tst_addr_), \
                               0, 0, 0, 0,                         \
                               0, 0);                              \
    }                                                              \
} while(0)

/** IP address types. */
typedef enum {
    SOCKTS_ADDR_NONE,    /**< No address. */
    SOCKTS_ADDR_SPEC,    /**< Specific (unicast) address. */
    SOCKTS_ADDR_WILD,    /**< INADDR_ANY. */
    SOCKTS_ADDR_MCAST,   /**< Multicast address. */
    SOCKTS_ADDR_BCAST,   /**< Broadcast address. */
} sockts_addr_type;

/**
 * List of address types to be passed to TEST_GET_ENUM_PARAM().
 */
#define SOCKTS_ADDR_TYPES \
    { "none",             SOCKTS_ADDR_NONE },    \
    { "specific",         SOCKTS_ADDR_SPEC },    \
    { "wildcard",         SOCKTS_ADDR_WILD },    \
    { "multicast",        SOCKTS_ADDR_MCAST },   \
    { "broadcast",        SOCKTS_ADDR_BCAST }

/** Get address type. */
#define SOCKTS_GET_ADDR_TYPE(_addr_type) \
    TEST_GET_ENUM_PARAM(_addr_type, SOCKTS_ADDR_TYPES)

/**
 * Functions used to create a socket.
 */
typedef enum {
    SOCKTS_SOCK_FUNC_SOCKET = 0,                /**< socket(). */
    SOCKTS_SOCK_FUNC_ONLOAD_UNICAST_NONACC,
                        /**< onload_socket_unicast_nonaccel(). */
} sockts_socket_func;

/**
 * List of socket creation functions, can be passed to macro
 * @b TEST_GET_ENUM_PARAM.
 */
#define SOCKTS_SOCKET_FUNCS \
    { "socket",             SOCKTS_SOCK_FUNC_SOCKET },                \
    { "onload_socket_unicast_nonaccel",                               \
                            SOCKTS_SOCK_FUNC_ONLOAD_UNICAST_NONACC }  \

/**
 * Get socket function.
 */
#define SOCKTS_GET_SOCK_FUNC(_sock_func) \
    TEST_GET_ENUM_PARAM(_sock_func, SOCKTS_SOCKET_FUNCS)

/**
 * Get socket function name.
 *
 * @param func    Socket function.
 *
 * @return Function name.
 */
static inline const char *
sockts_socket_func2str(sockts_socket_func func)
{
    switch (func)
    {
        case SOCKTS_SOCK_FUNC_SOCKET:
            return "socket";

        case SOCKTS_SOCK_FUNC_ONLOAD_UNICAST_NONACC:
            return "onload_socket_unicast_nonaccel";
    }

    return "<UNKNOWN>";
}

/**
 * Create sockets, bind and connect them in accordance to the parameters.
 *
 * @param pco_iut             IUT RPC server handle.
 * @param pco_tst             Tester RPC server handle.
 * @param iut_addr            IUT address.
 * @param tst_addr            Tester address.
 * @param sock_type           Socket type.
 * @param bind_wildcard       Bind IUT socket to wildcard address.
 * @param use_existing_socks  If @c TRUE, use already created sockets
 *                            if they are passed to this function
 *                            (i.e. if FD is already >= 0).
 * @param gw_addr             Gateway address or @c NULL, it must be
 *                            specified if IP_TRANSPARENT testing is
 *                            required, otherwise it must be @c NULL.
 * @param iut_s               IUT socket location.
 * @param tst_s               Tester socket location.
 * @param iut_l               IUT listener socket location or @c NULL.
 * @param iut_sock_func       Function to use for creating socket on IUT.
 */
extern void
sockts_connection(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                  const struct sockaddr *iut_addr,
                  const struct sockaddr *tst_addr,
                  sockts_socket_type sock_type, te_bool bind_wildcard,
                  te_bool use_existing_socks,
                  const struct sockaddr *gw_addr, int *iut_s, int *tst_s,
                  int *iut_l,
                  sockts_socket_func iut_sock_func);

#endif /* !__SOCKAPI_TS_ENV_H__ */
