/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 * 
 * Function, that is used in a group of tests from IP Multicasting
 * package. Some structures used in it.
 *  
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 * 
 * $Id$
 */

#include "sockapi-ts.h"


#ifndef __LIB_MULTICAST_H__
#define __LIB_MULTICAST_H__

/**
 * The list of values allowed for parameter of type 'mcast_oining_method'
 */
#define MCAST_METHOD_FUNC_MAPPING_LIST \
    { "add_drop", TARPC_MCAST_ADD_DROP },     \
    { "join_leave", TARPC_MCAST_JOIN_LEAVE },   \
    { "source_add_drop", TARPC_MCAST_SOURCE_ADD_DROP },     \
    { "source_join_leave", TARPC_MCAST_SOURCE_JOIN_LEAVE }

/**
 * Get the value of parameter of type 'mcast_oining_method'
 *
 * @param var_name_  Name of the variable used to get the value of
 *                   "var_name_" parameter of type 'mcast_oining_method' (OUT)
 */
#define TEST_GET_MCAST_METHOD(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, MCAST_METHOD_FUNC_MAPPING_LIST) 

/**
 * Leave multicast group in a cleanup part of test
 *
 * @param _pco          PCO
 * @param _s            Socket
 * @param _addr         Multicast address
 * @param _if_ind       Interface index
 * @param _method       Method used to join/leave multicast group
 */
#define CLEANUP_MULTICAST_LEAVE(_pco, _s, _addr, _if_ind, _method) \
    do {                                                            \
        if (rpc_mcast_leave(_pco, _s, _addr,                        \
                            _if_ind, _method) != 0)                 \
        {                                                           \
            ERROR("Cannot leave multicast group");                  \
            MACRO_TEST_ERROR;                                       \
        }                                                           \
    } while (0)

/**
 * Set IP_MULTICAST_IF for the provided socket
 * 
 * @param rpcs  RPC server
 * @param sock  Socket to set option
 * @param addr  Address to set
 */
static inline void
set_ip_multicast_if(rcf_rpc_server *rpcs, int sock,
                    const struct sockaddr *addr)
{
    struct tarpc_mreqn  mreq;

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(addr),
           sizeof(mreq.address));
    rpc_setsockopt(rpcs, sock, RPC_IP_MULTICAST_IF, &mreq);
}

/**
 * Set @c IP_MULTICAST_IF / @c IPV6_MULTICAST_IF socket option.
 *
 * @param rpcs      RPC server.
 * @param sock      Socket on which to set option.
 * @param af        Address family (@c AF_INET or @c AF_INET6).
 * @param if_index  Index of the target interface (on IPv4 used
 *                  if @p addr is @c NULL).
 *
 * @return @c 0 on success, @c -1 on failure. In case of failure
 *         RPC errno is set.
 */
static inline int
sockts_set_multicast_if(rcf_rpc_server *rpcs, int sock,
                        int af, unsigned int if_index)
{
    switch (af)
    {
        case AF_INET:
        {
            struct tarpc_mreqn  mreq;

            memset(&mreq, 0, sizeof(mreq));
            mreq.type = OPT_MREQN;
            mreq.ifindex = if_index;

            return rpc_setsockopt(rpcs, sock, RPC_IP_MULTICAST_IF, &mreq);
        }

        case AF_INET6:
            return rpc_setsockopt_int(rpcs, sock, RPC_IPV6_MULTICAST_IF,
                                      if_index);
    }

    ERROR("%s(): not supported address family %d", __FUNCTION__, af);
    rpcs->_errno = TE_RC(TE_TAPI, TE_EINVAL);
    return -1;
}

#endif
