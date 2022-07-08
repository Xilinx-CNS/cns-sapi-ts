/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Auxiliary test API for RPC servers
 *
 * Auxilliary test API to work with RPC servers.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#ifndef __SOCKAPI_TS_RPCS_H__
#define __SOCKAPI_TS_RPCS_H__

#include "te_errno.h"

/**
 * List of RPC server handles with auxiliary data.
 */
typedef struct sockts_rpcs {
    rcf_rpc_server *rpcs;       /**< RPC server */
    int             sock;       /**< A socket descriptor */
    SLIST_ENTRY(sockts_rpcs) link;
} sockts_rpcs;

/** Header of RPC servers list. */
SLIST_HEAD(sockts_rpcs_h, sockts_rpcs);
typedef struct sockts_rpcs_h sockts_rpcs_h;

/**
 * Get RPC server handle, create it if there is no RPC server for @p ta.
 *
 * @param ta        Test agent name
 * @param rpcs_h    Head of RPC servers list
 * @param rpcs      RPC server handle location
 *
 * @return Status code.
 */
extern te_errno sockts_rpcs_get(const char *ta, sockts_rpcs_h *rpcs_h,
                                sockts_rpcs **rpcs);

/**
 * Initialize RPC servers list.
 *
 * @param rpcs_h    Head of RPC servers list
 */
extern void sockts_rpcs_init(sockts_rpcs_h *rpcs_h);

/**
 * Release RPC servers list destroying RPC servers and auxiliary resources.
 *
 * @param rpcs_h    Head of RPC servers list
 *
 * @return Status code.
 */
extern te_errno sockts_rpcs_release(sockts_rpcs_h *rpcs_h);

#endif /* !__SOCKAPI_TS_RPCS_H__ */
