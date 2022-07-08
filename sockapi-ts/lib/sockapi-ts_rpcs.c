/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Auxiliary test API for RPC servers
 *
 * Implementation of auxilliary functions to work with RPC servers.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_LGR_USER     "Sockts RPCs"

#include "sockapi-ts.h"
#include "sockapi-ts_rpcs.h"

/* See description in sockapi-ts_rpcs.h */
te_errno
sockts_rpcs_get(const char *ta, sockts_rpcs_h *rpcs_h, sockts_rpcs **rpcs)
{
    sockts_rpcs *srpc;
    te_errno     rc;

    SLIST_FOREACH(srpc, rpcs_h, link)
    {
        if (strcmp(srpc->rpcs->ta, ta) == 0)
        {
            *rpcs = srpc;
            return 0;
        }
    }

    srpc = TE_ALLOC(sizeof(*srpc));
    if (srpc == NULL)
        return TE_RC(TE_TAPI, TE_ENOMEM);

    rc = rcf_rpc_server_create(ta, "aux_rpc_server", &srpc->rpcs);
    if (rc != 0)
    {
        free(srpc);
        return rc;
    }

    srpc->sock = -1;

    SLIST_INSERT_HEAD(rpcs_h, srpc, link);
    *rpcs = srpc;

    return 0;
}

/* See description in sockapi-ts_rpcs.h */
void
sockts_rpcs_init(sockts_rpcs_h *rpcs_h)
{
    SLIST_INIT(rpcs_h);
}

/* See description in sockapi-ts_rpcs.h */
te_errno
sockts_rpcs_release(sockts_rpcs_h *rpcs_h)
{
    sockts_rpcs *srpc;
    te_errno     rc = 0;
    te_errno     rc2;

    while((srpc = SLIST_FIRST(rpcs_h)) != NULL)
    {
        if (srpc->sock >= 0)
        {
            int res;

            RPC_AWAIT_IUT_ERROR(srpc->rpcs);
            res = rpc_close(srpc->rpcs, srpc->sock);
            if (res != 0)
            {
                ERROR("close() failed: %r", RPC_ERRNO(srpc->rpcs));
                if (rc == 0)
                    rc = TE_RC(TE_TAPI, TE_EFAIL);
            }
        }

        rc2 = rcf_rpc_server_destroy(srpc->rpcs);
        if (rc == 0)
            rc = rc2;
        SLIST_REMOVE_HEAD(rpcs_h, link);
        free(srpc);
    }

    return rc;
}
