/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros and functions for socket tests and agent RPC libraries.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __SOCKAPI_TA_H__
#define __SOCKAPI_TA_H__

#include "extensions.h"

/**
 * Convert error value which can be returned by function
 * @b onload_delegated_send_prepare to string.
 * 
 * @param rc    Error code
 * 
 * @return Constant string with the error name
 */
static inline const char *
ods_prepare_err2string(int rc)
{

#define ERR2STR(name_) \
    case ONLOAD_DELEGATED_SEND_RC_ ## name_: return #name_

    switch (rc)
    {
        ERR2STR(OK);
        ERR2STR(BAD_SOCKET);
        ERR2STR(SMALL_HEADER);
        ERR2STR(SENDQ_BUSY);
        ERR2STR(NOWIN);
        ERR2STR(NOARP);
#ifdef HAVE_DECL_ONLOAD_DELEGATED_SEND_RC_NOCWIN
        /* Supported from the Onload branch eol6 */
        ERR2STR(NOCWIN);
#endif
        default:
            return "UNKNOWN";
    }

#undef ERR2STR

    return "UNKNOWN";
}

/* Header length which is enoungh for using it with OD send API. */
#define OD_HEADERS_LEN 200

/**
 * Get maximum segemnt size which can be sent next with OD API.
 * 
 * @param ods   Onload delegated API context
 * 
 * @return Maximum segment size.
 */
static inline int
od_get_min(struct onload_delegated_send *ods)
{
    int min = ods->user_size;

    if (min > ods->mss)
        min = ods->mss;
    if (min > ods->send_wnd)
        min = ods->send_wnd;
    if (min > ods->cong_wnd)
        min = ods->cong_wnd;

    RING("ods->user_size %d, ods->mss %d, ods->send_wnd %d, "
         "ods->cong_wnd %d: %d", ods->user_size, ods->mss, ods->send_wnd,
         ods->cong_wnd, min);

    return min;
}


#endif /* __SOCKAPI_TA_H__ */
