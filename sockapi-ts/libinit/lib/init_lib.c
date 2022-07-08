/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Library _init() function tests
 *
 * Library _init() function tests auxiliary functions
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 *
 * $Id$
 */

#include "sockapi-test.h"
#include "init_lib.h"


/* Description in init_lib.h */
void
libinit_set_agent_env(rcf_rpc_server *rpcs, const char *seq)
{
    char *dst, *env;
    char *buf = NULL;
    int n = 0;
    char *ptr;
    size_t env_len, lib_len;

    dst = libinit_get_agent_destination(rpcs->ta);
    env = rpc_getenv(rpcs, "LD_PRELOAD");
    env_len = (env == RPC_NULL) ? 0 : strlen(env);
    lib_len = (rpcs->nv_lib == RPC_NULL) ? 0 : strlen(rpcs->nv_lib);
    buf = (char *)malloc(env_len + lib_len + strlen(dst) + 3);
    ptr = buf;
    n = sprintf(ptr, "%s", dst);
    ptr += n;
    if (env_len)
    {
        n = sprintf(ptr, ":%s", env);
        ptr += n;
    }
    if (lib_len)
        sprintf(ptr, ":%s", rpcs->nv_lib);

    rpc_setenv(rpcs, "LD_PRELOAD", buf, 1);
    free(buf);

    rpc_setenv(rpcs, "LIBINIT_TEST_SEQ", seq, 1);
    rpc_setenv(rpcs, "TE_LEAVE_SIGINT_HANDLER", "1", 1);

    free(dst);

    return;
}

