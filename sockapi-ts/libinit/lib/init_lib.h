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

#ifndef __TS_INIT_LIB_H__
#define __TS_INIT_LIB_H__

#include "sockapi-test.h"

#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_test.h"

#include "conf_api.h"
#include "tapi_rpc.h"


#define LIBINIT_BUF_LEN     256
#define TA_TMP_PATH         "/tmp/"

#ifdef __cplusplus
extern "C" {
#endif
/**
 * For test scenarios which success depends on a child's return code
 * (currently such scenarios are socket iterations of thread_fork and all
 * iterations of atfork), this macro waits for child with pid specified
 * by _pid parameter. The value of rc is set accordingly.
 *
 * @param _pco          PCO on IUT
 * @paran _sequence     Sequence name
 * @param _iteration    Iteration name
 * @param _pid          pid of child to wait for
 *
 */
#define LIBINIT_WAIT_CHILD(_pco, _sequence, _iteration,  _pid)    \
    do {                                                            \
        rpc_wait_status status;                                     \
        if (((strcmp(_sequence, "thread_fork") == 0) &&             \
             (strcmp(_iteration, "WRITE_ON_PIPE") != 0)) ||         \
            (strcmp(_sequence, "atfork") == 0))                     \
        {                                                           \
            if ((rpc_waitpid(_pco, _pid, &status, 0) <= 0) ||       \
                (status.flag != RPC_WAIT_STATUS_EXITED))            \
                TEST_FAIL("Failed to wait for child process");      \
            rc = status.value;                                      \
        }                                                           \
    } while (0)

/**
 * Set LD_PRELOAD and LIBINIT_TEST_SEQ environment variables on agent.
 */
extern void libinit_set_agent_env(rcf_rpc_server *rpcs, const char *seq);

/**
 * Get the destination path for libinit_test.so on Test Agent.
 *
 * @param ta        Test Agent name
 *
 * @return String containing destination path for libinit_test.so.
 */
static inline char *libinit_get_agent_destination(const char *ta)
{
    char *path;
    char *agt_dir;

    CHECK_RC(cfg_get_instance_fmt(NULL, &agt_dir, "/agent:%s/dir:", ta));

    path = tapi_calloc(1, RCF_MAX_PATH);
    CHECK_RC(te_snprintf(path, RCF_MAX_PATH, "%s/%s", agt_dir,
                         "libinit_test.so"));

    return path;
}

/**
 * Make dlopen(libinit_test) call.
 *
 * @param rpcs      RPC server handle
 * @param lazy      Use dlopen() with RTLD_LAZY or RTLD_NOW
 *
 * @return dynamic library handle
 */
static inline rpc_dlhandle libinit_dlopen(rcf_rpc_server *rpcs,
                                          te_bool lazy)
{
    char           *path = NULL;
    rpc_dlhandle    handle;

    path = libinit_get_agent_destination(rpcs->ta);
    handle = rpc_dlopen(rpcs, path, lazy ? RPC_RTLD_LAZY : RPC_RTLD_NOW);
    if (handle == RPC_DLHANDLE_NULL)
        TEST_FAIL("dlopen() failed with following error: %s",
                  rpc_dlerror(rpcs));
    if (path != NULL)
        free(path);
    return handle;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* __TS_INIT_LIB_H__ */
