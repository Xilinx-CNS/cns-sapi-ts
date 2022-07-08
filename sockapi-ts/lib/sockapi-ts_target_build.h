/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief API to compile files on engine/agent
 *
 * API to compile files on engine/agent
 *
 * @author Vasilii Ivanov <swaotet@oktetlabs.ru>
 */
#ifndef __SOCKAPI_TS_TARGET_BUILD_H__
#define __SOCKAPI_TS_TARGET_BUILD_H__

#include "sockapi-test.h"
#include "tapi_test.h"
#include "tapi_cfg.h"
#include "conf_api.h"
#include "te_shell_cmd.h"
#include <sys/wait.h>

/** Buffer size for reading from stdout and stderr */
#define COMMON_CMD_BUF_SIZE 4096

/** Archive name */
#define SOCKTS_TMP_TGZ_NAME "target_build_archive.tgz"

/**
 * Macros to check errno return value.
 *
 * @param ret    Status code
 *
 */
#define CHECK_ERRNO_RET(ret) \
    do {                                                                \
        if ((ret) != 0)                                                 \
        {                                                               \
            ERROR("%s() on line %d returned unexpected status %d",      \
                  __FUNCTION__, __LINE__, ret);                         \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build files from @p src_dir on agent @p pco in @p dst_dir directory.
 *
 * @param pco                       RPC server
 * @param src_dir                   Path to directory with source files
 * @param dst_dir                   Path to test agent directory
 * @param build_on_engine           true  if directory should be built on engine
 *                                  false if directory should be built on agent
 *
 * @return                          Status code
 */
extern te_errno
sockts_build_dir(rcf_rpc_server *pco, const char *src_dir,
                 const char *dst_dir, te_bool build_on_engine);
/**
 * Cleanup after build on engine/agent
 *
 * @param src_dir                   Path to directory with source files
 * @param build_on_engine           @c TRUE if directory was built on engine
 *                                  @c FALSE if directory was built on agent
 *
 * @return                          Status code
 */
extern te_errno
sockts_cleanup_build(const char *src_dir, te_bool build_on_engine);

#ifdef __cplusplus
}
#endif

#endif /* !__SOCKAPI_TS_TARGET_BUILD_H__ */
