/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Macros to be used in tests. The header must be included from test
 * sources only. It is allowed to use the macros only from @b main()
 * function of the test.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_SOCKAPI_TEST_H__
#define __TS_SOCKAPI_TEST_H__

#include "te_config.h"


#ifndef TEST_START_VARS
/**
 * Test suite specific variables of the test @b main() function.
 */
#define TEST_START_VARS TEST_START_ENV_VARS
#endif

#ifndef TEST_START_SPECIFIC
/**
 * Test suite specific the first actions of the test.
 */
#define TEST_START_SPECIFIC     \
do {                                                                        \
    CHECK_RC(rcf_rpc_server_hook_register(use_syscall_rpc_server_hook));    \
    TEST_START_ENV;                                                         \
    if (tapi_getenv_bool("IUT_NO_CHECK_MSG_FLAGS_IN_RPC"))                  \
        tapi_rpc_msghdr_msg_flags_init_check(FALSE);                        \
} while (0)
#endif

#ifndef TEST_END_SPECIFIC
/**
 * Test suite specific part of the last action of the test @b main()
 * function.
 */
#define TEST_END_SPECIFIC TEST_END_ENV
#endif

#include "tapi_test.h"
#include "sockapi-ts.h"
#include "sockapi-params.h"
#include "sockapi-ts_env.h"


#endif /* !__TS_SOCKAPI_TEST_H__ */
