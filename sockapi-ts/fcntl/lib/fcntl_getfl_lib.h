/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Macros for fcntl_getfl and fcntl_getfl_pipe tests.
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_FCNTL_GETFL_LIB_H__
#define __TS_FCNTL_GETFL_LIB_H__

#include "sockapi-test.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check that file state flags for file descriptor are same as expected.
 *
 * @param _pco          PCO
 * @param _fd           file descriptor
 * @param _exp_flags    expected flags
 */
#define FCNTL_GETFL_TEST_FLAGS(_pco, _fd, _exp_flags)  \
    do {                                                                 \
        int flags = rpc_fcntl(_pco, _fd, RPC_F_GETFL, 0);                \
        if (flags != _exp_flags)                                         \
        {                                                                \
            if ((~flags & _exp_flags) != 0)                              \
                RING_VERDICT("Flags are missing: %s",                    \
                             fcntl_flags_rpc2str(~flags & _exp_flags));  \
            if ((flags & ~_exp_flags) != 0)                              \
                RING_VERDICT("Unexpected flags set: %s",                 \
                             fcntl_flags_rpc2str(flags & ~_exp_flags));  \
            TEST_FAIL("Incorrect flags are set for file decriptor %s",   \
                                                                  #_fd); \
        }                                                                \
    } while (0)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __TS_MCAST_LIB_H__ */
