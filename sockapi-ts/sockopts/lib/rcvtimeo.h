/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros for SO_RCVTIMEO socket option tests 
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 *
 * $Id$
 */

/**
 * Check the function executing time and report if
 * not success.
 * All time intervals are measured
 * in microseconds.
 *
 * @param duration_                Time returned by RPC subsystem
 * @param inaccuracy_              Allowed inaccuracy in time measurement,
 *                                 should be TST_TIME_INACCURACY by default
 * @param inaccuracy_multiplier_   Inaccuracy multiplier of the upper bound
 *                                 in time measurement, should be
 *                                 TST_TIME_INACCURACY_MULTIPLIER by default
 * @param min_                     Minimum expected value
 * @param max_                     Maximum expected value
 * @param msg_                     TE macro to report error
 * @param verdict_                 TE macro to report test verdict
 * @param vtext_                   Verdict text
 */
#define CHECK_REPORT_TIMEOUT(duration_, inaccuracy_,       \
                             inaccuracy_multiplier_, min_, \
                             max_, msg_, verdict_, vtext_) \
    do {                                                            \
        CHECK_CALL_DURATION_INT_GEN(duration_, inaccuracy_,         \
                                    inaccuracy_multiplier_, min_,   \
                                    max_, msg_, verdict_, vtext_,   \
                                    "");                            \
    } while (0)

/**
 * Get current value of SO_RCVTIMEO socket option
 * on socket, try to set another value, check that
 * new value was set.
 *
 * @param pco_          RPC server
 * @param sock_         Socket
 * @param timeout_      Variable in which new value of SO_RCVTIMEO socket
 *                      option should be saved
 * @param sock_type_    Type of socket
 */
#define RCVTIMEO_GET_SET_CHECK(pco_, sock_, timeout_, sock_type_); \
    do {                                                                \
        tarpc_timeval opt_val_;                                         \
        RPC_AWAIT_IUT_ERROR(pco_);                                      \
        rc = rpc_getsockopt(pco_, sock_, RPC_SO_RCVTIMEO, &opt_val_);   \
        if (rc != 0)                                                    \
            TEST_VERDICT("getsockopt(SOL_SOCKET, SO_RCVTIMEO) failed "  \
                         "with errno %s",                               \
                         errno_rpc2str(RPC_ERRNO(pco_)));               \
        RING("SO_RCVTIMEO socket option is set to %s by default on %s " \
             "type of socket", tarpc_timeval2str(&opt_val_),            \
             socktype_rpc2str(sock_type_));                             \
        timeout_.tv_sec = rand_range(3, 7);                             \
        timeout_.tv_usec = 0;                                           \
                                                                        \
        /* Set up a new value for SO_RCVTIMEO socket option */          \
        opt_val_ = timeout_;                                            \
        RPC_AWAIT_IUT_ERROR(pco_);                                      \
        rc = rpc_setsockopt(pco_, sock_, RPC_SO_RCVTIMEO, &opt_val_);   \
        if (rc != 0)                                                    \
            TEST_VERDICT("setsockopt(SOL_SOCKET, SO_RCVTIMEO) failed "  \
                         "with errno %s",                               \
                         errno_rpc2str(RPC_ERRNO(pco_)));               \
                                                                        \
        memset(&opt_val_, 0, sizeof(opt_val_));                         \
        rpc_getsockopt(pco_, sock_, RPC_SO_RCVTIMEO, &opt_val_);        \
        if (opt_val_.tv_sec != timeout_.tv_sec ||                       \
            opt_val_.tv_usec != timeout_.tv_usec)                       \
            TEST_FAIL("The value of SO_RCVTIMEO socket option is not "  \
                      "updated by setsockopt() function %d %d",         \
                      opt_val_.tv_sec,                                  \
                      opt_val_.tv_usec);                                \
    } while (0)
