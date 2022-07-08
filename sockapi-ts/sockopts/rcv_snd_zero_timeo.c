/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/**
 * @page sockopts-rcv_snd_zero_timeo Usage of SO_RCVTIMEO and SO_SNDTIMEO with zero value
 *
 * @objective Check that @c SO_RCVTIMEO and @c SO_SNDTIMEO are correctly updated by zero value
 *
 * @param env        Testing environment:
 *                   - @ref arg_types_env_iut_only
 * @param sock_type  Type of socket
 *                   - @c SOCK_STREAM
 *                   - @c SOCK_DGRAM
 * @param sock_type  Socket domain
 *                   - @c PF_INET
 *                   - @c PF_INET6
 *
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "sockopts/rcv_snd_zero_timeo"

#include "sockapi-test.h"

/**
 * Set a new value of @c SO_RCVTIMEO or @c SO_SNDTIMEO socket option
 * on socket, check that new value was set.
 *
 * @param pco_           RPC server
 * @param sock_          Socket to set socket option on it
 * @param sock_type_     Type of socket
 * @param zero_timeout_  Set zerotimeout
 */
#define TIMEO_GET_SET_CHECK(pco_, sock_, sockopt_, zero_timeout_) \
    do {                                                                \
        tarpc_timeval opt_val;                                          \
        tarpc_timeval timeout;                                          \
        /* Some random non-zero values for timeout */                   \
        timeout.tv_sec = (zero_timeout_) ? 0 : rand_range(3, 7);        \
        timeout.tv_usec = 0;                                            \
        RPC_AWAIT_IUT_ERROR(pco_);                                      \
        rc = rpc_setsockopt((pco_), (sock_), (sockopt_), &timeout);     \
        if (rc != 0)                                                    \
            TEST_VERDICT("setsockopt(SOL_SOCKET, %s) failed "           \
                         "with errno %s",                               \
                         #sockopt_, errno_rpc2str(RPC_ERRNO(pco_)));    \
                                                                        \
        memset(&opt_val, 0, sizeof(opt_val));                           \
        RPC_AWAIT_IUT_ERROR(pco_);                                      \
        rc = rpc_getsockopt((pco_), (sock_), (sockopt_), &opt_val);     \
        if (rc != 0)                                                    \
            TEST_VERDICT("getsockopt(SOL_SOCKET, %s) failed "           \
                         "with errno %s",                               \
                         #sockopt_, errno_rpc2str(RPC_ERRNO(pco_)));    \
        if (opt_val.tv_sec != timeout.tv_sec ||                         \
            opt_val.tv_usec != timeout.tv_usec)                         \
            TEST_VERDICT("The value of %s socket option is "            \
                         "%d %d, but %d %d is expected.",               \
                          #sockopt_, opt_val.tv_sec, opt_val.tv_usec,   \
                          timeout.tv_sec, timeout.tv_usec);             \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server   *pco_iut = NULL;
    rpc_socket_type   sock_type;
    int               iut_s = -1;
    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_DOMAIN(domain);

    TEST_STEP("Create @p sock_type type socket on @p pco_iut");
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    TEST_STEP("Set non-zero value for @c SO_RCVTIMEO option and check that the value "
              "was correctly updated.");
    TIMEO_GET_SET_CHECK(pco_iut, iut_s, RPC_SO_RCVTIMEO, FALSE);

    TEST_STEP("Set zero value for @c SO_RCVTIMEO option and check that the value "
              "was correctly updated.");
    TIMEO_GET_SET_CHECK(pco_iut, iut_s, RPC_SO_RCVTIMEO, TRUE);

    TEST_STEP("Set non-zero value for @c SO_SNDTIMEO option and check that the value "
              "was correctly updated.");
    TIMEO_GET_SET_CHECK(pco_iut, iut_s, RPC_SO_SNDTIMEO, FALSE);

    TEST_STEP("Set zero value for @c SO_SNDTIMEO option and check that the value "
              "was correctly updated.");
    TIMEO_GET_SET_CHECK(pco_iut, iut_s, RPC_SO_SNDTIMEO, TRUE);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
