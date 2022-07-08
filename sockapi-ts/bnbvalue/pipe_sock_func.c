/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-pipe_sock_func Using socket functions with pipe
 *
 * @objective Check that it is not possible to use socket functions
 *            with pipe
 *
 * @type conformance, robustness
 *
 * @param pco_iut       PCO on IUT
 * @param write_end     Whether to test write or read end of pipe
 * @param func          Socket function to be tested
 *
 * @par Scenario:
 *  -# Create a pipe.
 *  -# Call @p func on its end selected according to @p write_end.
 *  -# Check that @c -1 with errno @c ENOTSOCK is returned.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/pipe_sock_func"

#include "sockapi-test.h"

#define BUF_SIZE 1024

enum {
    FUNC_BIND,
    FUNC_CONNECT,
    FUNC_LISTEN,
    FUNC_ACCEPT,
    FUNC_GETSOCKNAME,
    FUNC_GETPEERNAME,
    FUNC_SHUTDOWN,
};

#define SOCK_FUNCS \
    {"bind", FUNC_BIND},                \
    {"connect", FUNC_CONNECT},          \
    {"listen", FUNC_LISTEN},            \
    {"accept", FUNC_ACCEPT},            \
    {"getsockname", FUNC_GETSOCKNAME},  \
    {"getpeername", FUNC_GETPEERNAME},  \
    {"shutdown", FUNC_SHUTDOWN}

#define CALL_FUNC(func_) \
    do {                                                            \
        te_bool done_;                                              \
                                                                    \
        pco_iut->op = RCF_RPC_CALL;                                 \
        func_;                                                      \
        MSLEEP(500);                                                \
        if (!rcf_rpc_server_is_alive(pco_iut))                      \
        {                                                           \
            pipefds[0] = -1;                                        \
            pipefds[1] = -1;                                        \
            rcf_rpc_server_restart(pco_iut);                        \
            TEST_VERDICT("Function call results in death "          \
                         "of RPC server");                          \
        }                                                           \
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done_));       \
        if (!done_)                                                 \
        {                                                           \
            pipefds[0] = -1;                                        \
            pipefds[1] = -1;                                        \
            rcf_rpc_server_restart(pco_iut);                        \
            TEST_VERDICT("Function call is blocked on pipe");       \
        }                                                           \
        pco_iut->op = RCF_RPC_WAIT;                                 \
        RPC_AWAIT_IUT_ERROR(pco_iut);                               \
        rc = func_;                                                 \
        if (rc == 0)                                                \
            TEST_VERDICT("Function call successes on pipe");        \
        else if (RPC_ERRNO(pco_iut) != RPC_ENOTSOCK)                \
            RING_VERDICT("Function call failed with errno %s",      \
                         errno_rpc2str(RPC_ERRNO(pco_iut)));        \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server          *pco_iut = NULL;
    const struct sockaddr   *iut_addr = NULL;

    struct sockaddr          addr;
    socklen_t                addr_len;
    rpc_shut_how             shutdown_how = RPC_SHUT_NONE;

    int         pipefds[2] = { -1, -1 };
    te_bool     is_failed = FALSE;
    te_bool     write_end = FALSE;
    int         func;
    int         test_fd = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ENUM_PARAM(func, SOCK_FUNCS);
    if (func == FUNC_SHUTDOWN)
        TEST_GET_SHUT_HOW(shutdown_how);

    rpc_pipe(pco_iut, pipefds);
    test_fd = (write_end ? pipefds[1] : pipefds[0]);

    memset(&addr, 0, sizeof(addr));
    addr_len = sizeof(addr);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    switch(func)
    {
        case FUNC_BIND:
            CALL_FUNC(rpc_bind(pco_iut, test_fd, iut_addr));
            break;

        case FUNC_CONNECT:
            CALL_FUNC(rpc_connect(pco_iut, test_fd, iut_addr));
            break;

        case FUNC_LISTEN:
            CALL_FUNC(rpc_listen(pco_iut, test_fd, SOCKTS_BACKLOG_DEF));
            break;

        case FUNC_ACCEPT:
            CALL_FUNC(rpc_accept(pco_iut, test_fd, NULL, NULL));
            break;

        case FUNC_GETSOCKNAME:
            CALL_FUNC(rpc_getsockname(pco_iut, test_fd, &addr, &addr_len));
            break;

        case FUNC_GETPEERNAME:
            CALL_FUNC(rpc_getpeername(pco_iut, test_fd, &addr, &addr_len));
            break;

        case FUNC_SHUTDOWN:
            CALL_FUNC(rpc_shutdown(pco_iut, test_fd, shutdown_how));
            break;
    }

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);

    TEST_END;
}
