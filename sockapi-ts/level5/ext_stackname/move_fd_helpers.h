/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros and functions for calling and checking
 * onload_move_fd().
 *
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __LEVEL5_EXTENSIONS_MOVE_FD_HELPERS_H__
#define __LEVEL5_EXTENSIONS_MOVE_FD_HELPERS_H__

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

/**
 * Establish a TCP connection, using already created and bound socket
 * if necessary.
 *
 * @param rpcs1                 RPC server 1 handle
 * @param addr1                 Network address on RPC server 1
 * @param rpcs2                 RPC server 2 handle
 * @param addr2                 Network address on RPC server 2
 * @param s1_create             Whether we should create a socket
 *                              on RPC server 1
 * @param s1_bind               Whether we should bind a socket
 *                              on RPC server 1
 * @param s1_nonblock           Whether a socket on RPC server 1
 *                              supplied is in non-blocking mode
 * @param s1_passive            Whether TCP connection should be
 *                              opened passively in relation to
 *                              the socket on RPC server 1
 * @param s1          [in,out]  Socket on RPC server 1
 * @param s1_accepted [out]     Socket returned by @b accept() on
 *                              RPC server 1 (may be NULL if
 *                              @p s1_passive is @c FALSE)
 * @param s2          [out]     Socket on RPC server 2
 * @param s2_accepted [out]     Socket returned by @b accept() on
 *                              RPC server 2 (may be NULL if
 *                              @o s1_passive is @c TRUE)
 *
 * @return @c TRUE on success, @c FALSE on failure
 */
static inline te_bool
gen_tcp_conn_with_sock(rcf_rpc_server *rpcs1,
                       const struct sockaddr *addr1,
                       rcf_rpc_server *rpcs2,
                       const struct sockaddr *addr2,
                       te_bool s1_create,
                       te_bool s1_bind,
                       te_bool s1_nonblock,
                       te_bool s1_passive,
                       int *s1,
                       int *s1_accepted,
                       int *s2,
                       int *s2_accepted)
{
    te_bool success = TRUE;
    int     rc;

    assert(s1 != NULL);
    assert(s2 != NULL);

    if (s1_create)
        *s1 = rpc_socket(rpcs1, rpc_socket_domain_by_addr(addr1),
                         RPC_SOCK_STREAM,
                         RPC_PROTO_DEF);

    if (s1_bind)
        rpc_bind(rpcs1, *s1, addr1);

    *s2 = rpc_create_and_bind_socket(rpcs2, RPC_SOCK_STREAM,
                                     RPC_PROTO_DEF,
                                     FALSE, FALSE,
                                     addr2);

    if (s1_passive)
    {
        assert(s1_accepted != NULL);
        rpc_listen(rpcs1, *s1, SOCKTS_BACKLOG_DEF);
        rpc_connect(rpcs2, *s2, addr1);
        *s1_accepted = rpc_accept(rpcs1, *s1, NULL, NULL);
    }
    else
    {
        assert(s2_accepted != NULL);
        rpc_listen(rpcs2, *s2, SOCKTS_BACKLOG_DEF);
        if (s1_nonblock)
        {
            RPC_AWAIT_IUT_ERROR(rpcs1);
            rc = rpc_connect(rpcs1, *s1, addr2);
            if (rc < 0 && RPC_ERRNO(rpcs1) != RPC_EINPROGRESS)
            {
                ERROR_VERDICT("Non-blocking connect failed with "
                              "strange errno %s",
                              errno_rpc2str(RPC_ERRNO(rpcs1)));
                success = FALSE;
            }
            TAPI_WAIT_NETWORK;
        }
        else
            rpc_connect(rpcs1, *s1, addr2);

        *s2_accepted = rpc_accept(rpcs2, *s2, NULL, NULL);
    }

    return success;
}

/**
 * Call @b onload_set_stackname() and create a new socket to create
 * a new stack if necessary.
 *
 * @param rpcs              RPC server handle
 * @param who               @p Who parameter of @b onload_set_stackname()
 * @param scope             @p Scope parameter of @b onload_set_stackname()
 * @param stack_name        Stack name to be set
 * @param create_stack      Whether to create a new stack or not
 * @param s_aux             Where to save auxiliary socket fd used to
 *                          create a stack
 */
static inline void
tapi_rpc_onload_set_stackname_create(rcf_rpc_server *rpcs,
                                     int who, int scope,
                                     const char *stack_name,
                                     te_bool create_stack,
                                     int *s_aux)
{
    rpc_onload_set_stackname(rpcs, who, scope, stack_name);
    if (create_stack)
    {
        tarpc_onload_stat       ostat;

        assert(s_aux != NULL);

        if (*s_aux >= 0)
            rpc_close(rpcs, *s_aux);
        *s_aux = rpc_socket(rpcs, RPC_AF_INET, RPC_SOCK_STREAM,
                            RPC_PROTO_DEF);
        rpc_onload_fd_stat(rpcs, *s_aux, &ostat);
        if (!ostat_stack_name_match_str(&ostat, stack_name))
            TEST_FAIL("Failed to set a new stack name properly");
    }
}

#define TAPI_MOVE_FD_FAILURE_EXPECTED TRUE
#define TAPI_MOVE_FD_SUCCESS_EXPECTED FALSE

/**
 * Call @b onload_move_fd() and check result.
 *
 * @param rpcs            RPC server handle
 * @param s               Socked fd
 * @param fail_expected   Whether @b onload_move_fd() call is expected
 *                        to fail or not
 * @param stack_name      Stack name to check
 * @param msg             Introductory part of verdicts, if required
 *
 * @return @c TRUE on success, @c FALSE on failure
 */
static inline te_bool
tapi_rpc_onload_move_fd_check(rcf_rpc_server *rpcs, int s,
                              te_bool fail_expected,
                              const char *stack_name,
                              const char *msg)
{
#define ERROR_VERDICT_MSG(text_, msg_) \
    ERROR_VERDICT("%s%s" text_, \
                  (msg_ == NULL ? "" : msg_), \
                  (msg_ == NULL ? "" : ": "))

    int                     rc;
    tarpc_onload_stat       ostat1;
    tarpc_onload_stat       ostat2;
    te_bool                 succeeded = TRUE;

    rpc_onload_fd_stat(rpcs, s, &ostat1);
    RPC_AWAIT_IUT_ERROR(rpcs);
    rc = rpc_onload_move_fd(rpcs, s);
    if (rc < 0)
    {
        if (!fail_expected)
        {
            ERROR_VERDICT_MSG("onload_move_fd() failed unexpectedly",
                              msg);
            succeeded = FALSE;
        }

        rpc_onload_fd_stat(rpcs, s, &ostat2);
        if (!ostat_stack_names_match(&ostat1, &ostat2))
        {
            ERROR_VERDICT_MSG("onload_move_fd() failed "
                              "but stack name changed", msg);   
            succeeded = FALSE;
        }
    }
    else
    {
        if (fail_expected)
        {
            ERROR_VERDICT_MSG("onload_move_fd() succeeded unexpectedly",
                              msg);
            succeeded = FALSE;
        }

        rpc_onload_fd_stat(rpcs, s, &ostat2);
        if (ostat_stack_names_match(&ostat1, &ostat2) &&
            !ostat_stack_name_match_str(&ostat1, stack_name))
        {
            ERROR_VERDICT_MSG("onload_move_fd() succeeded but stack "
                              "name remained the same", msg);
            succeeded = FALSE;
        }
        else if (!ostat_stack_name_match_str(&ostat2, stack_name))
        {
            ERROR_VERDICT_MSG("onload_move_fd() succeeded but stack "
                              "name has unexpected value", msg);
            succeeded = FALSE;
        }
    }

    return succeeded;
#undef ERROR_VERDICT_MSG
}

#endif /* __LEVEL5_EXTENSIONS_MOVE_FD_HELPERS_H__ */
