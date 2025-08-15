/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Advanced Micro Devices, Inc. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/**
 * @page bnbvalue-func_splice_nonconn_dgram Using splice() operation on non-connected SOCK_DGRAM sockets
 *
 * @objective Check that @b splice() function correctly handles situation with
 *            not connected @c SOCK_DGRAM sockets.
 *
 * @type conformance, robustness
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_iut_ucast
 *                          - @ref arg_types_env_iut_ucast_ipv6
 * @param blocking_sock     Whether the socket should be blocked.
 * @param blocking_pipe     Whether the pipe should be blocked.
 * @param blocking_splice   Whether the splice should be blocked.
 * @param bound_socket      Whether the socket should be bound.
 * @param pipe_with_data    Whether the pipe should have data.
 * @param set_move          Whether to call splice with @c SPLICE_F_MOVE
 *                          flag or not.
 * @param use_sock_as_in    Whether the socket should be used as in FD.
 * @param zero_tx_buf_len   Whether tx buffer length should be zero.
 * @param unblock_same_sock For blocked socket should we unblock the socket
 *                          with trying to connect it to itself.
 *
 * @par Scenario:
 *
 * @author Nikolai Kosovskii <Nikolai.Kosovskii@arknetworks.am>
 */

#define TE_TEST_NAME  "bnbvalue/func_splice_nonconn_dgram"

#include "sockapi-test.h"

#define DEFAULT_TX_BUF_LEN 65536

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_aux = NULL;
    const struct sockaddr *iut_addr;
    struct sockaddr_storage aux_addr;

    rpc_socket_domain domain;

    int iut_socket = -1;
    int aux_socket = -1;

    int expected_errno = 0;
    int flags = 0;
    size_t tx_buf_len;
    int fd[2];
    te_bool set_move;
    te_bool blocking_sock;
    te_bool blocking_pipe;
    te_bool blocking_splice;
    te_bool bound_socket;
    te_bool pipe_with_data;
    te_bool use_sock_as_in;
    te_bool zero_tx_buf_len;
    te_bool unblock_same_sock;
    te_bool blocked_splice = FALSE;
    int fd_in;
    int fd_out;
    const char *msg = "Test data";
    int i;
    te_bool splice_is_completed;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(blocking_sock);
    TEST_GET_BOOL_PARAM(blocking_pipe);
    TEST_GET_BOOL_PARAM(blocking_splice);
    TEST_GET_BOOL_PARAM(bound_socket);
    TEST_GET_BOOL_PARAM(pipe_with_data);
    TEST_GET_BOOL_PARAM(set_move);
    TEST_GET_BOOL_PARAM(use_sock_as_in);
    TEST_GET_BOOL_PARAM(zero_tx_buf_len);
    TEST_GET_BOOL_PARAM(unblock_same_sock);

    if (use_sock_as_in && pipe_with_data)
        TEST_FAIL("Pipe couldn't be with data if socket is used as in");

    if (unblock_same_sock && !(use_sock_as_in && !pipe_with_data &&
                               !zero_tx_buf_len && blocking_sock))
        TEST_FAIL("Socket would be unblocked only if it is blocked");

    if (!zero_tx_buf_len && !pipe_with_data &&
        ((!use_sock_as_in && blocking_pipe && blocking_splice) ||
         (use_sock_as_in && blocking_sock)))
    {
        blocked_splice = TRUE;
    }

    if (blocked_splice)
    {
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "iut_thread",
                                              &pco_aux));
        if (!unblock_same_sock)
            tapi_sockaddr_clone(pco_iut, iut_addr, &aux_addr);
    }

    domain = rpc_socket_domain_by_addr(iut_addr);

    tx_buf_len = zero_tx_buf_len ? 0 : DEFAULT_TX_BUF_LEN;
    iut_socket = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("If @p blocking_sock is @c FALSE, set nonblocking state "
              "for the socket");
    if (!blocking_sock)
        CHECK_RC(rpc_fcntl(pco_iut, iut_socket, RPC_F_SETFL, RPC_O_NONBLOCK));

    TEST_STEP("If @p bound_socket is @c TRUE, bind the socket");
    if (bound_socket)
        CHECK_RC(rpc_bind(pco_iut, iut_socket, iut_addr));

    TEST_STEP("Create a pipe");

    fd[0] = fd[1] = -1;
    CHECK_RC(rpc_pipe(pco_iut, fd));

    TEST_STEP("If @p blocking_pipe is @c FALSE, set nonblocking state "
              "for both ends of the pipe");
    if (!blocking_pipe)
    {
        for (i = 0; i < 2; i++)
        {
            flags = rpc_fcntl(pco_iut, fd[i], RPC_F_GETFL);
            CHECK_RC(rpc_fcntl(pco_iut, fd[i], RPC_F_SETFL,
                               flags | RPC_O_NONBLOCK));
        }
    }

    fd_in = use_sock_as_in ? iut_socket : fd[0];
    fd_out = use_sock_as_in ? fd[1] : iut_socket;

    TEST_STEP("If @p pipe_with_data is @c TRUE, write a data to the pipe");
    if (pipe_with_data)
    {
        RPC_WRITE(rc, pco_iut, fd[1], msg, strlen(msg) + 1);
    }
    RPC_AWAIT_IUT_ERROR(pco_iut);

    TEST_STEP("Call @b splice() with @p iut_socket socket and with read/write "
              "end on the pipe");

    if (pipe_with_data)
        expected_errno = TE_RC(TE_RPC, TE_EDESTADDRREQ);
    else
        expected_errno = TE_RC(TE_RPC, TE_EAGAIN);

    flags = (blocking_splice ? 0 : SPLICE_F_NONBLOCK) |
            (set_move ? RPC_SPLICE_F_MOVE : 0);

    pco_iut->op = RCF_RPC_CALL;
    CHECK_RC(rpc_splice(pco_iut, fd_in, NULL, fd_out, NULL, tx_buf_len,
             flags));
    TAPI_WAIT_NETWORK;
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &splice_is_completed));

    if (!splice_is_completed)
    {
        if (!blocked_splice)
            TEST_VERDICT("splice() is unexpectedly blocked");

        if (use_sock_as_in)
        {
            TEST_STEP("If @b splice() was blocked and "
                      "@p use_sock_as_in is @c TRUE");
            TEST_SUBSTEP("Bind, connect and write to unblock @b splice()");
            if (!bound_socket)
                CHECK_RC(rpc_bind(pco_aux, iut_socket, iut_addr));
            if (unblock_same_sock)
            {
                te_bool op_is_completed;

                CHECK_RC(rpc_connect(pco_aux, iut_socket, iut_addr));
                pco_aux->op = RCF_RPC_CALL;
                rc = rpc_write(pco_aux, iut_socket, msg,
                               strlen(msg) + 1);
                if (rc != 0)
                    TEST_VERDICT("write() is unexpectedly failed to call "
                                 "when UDP socket connected to itself");

                TAPI_WAIT_NETWORK;
                CHECK_RC(rcf_rpc_server_is_op_done(pco_aux, &op_is_completed));
                if (!op_is_completed)
                    TEST_VERDICT("write() is unexpectedly not completed "
                                 "when UDP socket connected to itself");
                pco_iut->op = RCF_RPC_WAIT;
                RPC_AWAIT_IUT_ERROR(pco_aux);

                RPC_WRITE(rc, pco_aux, iut_socket, msg,
                          strlen(msg) + 1);
            }
            else
            {
                aux_socket = rpc_socket(pco_aux, domain,
                                        RPC_SOCK_DGRAM,
                                        RPC_PROTO_DEF);
                CHECK_RC(rpc_bind(pco_aux, aux_socket, SA(&aux_addr)));
                CHECK_RC(rpc_connect(pco_aux, aux_socket, iut_addr));
                RPC_WRITE(rc, pco_aux, aux_socket, msg,
                          strlen(msg) + 1);
            }

        }
        else
        {
            TEST_STEP("If @b splice() was blocked and "
                      "@p use_sock_as_in is @c FALSE");
            TEST_SUBSTEP("Write to pipe to unblock @b splice()");
            RPC_WRITE(rc, pco_aux, fd[1], msg, strlen(msg) + 1);

        }
        pco_iut->op = RCF_RPC_WAIT;
        RPC_AWAIT_IUT_ERROR(pco_iut);

        TEST_STEP("If @b splice() was blocked "
                  "check if @b splice() is unblocked");
        rc = rpc_splice(pco_iut, fd_in, NULL, fd_out, NULL,
                        tx_buf_len, flags);
        if (use_sock_as_in)
        {
            if (rc != strlen(msg) + 1)
            {
                TEST_VERDICT("splice() called on not connected "
                             "SOCK_DGRAM sockets unexpectedly returned %d", rc);
            }
        }
        else
        {
            if (rc != -1)
            {
                TEST_VERDICT("splice() called on not connected "
                             "SOCK_DGRAM sockets unexpectedly "
                             "does not fail and spliced %d bytes", rc);
            }
            else
            {
                CHECK_RPC_ERRNO(pco_iut, TE_RC(TE_RPC, TE_EDESTADDRREQ),
                                "splice() was called on nonconnected "
                                "SOCK_DGRAM sockets");
            }
        }
    }
    else
    {
        if (blocked_splice)
            TEST_VERDICT("splice() is unexpectedly not blocked");
        TEST_STEP("If @b splice() was not blocked obtain result for it");
        pco_iut->op = RCF_RPC_WAIT;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_splice(pco_iut, fd_in, NULL, fd_out, NULL, tx_buf_len,
                        flags);
        if (zero_tx_buf_len)
        {
            if (rc == -1)
            {
                TEST_VERDICT("splice() called on nonconnected SOCK_DGRAM "
                             "socket with zero TX buffer length unexpectedly "
                             "fails");
            }
            else if (rc != 0)
            {
                TEST_VERDICT("splice() called on nonconnected SOCK_DGRAM "
                             "socket with zero TX buffer length unexpectedly "
                             "spliced %d bytes", rc);
            }

        }
        else
        {
            if (rc != -1)
            {
                TEST_VERDICT("splice() called on nonconnected SOCK_DGRAM "
                             "socket with nonzero TX buffer length "
                             "unexpectedly did not fail and spliced %d bytes",
                             rc);
            }
            CHECK_RPC_ERRNO(pco_iut, expected_errno,
                            "splice() was called on nonconnected "
                            "SOCK_DGRAM sockets");
        }
    }

    TEST_SUCCESS;

cleanup:

    if (blocked_splice)
    {
        CLEANUP_RPC_CLOSE(pco_iut, aux_socket);
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);
    CLEANUP_RPC_CLOSE(pco_iut, fd[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fd[1]);


    TEST_END;
}
