/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-splice_nonblock The splice() operation on nonblocking pipe and socket
 *
 * @objective Test that @b splice() works correctly on nonblocking pipe
 *            and socket.
 *
 * @type conformance
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *                            - @ref arg_types_env_peer2peer_fake
 * @param set_nonblock        Set flag @c SPLICE_F_NONBLOCK if @c TRUE.
 * @param pipe_nonblock       If @c TRUE, pipe FD passed to splice()
                              is non-blocking.
 * @param sock_nonblock       If @c TRUE, socket FD passed to splice()
 *                            is non-blocking.
 * @param to_socket           If @c TRUE, splice() should move data from
 *                            pipe to socket, else - the other way round.
 * @param diff_stacks         Create pipe and socket in different Onload
 *                            stacks if @c TRUE.
 * @param block_on_pipe       IO operation on pipe end passed to splice()
 *                            should block.
 * @param block_on_sock       IO operation on socket FD passed to splice()
 *                            should block().
 * @param unblock_pipe_first  If IO operation on both pipe FD and socket FD
 *                            passed to splice() should block, then unblock
 *                            it on pipe FD firstly if this parameter is
 *                            @c TRUE and on socket FD firstly if this
 *                            parameter is @c FALSE.
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/splice_nonblock"

#include "sockapi-test.h"
#include "extensions.h"

#define MAX_BUFF_SIZE 10240

/**
 * Read all data sent when overfilling socket or pipe buffers
 * (but not the data queued after that).
 *
 * @param rpcs          RPC server.
 * @param fd            File descriptor.
 * @param exp_len       How many bytes to read.
 * @param stage         String to use as verdict prefix in case
 *                      of failure.
 */
static void
read_sent_data(rcf_rpc_server *rpcs, int fd, uint64_t exp_len,
               const char *stage)
{
    char buf[MAX_BUFF_SIZE];
    int rc;
    int cur_len;

    do {
        cur_len = MIN(exp_len, MAX_BUFF_SIZE);

        RPC_AWAIT_ERROR(rpcs);
        rc = rpc_read(rpcs, fd, buf, cur_len);
        if (rc < 0)
        {
            TEST_VERDICT("%s: read() unexpectedly failed with error "
                         RPC_ERROR_FMT, stage, RPC_ERROR_ARGS(rpcs));
        }
        else if (rc == 0)
        {
            TEST_VERDICT("%s: read() unexpectedly returned zero",
                         stage);
        }
        else if (rc > cur_len)
        {
            TEST_VERDICT("%s: read() unexpectedly returned too big value",
                         stage);
        }

        exp_len -= rc;
    } while (exp_len != 0);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_aux = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *rpcs = NULL;
    int             tst_s = -1;
    int             iut_s = -1;
    void           *tx_buf = NULL;
    size_t          tx_buf_len;
    void           *rx_buf = NULL;
    size_t          rx_buf_len;
    uint64_t        total_bytes;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int             fds[2] = { -1, -1 };
    int             aux_fd = -1;
    te_bool         set_nonblock = FALSE;
    int             flags = 0;
    te_bool         diff_stacks = FALSE;

    int                    fdflags;
    te_bool                is_done;
    te_bool                is_failed = FALSE;
    te_bool                exp_eagain = FALSE;

    te_bool                sock_nonblock = FALSE;
    te_bool                pipe_nonblock = FALSE;
    te_bool                to_socket = FALSE;
    te_bool                block_on_sock = FALSE;
    te_bool                block_on_pipe = FALSE;
    te_bool                unblock_pipe_first = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(set_nonblock);
    TEST_GET_BOOL_PARAM(sock_nonblock);
    TEST_GET_BOOL_PARAM(pipe_nonblock);
    TEST_GET_BOOL_PARAM(to_socket);
    TEST_GET_BOOL_PARAM(diff_stacks);
    TEST_GET_BOOL_PARAM(block_on_sock);
    TEST_GET_BOOL_PARAM(block_on_pipe);
    TEST_GET_BOOL_PARAM(unblock_pipe_first);

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);
    flags = set_nonblock ? RPC_SPLICE_F_NONBLOCK : 0;

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "iut_thread",
                                          &pco_aux));

    TEST_STEP("Create a pair of connected TCP sockets on IUT "
              "and Tester.");
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);
    TEST_STEP("If @p diff_stacks is @c TRUE, change Onload stack on IUT.");
    if (diff_stacks)
    {
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, "test");
    }

    TEST_STEP("Create a pipe() on IUT.");

    rpc_pipe(pco_iut, fds);

    TEST_STEP("Make blocking conditions according to @p block_on_sock and "
              "@p block_on_pipe parameters.");
    if (to_socket)
    {
        if (block_on_sock)
            rpc_overfill_buffers(pco_iut, iut_s, &total_bytes);
        if (!block_on_pipe)
            RPC_WRITE(rc, pco_iut, fds[1], tx_buf, tx_buf_len);
    }
    else
    {
        if (block_on_pipe)
            rpc_overfill_fd(pco_iut, fds[1], &total_bytes);
        if (!block_on_sock)
        {
            RPC_WRITE(rc, pco_tst, tst_s, tx_buf, tx_buf_len);
            TAPI_WAIT_NETWORK;
        }
    }

    TEST_STEP("Make pipe and socket FDs on IUT non-blocking if required by "
              "@p sock_nonblock and @p pipe_nonblock parameters.");
    if (sock_nonblock)
    {
        fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, fdflags | RPC_O_NONBLOCK);
    }
    if (pipe_nonblock)
    {
        aux_fd = to_socket ? fds[0] : fds[1];
        fdflags = rpc_fcntl(pco_iut, aux_fd, RPC_F_GETFL, RPC_O_NONBLOCK);
        rpc_fcntl(pco_iut, aux_fd, RPC_F_SETFL, fdflags | RPC_O_NONBLOCK);
    }

    TEST_STEP("On IUT call @b splice() in a thread according to "
              "@p to_socket parameter.");
    pco_aux->op = RCF_RPC_CALL;
    if (to_socket)
        rpc_splice(pco_aux, fds[0], NULL, iut_s, NULL, tx_buf_len, flags);
    else
        rpc_splice(pco_aux, iut_s, NULL, fds[1], NULL, tx_buf_len, flags);

    TEST_STEP("Wait for a while and check whether @b splice() blocks. It "
              "should block only if either IO operation on pipe FD would "
              "block (and neither pipe FD is non-blocking nor "
              "@C SPLICE_F_NONBLOCK is used) or IO operation on socket FD "
              "would block (and socket FD is not non-blocking).");

    TAPI_WAIT_NETWORK;
    CHECK_RC(rcf_rpc_server_is_op_done(pco_aux, &is_done));

    if ((block_on_pipe && !pipe_nonblock && !set_nonblock) ||
        (!block_on_pipe && block_on_sock && !sock_nonblock))
    {
        if (is_done)
        {
            ERROR_VERDICT("splice() was unexpectedly unblocked");
            is_failed = TRUE;
            exp_eagain = TRUE;
        }
        else
        {
            RING("splice() call blocks as expected");
        }
    }
    else
    {
        if (!is_done)
        {
            ERROR_VERDICT("splice() was unexpectedly blocked");
            is_failed = TRUE;
        }
        else
        {
            RING("splice() call does not block as expected");
            if (block_on_pipe || block_on_sock)
                exp_eagain = TRUE;
        }
    }

    TEST_STEP("Remove blocking conditions on IUT FDs.");

    if (block_on_pipe && unblock_pipe_first)
    {
        if (to_socket)
        {
            RPC_WRITE(rc, pco_iut, fds[1], tx_buf, tx_buf_len);
            TAPI_WAIT_NETWORK;
        }
        else
        {
            read_sent_data(pco_iut, fds[0], total_bytes,
                           "Reading all data from pipe");
        }

        if (sock_nonblock && block_on_sock)
        {
            /*
             * We unblocked pipe FD, and operation on socket FD
             * would block and fail with EAGAIN.
             */
            exp_eagain = TRUE;
        }
    }

    TAPI_WAIT_NETWORK;

    if (block_on_sock)
    {
        if (to_socket)
        {
            read_sent_data(pco_tst, tst_s, total_bytes,
                           "Reading all data from Tester socket");
        }
        else
        {
            RPC_WRITE(rc, pco_tst, tst_s, tx_buf, tx_buf_len);
            TAPI_WAIT_NETWORK;
        }

        if (block_on_pipe && !unblock_pipe_first &&
            (pipe_nonblock | set_nonblock))
        {
            /*
             * We unblocked socket FD, and operation on pipe FD
             * would block and fail with EAGAIN.
             */
            exp_eagain = TRUE;
        }
    }

    if (block_on_pipe && !unblock_pipe_first)
    {
        if (to_socket)
        {
            RPC_WRITE(rc, pco_iut, fds[1], tx_buf, tx_buf_len);
        }
        else
        {
            read_sent_data(pco_iut, fds[0], total_bytes,
                           "Reading all data from pipe");
        }
    }

    TEST_STEP("Check what @b splice() returns. If it is unblocked "
              "before IO operations on both FDs passed to it "
              "are unblocked, it should fail with @c EAGAIN; "
              "otherwise it should succeed.");

    RPC_AWAIT_ERROR(pco_aux);
    pco_aux->op = RCF_RPC_WAIT;
    if (to_socket)
    {
        rc = rpc_splice(pco_aux, fds[0], NULL, iut_s, NULL, tx_buf_len,
                        flags);
    }
    else
    {
        rc = rpc_splice(pco_aux, iut_s, NULL, fds[1], NULL, tx_buf_len,
                        flags);
    }

    if (exp_eagain)
    {
        if (rc >= 0)
        {
            ERROR_VERDICT("splice() unexpectedly succeeded instead of "
                          "failing with EAGAIN");
            is_failed = TRUE;
        }
        else
        {
            CHECK_RPC_ERRNO(pco_aux, RPC_EAGAIN,
                            "nonblocking splice() returned -1");

            TEST_STEP("Resend the data using @b splice() if the first call "
                      "returned @c -1 with @c EAGAIN.");
            RPC_AWAIT_ERROR(pco_aux);
            if (to_socket)
            {
                rc = rpc_splice(pco_aux, fds[0], NULL, iut_s, NULL,
                                tx_buf_len, flags);
            }
            else
            {
                rc = rpc_splice(pco_aux, iut_s, NULL, fds[1], NULL,
                                tx_buf_len, flags);
            }
            if (rc < 0)
            {
                TEST_VERDICT("splice() called again failed with error "
                             RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_aux));
            }
        }
    }
    else if (rc < 0)
    {
        TEST_VERDICT("splice() call unexpectedly failed with error "
                      RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_aux));
    }

    if (rc != (int)tx_buf_len)
    {
        TEST_VERDICT("The final splice() call succeeded but returned "
                     "unexpected value");
    }

    TEST_STEP("Read the data moved by @b splice() and check that it "
              "is correct.");
    if (to_socket)
    {
        rpcs = pco_tst;
        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_read(pco_tst, tst_s, rx_buf, rx_buf_len);
    }
    else
    {
        rpcs = pco_iut;
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_read(pco_iut, fds[0], rx_buf, rx_buf_len);
    }

    if (rc < 0)
    {
        TEST_VERDICT("Trying to read data moved by splice() failed with "
                     "error " RPC_ERROR_FMT, RPC_ERROR_ARGS(rpcs));
    }
    else if (rc != (int)tx_buf_len)
    {
        TEST_VERDICT("read() returned unexpected number of bytes when "
                     "trying to read data moved by splice()");
    }
    else if (memcmp(tx_buf, rx_buf, tx_buf_len) != 0)
    {
        TEST_VERDICT("read() returned unexpected data when "
                     "trying to read data moved by splice()");
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fds[1]);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf);
    free(rx_buf);

    if (pco_aux)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
