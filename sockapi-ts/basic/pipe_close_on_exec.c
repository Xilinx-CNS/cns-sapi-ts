/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-pipe_close_on_exec Usage of fcntl and pipe2 functionality for handling close-on-exec on pipe
 *
 * @objective Check that @b fcntl() and @b pipe2() can handle close-on-exec
 *            flag and @b exec() operates in accordance with this flag.
 *
 * @type conformance
 *
 * @param pco_iut       Private environment with two threads on IUT.
 * @param close_on_exec @c TRUE to set close-on-exec flag, FALSE - unset it.
 * @param func          Tested function:
 *                      - fcntl
 *                      - pipe2
 * @param recv_f        Receiving function:
 *                      - read
 *                      - readv
 * @param send_f        Sending function:
 *                      - write
 *                      - writev
 * @param data_size     Size of data to send:
 *                      - 512
 * @param use_fork      Create child process after creating
 *                      pipe but before @b exec() call if @c TRUE.
 * @param test_read_end   If this parameter is set and @p func is "fcntl",
 *                        set close-on-exec flag on the read end of
 *                        pipe if @p close_on_exec is TRUE. Also, if
 *                        @p use_fork is @c TRUE, close read end of pipe
 *                        in the child process.
 * @param test_write_end  If this parameter is set and @p func is "fcntl",
 *                        set close-on-exec flag on the write end of
 *                        pipe if @p close_on_exec is TRUE. Also, if
 *                        @p use_fork is @c TRUE, close write end of pipe
 *                        in the child process.
 * @param use_fdup        Use @c F_DUPFD_CLOEXEC/@c F_DUPFD
 *                        when calling fcntl() and work with
 *                        duplicated socket.
 * @par Test sequence:
 * -# Create a pipe. If @p func is "pipe2" and @p close_on_exec is
 *    @c TRUE, we create pipe with @c RPC_SOCK_CLOEXEC flag set
 *    on both its ends with help of @b pipe2().
 * -# If @p func is "fcntl", set close-on-exec flag by means of
 *    @b fcntl() on ends of pipe determined by @p test_read_end and
 *    @p test_write_end.
 * -# Create child process @p pco_iut_aux if @p use_fork is set
 *    (otherwise @p pco_iut_aux is the same as @p pco_iut).
 * -# Perform @b exec() in @p pco_iut.
 * -# Check whether end(s) of pipe for which close-on-exec flag
 *    was set are really closed after @b exec() call.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/close_on_exec"

#include "sockapi-test.h"
#include "tapi_sockets.h"

#define FCNTL_SETFD(fd_) \
    do {                                                            \
        int fd_aux_;                                                \
        rc = rpc_fcntl(pco_iut, fd_, RPC_F_GETFD, arg);             \
        RING("Default value of FD_CLOEXEC bit is %d", rc);          \
        if (!use_fdup)                                              \
            rpc_fcntl(pco_iut, fd_, RPC_F_SETFD, close_on_exec);    \
        else                                                        \
        {                                                           \
            if (use_dup3)                                           \
            {                                                       \
                fd_aux_ = rpc_socket(pco_iut, RPC_PF_INET,          \
                                     RPC_SOCK_DGRAM,                \
                                     RPC_PROTO_DEF);                \
                rpc_dup3(pco_iut, fd_, fd_aux_,                     \
                         close_on_exec ? RPC_O_CLOEXEC : 0);        \
            }                                                       \
            else                                                    \
            {                                                       \
                RPC_AWAIT_IUT_ERROR(pco_iut);                       \
                fd_aux_ = rpc_fcntl(pco_iut, fd_,                   \
                                    close_on_exec ?                 \
                                    RPC_F_DUPFD_CLOEXEC :           \
                                    RPC_F_DUPFD, 0);                \
                if (fd_aux_ < 0)                                    \
                    TEST_VERDICT("fcntl(%s) call failed",           \
                                 close_on_exec ?                    \
                                 "F_DUPFD_CLOEXEC" :                \
                                 "F_DUPFD");                        \
            }                                                       \
            rpc_close(pco_iut, fd_);                                \
            fd_ = fd_aux_;                                          \
                                                                    \
        }                                                           \
        rc = rpc_fcntl(pco_iut, fd_, RPC_F_GETFD, arg);             \
        if (rc != close_on_exec)                                    \
            TEST_FAIL("Unable to set FD_CLOEXEC bit to %d",         \
                      close_on_exec);                               \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_iut_aux = NULL;
    int                    pipefds[2] = { -1, -1};

    void                  *tx_buf = NULL;
    void                  *rx_buf = NULL;
    int                    data_size;
    te_bool                close_on_exec = FALSE;
    te_bool                test_read_end = FALSE;
    te_bool                test_write_end = FALSE;
    te_bool                use_fork = FALSE;
    int                    arg = 0;

    int                    sent = 0;
    te_bool                pipe2_found = FALSE;
    te_bool                is_failed = FALSE;

    fdflag_set_func_type_t func;

    rpc_send_f          send_f;
    rpc_recv_f          recv_f;

    te_bool             use_fdup = FALSE;
    te_bool             use_dup3 = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_RECV_FUNC(recv_f);
    TEST_GET_BOOL_PARAM(close_on_exec);
    TEST_GET_BOOL_PARAM(test_read_end);
    TEST_GET_BOOL_PARAM(test_write_end);
    TEST_GET_BOOL_PARAM(use_fork);
    TEST_GET_FDFLAG_SET_FUNC(func);
    if (func == FCNTL_SET_FDFLAG)
    {
        TEST_GET_BOOL_PARAM(use_fdup);
        if (use_fdup)
            TEST_GET_BOOL_PARAM(use_dup3);
    }

    if (rpc_find_func(pco_iut, "pipe2") == 0)
        pipe2_found = TRUE;

    if (func == PIPE2_SET_FDFLAG && !pipe2_found)
        TEST_VERDICT("Failed to find pipe2 on pco_iut");

    tx_buf = te_make_buf_by_len(data_size);
    rx_buf = te_make_buf_by_len(data_size);
    te_fill_buf(tx_buf, data_size);

    /* Scenario */

    if (func == FCNTL_SET_FDFLAG)
    {
        rpc_pipe(pco_iut, pipefds);
        if (test_read_end)
            FCNTL_SETFD(pipefds[0]);
        if (test_write_end)
            FCNTL_SETFD(pipefds[1]);
    }
    else if (func == PIPE2_SET_FDFLAG)
        rpc_pipe2(pco_iut, pipefds, close_on_exec ? RPC_O_CLOEXEC : 0);
    else
        TEST_FAIL("Unknown \"func\" parameter");

    if (use_fork)
    {
        rcf_rpc_server_fork(pco_iut, "pco_iut_child", &pco_iut_aux);
        if (test_read_end)
            rpc_close(pco_iut_aux, pipefds[0]);
        if (test_write_end)
            rpc_close(pco_iut_aux, pipefds[1]);
    }
    else
        pco_iut_aux = pco_iut;
    
    CHECK_RC(rcf_rpc_server_exec(pco_iut));
    SLEEP(2);

    if (close_on_exec == TRUE)
    {
        te_bool write_end_closed;
        te_bool read_end_closed;

        if (!use_fork && func == PIPE2_SET_FDFLAG)
        {
            read_end_closed = TRUE;
            write_end_closed = TRUE;
        }
        else
        {
            read_end_closed = test_read_end;
            write_end_closed = test_write_end;
        }

        RPC_AWAIT_IUT_ERROR(write_end_closed ? pco_iut : pco_iut_aux);
        sent = send_f(write_end_closed ? pco_iut : pco_iut_aux,
                      pipefds[1], tx_buf,
                      data_size, 0);

        if ((read_end_closed || write_end_closed) && sent != -1)
        {
            RING_VERDICT("%s() returned %d instead of -1",
                         rpc_send_func_name(send_f),
                         sent);
            is_failed = TRUE;
        }

        if (write_end_closed)
            CHECK_RPC_ERRNO_NOEXIT(pco_iut, RPC_EBADF, is_failed,
                                   "%s() returned -1, but",
                                   rpc_send_func_name(send_f));
        else if (read_end_closed)
            CHECK_RPC_ERRNO_NOEXIT(pco_iut_aux, RPC_EPIPE, is_failed,
                                   "%s() returned -1, but",
                                   rpc_send_func_name(send_f));
        else if (sent != data_size)
        {
            RING_VERDICT("%s() returned %d instead of %d",
                         rpc_send_func_name(send_f), sent,
                         data_size);
            is_failed = TRUE;
        }

        RPC_AWAIT_IUT_ERROR(read_end_closed ? pco_iut : pco_iut_aux);
        rc = recv_f(read_end_closed ? pco_iut : pco_iut_aux,
                    pipefds[0], rx_buf, data_size, 0);

        if (read_end_closed)
        {
            if (rc != -1)
            {
                RING_VERDICT("%s() returned %d instead of -1",
                             rpc_recv_func_name(recv_f),
                             rc);
                is_failed = TRUE;
            }
            else
                CHECK_RPC_ERRNO_NOEXIT(pco_iut, RPC_EBADF, is_failed,
                                       "%s() returned -1, but",
                                       rpc_recv_func_name(recv_f));
        }
        else if (write_end_closed && rc != 0)
        {
            RING_VERDICT("%s() returned %d instead of 0",
                         rpc_recv_func_name(recv_f), rc);
            is_failed = TRUE;
        }
        else if (!write_end_closed && rc != sent)
        {
            RING_VERDICT("%s() returned %d instead of %d",
                         rpc_recv_func_name(recv_f), rc, sent);
            is_failed = TRUE;
        }
    }
    else
    {
        sent = send_f(test_write_end ? pco_iut : pco_iut_aux,
                      pipefds[1], tx_buf,
                      data_size, 0);
        rc = recv_f(test_read_end ? pco_iut : pco_iut_aux,
                    pipefds[0], rx_buf, data_size, 0);

        if (rc != sent)
        {
            RING_VERDICT("%s(): Expected to receive %d instead of %d",
                         rpc_recv_func_name(recv_f), sent, rc);
            is_failed = TRUE;
        }
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (use_fork)
        rcf_rpc_server_destroy(pco_iut_aux);

    if (!close_on_exec)
    {
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
    }
    else
    {
        if (func != PIPE2_SET_FDFLAG)
        {
            if (!test_read_end)
                CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
            if (!test_write_end)
                CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
        }
    }

    TEST_END;
}
