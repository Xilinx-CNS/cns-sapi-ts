/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-fcntl_flags_dup_pipe Usage of fcntl functionality for duplicating of a pipe and nonblocking mode control
 *
 * @objective Check that @b fcntl() can duplicate pipe and
 *            changing of @c O_NONBLOCK mode on duplicated pipe
 *            influence on behavior on original one.
 *
 * @type conformance
 *
 * @param pco_iut1              PCO on IUT thread #1
 * @param pco_iut2              PCO on IUT thread #2
 * @param pco_tst               Auxiliary PCO on TST
 * @param use_dupfd_cloexec     Use @c F_DUPFD_CLOEXEC instead
 *                              of @c F_DUPFD
 * @param use_getown_ex         Use @c F_GETOWN_EX instead
 *                              of @c F_GETOWN
 * @param check_wr              If variable is @c TRUE check write end of
 *                              pipe
 *
 * @par Test sequence:
 * -# Create pipe on @p pco_iut1.
 * -# Duplicate appropriate end of pipe to @p fd_dup according to
 *    @p use_dupfd_cloexec on @p pco_iut2.
 * -# @b write() and @b read() some data via pipe using @p fd_dup where
 *    suitable.
 * -# Check that sent/received data is valid.
 * -# Get owner of the @p fd_dup on @p pco_iut2 by means of @b fcntl()
 *    with command @c F_GETOWN.
 * -# Check that @b fcntl() returns 0.
 * -# Set owner of the @p fd_dup on @p pco_iut2 by means of @b fcntl()
 *    with process id of @p pco_iut2.
 * -# Get owner of the appropriate end of pipe according to @p check_wr
 *    on @p pco_iut1 by means of @b fcntl() with command @c F_GETOWN.
 * -# Check that @b fcntl() returns the process id of @p pco_iut2.
 * -# Set appropriate end of pipe in non-blocking mode by means of @b fcntl().
 * -# Call @b read() or several @b write() calls according to @p check_wr
 *    on @p fd_dup on @p pco_iut2 with last parameter as @c 0.
 * -# Check that last call returns @c -1 and errno set to @c EAGAIN.
 * -# If @p check_wr is @c TRUE read all data from the pipe.
 * -# Split process @p iut_child from @p pco_iut2 with @b fork().
 * -# Change image of process @p iut_child by means of @b execve() call.
 * -# If @p use_dup_cloexec is @c TRUE check that @b write() or @b read()
 *    call according to @p check_wr parameter returns @ -1 with EBADF errno
 *    on @p iut_child process with @p fd_dup.
 * -# if @p use_dup_cloexec is @c FALSE check that @p fd_dup can be used in
 *    @p iut_child process to write or read data from the pipe (according
 *    to @p check_wr parameter).
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "fcntl/fcntl_flags_dup_pipe"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{

    rcf_rpc_server        *pco_iut1 = NULL;
    rcf_rpc_server        *pco_iut2 = NULL;
    rcf_rpc_server        *iut_child = NULL;

    void                  *rd_buf = NULL;
    void                  *wr_buf = NULL;

    pid_t                  iut1_pid, iut2_pid;
    size_t                 sent = 0;

    te_bool                use_dupfd_cloexec = FALSE;

    te_bool                use_getown_ex = FALSE;
    struct rpc_f_owner_ex  foex;

    int                    pipe_fd[2];
    int                    fd_dup = -1;

    te_bool                check_wr = FALSE;
    int                    data_size;
    te_bool                readable = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_BOOL_PARAM(use_dupfd_cloexec);
    TEST_GET_BOOL_PARAM(use_getown_ex);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(check_wr);

    memset(&foex, 0, sizeof(foex));
    iut2_pid = rpc_getpid(pco_iut2);

    pipe_fd[0] = -1;
    pipe_fd[1] = -1;

    rd_buf = te_make_buf_by_len(data_size);
    wr_buf = te_make_buf_by_len(data_size);

    rpc_pipe(pco_iut1, pipe_fd);

    RPC_AWAIT_IUT_ERROR(pco_iut2);
    fd_dup = rpc_fcntl(pco_iut2,
                       check_wr ? pipe_fd[1] : pipe_fd[0],
                       use_dupfd_cloexec ?
                            RPC_F_DUPFD_CLOEXEC : RPC_F_DUPFD, 1);
    if (fd_dup < 0)
        TEST_VERDICT("fcntl(%s) call failed",
                     use_dupfd_cloexec ?
                     "F_DUPFD_CLOEXEC" :
                     "F_DUPFD");

    sent = rpc_write(pco_iut1, check_wr ? fd_dup : pipe_fd[1], wr_buf,
                    data_size);

    rc = rpc_read(pco_iut1, check_wr ? pipe_fd[0] : fd_dup, rd_buf,
                  data_size);
    if (rc != (int)sent)
        TEST_FAIL("rpc_read(): Expected to receive %d instead of %d",
                   sent, rc);
    if (memcmp(wr_buf, rd_buf, sent) != 0)
        TEST_FAIL("Received data is not valid.");

    if (use_getown_ex)
    {
        rpc_fcntl(pco_iut2, fd_dup, RPC_F_GETOWN_EX, &foex);
        iut1_pid = foex.pid;
    }
    else
        iut1_pid = rpc_fcntl(pco_iut2, fd_dup, RPC_F_GETOWN, 0);
    if (iut1_pid != 0)
        TEST_FAIL("Unexpected descriptor owner %d", iut1_pid);

    if (use_getown_ex)
    {
        foex.pid = iut2_pid;
        rc = rpc_fcntl(pco_iut2, fd_dup, RPC_F_SETOWN_EX, &foex);
    }
    else
        rc = rpc_fcntl(pco_iut2, fd_dup, RPC_F_SETOWN, iut2_pid);

    if (use_getown_ex)
    {
        rpc_fcntl(pco_iut2, check_wr ? pipe_fd[1] : pipe_fd[0],
                  RPC_F_GETOWN_EX, &foex);
        iut1_pid = foex.pid;
    }
    else
        iut1_pid = rpc_fcntl(pco_iut2, check_wr ? pipe_fd[1] : pipe_fd[0],
                             RPC_F_GETOWN, 0);
    if (iut1_pid != iut2_pid)
        TEST_FAIL("Unexpected descriptor owner %d instead of %d",
                   iut1_pid, iut2_pid);

    (void)rpc_fcntl(pco_iut1, check_wr ? pipe_fd[1] : pipe_fd[0],
                    RPC_F_GETFL, 0);
    rc = rpc_fcntl(pco_iut1, check_wr ? pipe_fd[1] : pipe_fd[0],
                   RPC_F_SETFL, RPC_O_NONBLOCK);

    if (check_wr)
    {
        do {
            RPC_AWAIT_IUT_ERROR(pco_iut2);
            rc = rpc_write(pco_iut2, fd_dup, wr_buf, data_size);
        } while (rc != -1);
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut2);
        rc = rpc_read(pco_iut2, fd_dup, rd_buf, data_size);
    }
    if (rc != -1)
        TEST_FAIL("%s() returns %d instead of -1",
                  check_wr ? "write" : "read", rc);
    CHECK_RPC_ERRNO(pco_iut2, RPC_EAGAIN, "read() returns -1, but");

    if (check_wr)
        do {
            (void)rpc_read(pco_iut1, pipe_fd[0], rd_buf, data_size);
            RPC_GET_READABILITY(readable, pco_iut1, pipe_fd[0], 1);
        } while (readable);

    CHECK_RC(rcf_rpc_server_fork_exec(pco_iut2, "iut2_child", &iut_child));

    if (use_dupfd_cloexec)
    {
        RPC_AWAIT_IUT_ERROR(iut_child);
        if (check_wr)
            rc = rpc_write(iut_child, fd_dup, wr_buf, data_size);
        else
            rc = rpc_read(iut_child, fd_dup, rd_buf, data_size);
        if (rc != -1)
            TEST_VERDICT("Pipe was not closed after exec()");
        CHECK_RPC_ERRNO(iut_child, RPC_EBADF,\
                        "%s() function returned -1, but",
                        check_wr ? "write" : "read");
    }
    else
    {
        sent = rpc_write(check_wr ? iut_child : pco_iut1,
                         check_wr ? fd_dup : pipe_fd[1], wr_buf,
                         data_size);

        rc = rpc_read(check_wr ? pco_iut1 : iut_child,
                      check_wr ? pipe_fd[0] : fd_dup, rd_buf,
                      data_size);
        if (rc != (int)sent)
            TEST_FAIL("rpc_read(): Expected to receive %d instead of %d",
                       sent, rc);
        if (memcmp(wr_buf, rd_buf, sent) != 0)
            TEST_FAIL("Received data is not valid.");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut1, pipe_fd[0]);
    CLEANUP_RPC_CLOSE(pco_iut1, pipe_fd[1]);
    CLEANUP_RPC_CLOSE(pco_iut1, fd_dup);

    if (iut_child != NULL)
    {
        if (rcf_rpc_server_destroy(iut_child) < 0)
            ERROR("Failed to destroy child RPC server on the IUT");
    }

    free(wr_buf);
    free(rd_buf);

    TEST_END;
}

