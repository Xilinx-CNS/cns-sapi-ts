/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-fcntl_flags_dup Usage of fcntl functionality for duplicating of a socket descriptor and nonblocking mode control
 *
 * @objective Check that @b fcntl() can duplicate socket descriptor and
 *            changing of @c O_NONBLOCK mode on duplicated socket
 *            descriptor influence on behavior on original one.
 *
 * @type conformance
 *
 * @param pco_iut1              PCO on IUT thread #1
 * @param pco_iut2              PCO on IUT thread #2
 * @param pco_tst               Auxiliary PCO on TST
 * @param use_dupfd_cloexec     Use @c F_DUPFD_CLOEXEC instead
 *                              of @c F_DUPFD
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut1.
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst.
 * -# @b bind() @p tst_s socket to a local address on @p pco_tst.
 * -# Call @b listen() on @p tst_s.
 * -# Duplicate @p iut_s descriptor to @p iut_dup by means of
 *    @b fcntl(F_DUPFD) on @p pco_iut2.
 * -# @b bind() @p iut_s socket to a local address on @p pco_iut1.
 * -# @b connect() @p iut_dup to the @p tst_s.
 * -# Call @b accept() on @p tst_s to return new @p acc_s descriptor.
 * -# @b send() some data through @p iut_dup on @p pco_iut1.
 * -# @b recv() data sent through @p iut_dup on @p acc_s.
 * -# @b send() received data through @p acc_s.
 * -# @b recv() data sent through @p acc_s on @p iut_s on @p pco_iut2.
 * -# Check that sent/received data is valid.
 * -# Get owner of the @p iut_dup on @p pco_iut2 by means of @b fcntl()
 *    with command @c F_GETOWN.
 * -# Check that @b fcntl() returns 0.
 * -# Set owner of the @p iut_dup on @p pco_iut2 by means of @b fcntl()
 *    with process id of @p pco_iut2.
 * -# Get owner of the @p iut_s on @p pco_iut1 by means of @b fcntl()
 *    with command @c F_GETOWN.
 * -# Check that @b fcntl() returns the process id of @p pco_iut2.
 * -# Set @p iut_s in non-blocking mode by means of @b fcntl().
 * -# Call @b recv() on @p iut_dup on @p pco_iut2 with last parameter
 *    as @c 0.
 * -# Check that @b recv() returns immediately with return code @c -1
 *    and errno set to @c EAGAIN.
 * -# Call @b shutdown(WR) on @p iut_dup on @p pco_iut2.
 * -# Call @b send() on @p iut_s on @p pco_iut1.
 * -# Check that @b send() returns -1 and @b errno set to @c EPIPE.
 * -# @b send() some data through @p acc_s.
 * -# Split process @p iut_child from @p pco_iut2 with @b fork().
 * -# @b recv() data passed through @p acc_s on @p iut_s on @p iut_child
 *    and check its validity.
 * -# Change image of process @p iut_child by means of @b execve() call.
 * -# Perform #sockts_get_socket_state routine for @p iut_s on @p
 *    iut_child.
 * -# Check that obtained state of @p iut_s is @c STATE_SHUT_RW.
 * -# Delete all created buffers.
 * -# Close created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "fcntl/fcntl_flags_dup"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{

    rcf_rpc_server        *pco_iut1 = NULL;
    rcf_rpc_server        *pco_iut2 = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rcf_rpc_server        *iut_child = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    acc_s = -1;
    int                    iut_dup = -1;

    void                  *rd_buf = NULL;
    size_t                 rd_buflen;
    void                  *wr_buf = NULL;
    size_t                 wr_buflen;  
    void                  *buffer = NULL;
    size_t                 buflen;

    pid_t                  iut1_pid, iut2_pid;
    size_t                 sent = 0;

    te_bool                use_dupfd_cloexec = FALSE;

    te_bool                use_getown_ex = FALSE;
    struct rpc_f_owner_ex  foex;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(use_dupfd_cloexec);
    TEST_GET_BOOL_PARAM(use_getown_ex);

    memset(&foex, 0, sizeof(foex));
    iut2_pid = rpc_getpid(pco_iut2);

    CHECK_NOT_NULL(wr_buf = sockts_make_buf_stream(&wr_buflen));
    rd_buf = te_make_buf_min(wr_buflen, &rd_buflen);
    buffer = te_make_buf_min(wr_buflen, &buflen);

    iut_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut2);
    iut_dup = rpc_fcntl(pco_iut2, iut_s,
                        use_dupfd_cloexec ?
                                RPC_F_DUPFD_CLOEXEC : RPC_F_DUPFD, 1);
    if (iut_dup < 0)
        TEST_VERDICT("fcntl(%s) call failed",
                     use_dupfd_cloexec ?
                     "F_DUPFD_CLOEXEC" :
                     "F_DUPFD");

    rpc_bind(pco_iut1, iut_s, iut_addr);

    rpc_connect(pco_iut2, iut_dup, tst_addr);

    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    RPC_SEND(sent, pco_iut1, iut_dup, wr_buf, wr_buflen, 0);

    rc = rpc_recv(pco_tst, acc_s, rd_buf, rd_buflen, 0);

    RPC_SEND(rc, pco_tst, acc_s, rd_buf, rc, 0);

    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rc = rpc_recv(pco_iut2, iut_s, buffer, buflen, 0);
    if (rc == -1)
        TEST_VERDICT("recv() function failed with %s errno",
                     errno_rpc2str(RPC_ERRNO(pco_iut2)));
    if (rc != (int)sent)
        TEST_FAIL("rpc_recv(): Expected to receive %d instead of %d",
                   sent, rc);
    if (memcmp(wr_buf, buffer, sent) != 0)
        TEST_FAIL("Received data is not valid.");

    if (use_getown_ex)
    {
        rpc_fcntl(pco_iut2, iut_dup, RPC_F_GETOWN_EX, &foex);
        iut1_pid = foex.pid;
    }
    else
        iut1_pid = rpc_fcntl(pco_iut2, iut_dup, RPC_F_GETOWN, 0);
    if (iut1_pid != 0)
        TEST_FAIL("Unexpected descriptor owner %d", iut1_pid);

    if (use_getown_ex)
    {
        foex.pid = iut2_pid;
        rc = rpc_fcntl(pco_iut2, iut_dup, RPC_F_SETOWN_EX, &foex);
    }
    else
        rc = rpc_fcntl(pco_iut2, iut_dup, RPC_F_SETOWN, iut2_pid);

    if (use_getown_ex)
    {
        rpc_fcntl(pco_iut2, iut_dup, RPC_F_GETOWN_EX, &foex);
        iut1_pid = foex.pid;
    }
    else
        iut1_pid = rpc_fcntl(pco_iut2, iut_dup, RPC_F_GETOWN, 0);
    if (iut1_pid != iut2_pid)
        TEST_FAIL("Unexpected descriptor owner %d instead of %d",
                   iut1_pid, iut2_pid);

    rpc_fcntl(pco_iut1, iut_s, RPC_F_GETFL, 0);

    rc = rpc_fcntl(pco_iut1, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rc = rpc_recv(pco_iut2, iut_dup, rd_buf, rd_buflen, 0);
    if (rc != -1)
        TEST_FAIL("recv() returns %d instead of -1", rc);

    CHECK_RPC_ERRNO(pco_iut2, RPC_EAGAIN, "recv() returns -1, but");

    rpc_shutdown(pco_iut2, iut_dup, RPC_SHUT_WR);

    RPC_AWAIT_IUT_ERROR(pco_iut1);
    rc = rpc_send(pco_iut1, iut_s, wr_buf, wr_buflen, 0);
    if (rc != -1)
        TEST_FAIL("send() returns %d instead of -1", rc);

    CHECK_RPC_ERRNO(pco_iut1, RPC_EPIPE, "send() returns -1, but");

    RPC_SEND(sent, pco_tst, acc_s, wr_buf, wr_buflen, 0);

    CHECK_RC(rcf_rpc_server_fork(pco_iut2, "iut2_child", &iut_child));

    rc = rpc_recv(iut_child, iut_s, rd_buf, rd_buflen, 0);
    if (rc != (int)sent)
        TEST_FAIL("Received %d bytes instead of %d", rc, sent);

    if (memcmp(wr_buf, rd_buf, sent))
    {
        TEST_FAIL("Received data is not the same as sent");
    }

    CHECK_RC(rcf_rpc_server_exec(iut_child));

    CHECK_SOCKET_STATE(iut_child, iut_s, NULL, -1, STATE_SHUT_WR);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);

    if (iut_child != NULL)
    {
        if (rcf_rpc_server_destroy(iut_child) < 0)
            ERROR("Failed to destroy child RPC server on the IUT");
    }

    free(wr_buf);
    free(rd_buf);
    free(buffer);

    TEST_END;
}

