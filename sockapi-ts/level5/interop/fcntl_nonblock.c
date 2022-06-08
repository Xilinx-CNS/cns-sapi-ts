/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-fcntl_nonblock Interoperability of libc and L5 implementations of fcntl() O_NONBLOCK and socket()/accept4()/pipe2() (SOCK|O)_NONBLOCK flags
 *
 * @objective Check that @c O_NONBLOCK flag can be changed from
 *            different processes by @e L5 and @e libc implementations
 *            of @b fcntl().
 *
 * @type interop
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on Tester
 * @param is_pipe           Whether we test pipe or socket
 * @param sock_type         Socket type used in the test (if we test
 *                          socket)
 * @param func              Name of function to be tested: @b read(),
 *                          @b readv(), @b write(), @b writev(),
 *                          @b send() or @b recv().
 * @param nonblock_func     Function used to get fd with NONBLOCK flag
 *                          ("socket", "accept4", "fcntl", "pipe2")
 *                          initially
 * @param fcntl_sys_call    Whether system provided @b fcntl() function
 *                          should be used instead of vendor-specific one
 *                          (This parameter only has sense when we have
 *                          alternative TCP/IP stack that provides
 *                          socket API, along with system "libc" library)
 *                          Set it to TRUE when you want to use @b fcntl()
 *                          from "libc".
 * @param iut_sys_call      Whether system provided @b func function
 *                          should be used instead of vendor-specific one
 *                          on @p pco_iut
 *                          (This parameter only has sense when we have
 *                          alternative TCP/IP stack that provides
 *                          socket API, along with system "libc" library)
 *                          Set it to TRUE when you want to use @p func
 *                          from "libc".
 * @param child_sys_call    Whether system provided @p func function
 *                          should be used instead of vendor-specific one
 *                          on @p pco_iut_child
 *                          (This parameter only has sense when we have
 *                          alternative TCP/IP stack that provides
 *                          socket API, along with system "libc" library)
 *                          Set it to TRUE when you want to use @p func
 *                          from "libc".
 * @param start_blocking    Whether set fd blocking or non-blocking
 *                          at the beginning of the test.
 *                          (@c TRUE -- set blocking,
 *                          @c FALSE -- set non-blocking)
 * @param change_iut        Whether change fd blocking state on @p iut
 *                          or on @p pco_iut_child.
 *
 * @par Test sequence:
 * -# Generate connection between IUT and Tester of type @p sock_type.
 *    Obtain fds @p iut_fd and @p tst_fd. If @p nonblock_func is
 *    @c ACCEPT4_SET_FDFLAG, @c SOCKET_SET_FDFLAG or @c PIPE2_SET_FDFLAG,
 *    and @p start_blocking is FALSE, set @c SOCK_NONBLOCK flag with
 *    help of function defined by @p nonblock_func.
 * -# If @p nonblock_func is @c FCNTL_SET_FDFLAG, set (non)blocking
 *    mode of @p iut_fd according to @p start_blocking parameter using
 *    @b fcntl(@c F_SETFL) call.
 * -# @b fork() + @b exec() @p pco_iut, obtain @p pco_iut_child RPC server;
 * -# Change blocking mode of @p iut_fd using @b fcnlt(@c F_SETFL) call on
 *    @p pco_iut or @p pco_iut_child according to @p change_iut.
 *    Library should be reset according to @p fcntl_sys_call;
 * -# If @p func is send function, overfill buffers of @p iut_fd.
 * -# If @p child_sys_call is @c TRUE, reset lib on @p pco_iut_child
 *    permanently.
 * -# Check that @p func function call on @p pco_iut and
 *    @p pco_iut_child blocks or does not block according to
 *    @p start_blocking parameter.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/fcntl_nonblock"

#include "sockapi-test.h"

#define DATA_BULK               1024

/**
 * Set O_NONBLOCK flag using fcntl(F_SETFL) call.
 *
 * @param _pco      RPC server handle
 * @param _fd       file descriptor of socket or pipe
 * @param _flag     Set O_NONBLOCK flag or not 
 * @param _sys      whether to use sys_call or not
 */
#define TST_SET_NONBLOCK(_pco, _fd, _flag, _sys) \
    do                                                      \
    {                                                       \
        int newflags = fdflags;                             \
                                                            \
        if((_flag))                                         \
            newflags = fdflags | RPC_O_NONBLOCK;            \
        (_pco)->use_libc_once = _sys;                       \
        rpc_fcntl((_pco), (_fd), RPC_F_SETFL, newflags);  \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_iut_child = NULL;

    int                     iut_fd = -1;
    int                     tst_fd = -1;
    int                     pipefds[2] = { -1, -1};

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    void                   *func = NULL;
    te_bool                 is_send = FALSE;
    te_bool                 iut_sys_call;
    te_bool                 child_sys_call;
    te_bool                 fcntl_sys_call;
    te_bool                 start_blocking;
    te_bool                 change_iut;
    te_bool                 is_pipe;
    te_bool                 use_libc_old = FALSE;
    rpc_socket_type         sock_type;

    int                     fdflags;
    uint64_t                sent;

    fdflag_set_func_type_t  nonblock_func = UNKNOWN_SET_FDFLAG;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_FUNC(func, is_send);
    TEST_GET_BOOL_PARAM(iut_sys_call);
    TEST_GET_BOOL_PARAM(child_sys_call);
    TEST_GET_BOOL_PARAM(fcntl_sys_call);
    TEST_GET_BOOL_PARAM(start_blocking);
    TEST_GET_BOOL_PARAM(change_iut);
    TEST_GET_BOOL_PARAM(is_pipe);
    TEST_GET_FDFLAG_SET_FUNC(nonblock_func);
    if (!is_pipe)
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_iut, iut_addr);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_SOCK_TYPE(sock_type);
    }

    if (nonblock_func == ACCEPT4_SET_FDFLAG)
    {
        if (rpc_find_func(pco_iut, "accept4") != 0)
            TEST_VERDICT("Failed to find accept4 on pco_iut");

        if (sock_type != RPC_SOCK_STREAM)
            TEST_FAIL("accept4() can be used only with SOCK_STREAM socket");
    }
    else if (nonblock_func == PIPE2_SET_FDFLAG)
    {
        if (rpc_find_func(pco_iut, "pipe2") != 0)
            TEST_VERDICT("Failed to find pipe2 on pco_iut");

        if (!is_pipe)
            TEST_FAIL("pipe2() can be used only with pipe");
    }

    if (!is_pipe)
    {
        if (nonblock_func == ACCEPT4_SET_FDFLAG)
            gen_conn_with_flags(pco_iut, pco_tst, iut_addr, tst_addr,
                                &iut_fd, &tst_fd, sock_type,
                                start_blocking ? 0 : RPC_SOCK_NONBLOCK,
                                FALSE, FALSE, TRUE);
        else
            gen_conn_with_flags(pco_tst, pco_iut, tst_addr, iut_addr,
                                &tst_fd, &iut_fd, sock_type,
                                start_blocking ? 0 : RPC_SOCK_NONBLOCK,
                                FALSE,
                                nonblock_func == SOCKET_SET_FDFLAG ?
                                                        TRUE : FALSE,
                                FALSE);
    }
    else
    {
        if (nonblock_func == PIPE2_SET_FDFLAG)
            rpc_pipe2(pco_iut, pipefds,
                      start_blocking ? 0 : RPC_O_NONBLOCK);
        else
            rpc_pipe(pco_iut, pipefds);

        if (is_send)
        {
            iut_fd = pipefds[1];
            tst_fd = pipefds[0];
        }
        else
        {
            iut_fd = pipefds[0];
            tst_fd = pipefds[1];
        }

        rc = rcf_rpc_server_fork(pco_iut, "pco_tst", &pco_tst);
        if (rc < 0)
        {
            rpc_close(pco_iut, iut_fd);
            rpc_close(pco_iut, tst_fd);
            iut_fd = -1;
            tst_fd = -1;
            TEST_FAIL("fork() failed.");
        }

        rpc_close(pco_iut, tst_fd);
        rpc_close(pco_tst, iut_fd);
    }

    fdflags = rpc_fcntl(pco_iut, iut_fd, RPC_F_GETFL, RPC_O_NONBLOCK);

    if ((fdflags & RPC_O_NONBLOCK) && start_blocking)
        TEST_FAIL("Unexpected O_NONBLOCK flag on just created "
                  "file descriptor.");

    if (!(fdflags & RPC_O_NONBLOCK) && !start_blocking
        && nonblock_func != FCNTL_SET_FDFLAG)
        TEST_FAIL("O_NONBLOCK flag wasn't set by socket or accept4 "
                  "or pipe2 functions.");

    /*
     * At least in Linux O_NONBLOCK is equal to O_NDELAY,
     * but in TE RPC_O_NONBLOCK and RPC_O_DELAY are not
     * equal, so, we will have both different bits set or not
     * simultaneously in any case and we must turn off both
     * ones to turn off blocking mode.
     */
    fdflags &= ~RPC_O_NONBLOCK & ~RPC_O_NDELAY;

    if (nonblock_func == FCNTL_SET_FDFLAG)
        TST_SET_NONBLOCK(pco_iut , iut_fd, !start_blocking, FALSE);

    CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, "iut_child",
                                      &pco_iut_child));

    TST_SET_NONBLOCK(change_iut ? pco_iut : pco_iut_child, iut_fd,
                     start_blocking,
                     fcntl_sys_call);

    if (is_send)
    {
        if (is_pipe)
            rpc_overfill_fd(pco_iut, iut_fd, &sent);
        else
            rpc_overfill_buffers(pco_iut, iut_fd, &sent);
    }
    use_libc_old = pco_iut->use_libc;
    pco_iut->use_libc = iut_sys_call;
    sockts_check_blocking(pco_iut, pco_tst, func, is_send,
                          iut_fd, tst_fd, !start_blocking, DATA_BULK,
                          "Check blocking state on pco_iut");

    if (is_send)
    {
        if (is_pipe)
            rpc_overfill_fd(pco_iut_child, iut_fd, &sent);
        else
            rpc_overfill_buffers(pco_iut_child, iut_fd, &sent);
    }
    pco_iut_child->use_libc = child_sys_call;
    sockts_check_blocking(pco_iut_child, pco_tst, func, is_send,
                          iut_fd, tst_fd, !start_blocking, DATA_BULK,
                          "Check blocking state on pco_iut_child");

    TEST_SUCCESS;

cleanup:
    pco_iut->use_libc = use_libc_old;
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);

    if (is_pipe)
        rcf_rpc_server_destroy(pco_tst);
    rcf_rpc_server_destroy(pco_iut_child);

    TEST_END;
}
