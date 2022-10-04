/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-nonblock Interoperability of libc I/O functions and O_NONBLOCK fcntl() flag or SOCK_NONBLOCK socket()/accept4() flag on L5 socket
 *
 * @objective Check that setting @c O_NONBLOCK (or @c SOCK_NONBLOCK) flag
 * really makes L5 socket non-blocking.
 *
 * @type interop
 *
 * @param sock_type         Socket type used in the test
 * @param test_func         Name of libc function to be tested: @b read(),
 *                          @b readv() @b write() or @b writev()
 * @param nonblock_func     Function used to get socket with NONBLOCK flag
 *                          ("socket", "accept4", "fcntl")
 * @param l5_fcntl          Set @c O_NONBLOCK flag using L5 @b fcntl()
 *                          implementation (if nonblock_func = "fcntl").
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on Tester
 *
 * @par Test sequence:
 * -# Create a connection of type @p sock_type between @p pco_iut and
 *    @p pco_tst. As the result we will have two sockets:
 *    @p iut_s and @p tst_s. If @p nonblock_func is @c SOCKET_SET_FDFLAG
 *    or @c ACCEPT4_SET_FDFLAG, obtain @p iut_s with SOCK_NONBLOCK flag
 *    set with help of function defined by @p nonblock_func during this
 *    process.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p test_func is sending function, overfill buffers on @p iut_s.
 * -# If @p nonblock_func is @c FCNTL_SET_FDFLAG, set @c O_NONBLOCK flag
 *    on iut_s with help of @b fcntl(). If @p l5_fcntl is @c TRUE, use
 *    Level5 @b fcntl() implementation, otherwise use @e libc function.
 * -# Call @e libc version of the function defined by @p test_func on
 *    @p iut_s. Make sure it fails with @c EAGAIN error.
 * -# Clear @c O_NONBLOCK flag on @p iut_s.
 * -# Call @e libc version of the @p test_func.
 * -# Make sure it has been blocked.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/nonblock"

#include "sockapi-test.h"

#define  DATA_BULK SOCKTS_MSG_STREAM_MAX

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;
    rpc_socket_type        sock_type;
    void                  *test_func = NULL;
    te_bool                is_send = FALSE;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    uint8_t               *data_buf = NULL;
    uint8_t               *tst_buf = NULL;
    int                    fdflags;
    te_bool                operation_done;
    te_bool                l5_fcntl = FALSE;
    te_bool                accept4_found = FALSE;
    te_bool                use_libc_old = FALSE;
    uint64_t               sent;

    fdflag_set_func_type_t nonblock_func = UNKNOWN_SET_FDFLAG;

    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_FUNC(test_func, is_send);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_FDFLAG_SET_FUNC(nonblock_func);
    TEST_GET_BOOL_PARAM(l5_fcntl);

    if (rpc_find_func(pco_iut, "accept4") == 0)
        accept4_found = TRUE;

    if (nonblock_func == ACCEPT4_SET_FDFLAG)
    {
        if (!accept4_found)
            TEST_VERDICT("Failed to find accept4 on pco_iut");

        if (sock_type != RPC_SOCK_STREAM)
            TEST_FAIL("accept4() can be used only with SOCK_STREAM socket");
    }

    if (nonblock_func == ACCEPT4_SET_FDFLAG)
        gen_conn_with_flags(pco_iut, pco_tst, iut_addr, tst_addr,
                            &iut_s, &tst_s, sock_type,
                            RPC_SOCK_NONBLOCK,
                            FALSE, FALSE, TRUE);
    else
        gen_conn_with_flags(pco_tst, pco_iut, tst_addr, iut_addr,
                            &tst_s, &iut_s, sock_type,
                            RPC_SOCK_NONBLOCK,
                            FALSE,
                            nonblock_func == SOCKET_SET_FDFLAG ?
                                                    TRUE : FALSE,
                            FALSE);

    if (is_send)
    {
        /* Overfill buffers (for send function) */
        rpc_overfill_buffers(pco_iut, iut_s, &sent);
    }

    /* Prepare data to transmit */
    data_buf = te_make_buf_by_len(DATA_BULK);
    tst_buf = te_make_buf_by_len(DATA_BULK);

    fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);

    use_libc_old = pco_iut->use_libc;

    if (nonblock_func == FCNTL_SET_FDFLAG)
    {
        if (!l5_fcntl)
            pco_iut->use_libc = TRUE;
        else
            pco_iut->use_libc = FALSE;

        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, fdflags | RPC_O_NONBLOCK);

    }

    pco_iut->use_libc = TRUE;

    if (is_send)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = ((rpc_send_f)test_func)(pco_iut, iut_s, data_buf,
                                     DATA_BULK, 0);
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = ((rpc_recv_f)test_func)(pco_iut, iut_s, data_buf,
                                     DATA_BULK, 0);
    }

    if (rc != -1)
        TEST_VERDICT("Unexpected result of send/recv function");
    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                    "libc send/recv function failed");

    /* Clear O_NONBLOCK flag */
    if (!l5_fcntl)
        pco_iut->use_libc = TRUE;
    else
        pco_iut->use_libc = FALSE;

    /*
     * At least in Linux O_NONBLOCK is equal to O_NDELAY,
     * but in TE RPC_O_NONBLOCK and RPC_O_DELAY are not
     * equal, so, we will have both different bits set or not
     * simultaneously in any case and we must turn off both
     * ones to turn off blocking mode.
     */
    rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, fdflags & ~RPC_O_NONBLOCK &
                                           ~RPC_O_NDELAY);

    pco_iut->use_libc = TRUE;

    pco_iut->op = RCF_RPC_CALL;
    rc = is_send ? ((rpc_send_f)test_func)(pco_iut, iut_s,
                                           data_buf, DATA_BULK, 0)
                 : ((rpc_recv_f)test_func)(pco_iut, iut_s,
                                           data_buf, DATA_BULK, 0);

    MSLEEP(pco_iut->def_timeout / 5);

    rcf_rpc_server_is_op_done(pco_iut, &operation_done);

    if (is_send)
    {
        do {
            rc = rpc_read(pco_tst, tst_s, tst_buf, sent > DATA_BULK ?
                                                   DATA_BULK : sent);
            if (rc == 0)
                TEST_VERDICT("Tester unexpectedly got EOF");
            sent -= rc;
        } while (sent > 0);
    }
    else
    {
        rpc_write(pco_tst, tst_s, tst_buf, DATA_BULK);
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = is_send ? ((rpc_send_f)test_func)(pco_iut, iut_s,
                                       data_buf, DATA_BULK, 0)
             : ((rpc_recv_f)test_func)(pco_iut, iut_s,
                                       data_buf, DATA_BULK, 0);

    if (operation_done)
    {
        if (!is_send)
            TEST_VERDICT("O_NONBLOCK flag cleared, but receiving "
                         "function was not blocked");
        else
        {
            if (rc > 0)
                TEST_VERDICT("Buffers were overfilled, but %d "
                             "bytes sent", rc);
            else if (rc < 0)
            {
                if (RPC_ERRNO(pco_iut) == RPC_EAGAIN)
                    TEST_VERDICT("O_NONBLOCK flag cleared, but sending "
                                 "function was not blocked");
                else
                    TEST_VERDICT("%s error occured while sending data",
                                 errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
            else
                TEST_VERDICT("Send function succeed despite of the fact "
                             "that buffers are overfilled");
        }
    }

    if (is_send)
    {
        rc = rpc_read(pco_tst, tst_s, tst_buf, DATA_BULK);
        SOCKTS_CHECK_RECV(pco_tst, data_buf, tst_buf, DATA_BULK, rc);
    }
    else
    {
        SOCKTS_CHECK_RECV(pco_iut, tst_buf, data_buf, DATA_BULK, rc);
    }

    TEST_SUCCESS;

cleanup:
    pco_iut->use_libc = use_libc_old;
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
