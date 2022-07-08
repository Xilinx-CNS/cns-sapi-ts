/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-nonblock_handover Setting nonblock flag on L5 socket and then handover it
 *
 * @objective Check that setting @c O_NONBLOCK (or @c SOCK_NONBLOCK) flag
 *            on L5 socket will be preserved after connecting L5 socket
 *            through non-onload interface
 *
 * @type interop
 *
 * @param sock_type         Socket type used in the test
 * @param test_func         Name of libc function to be tested: @b read(),
 *                          @b readv() @b write() or @b writev()
 * @param nonblock_func     Function used to get socket with NONBLOCK flag
 *                          ("socket", "fcntl")
 * @param nonblock_set      Whether @c O_NONBLOCK flag is set before
 *                          handover
 * @param pco_iut           PCO on IUT
 * @param iut_addr1         Network address on vendor interface on IUT
 * @param pco_tst2          PCO on Tester
 * @param tst2_addr         Network address on TST interface on TESTER
 *
 * @par Test sequence:
 * -# Create a socket @p iut_s of type @p sock_type on @p pco_iut.
 *    If @p nonblock_func is "socket", set @c SOCK_NONBLOCK flag
 *    during creation if required.
 * -# If @p nonblock_func is @c FCNTL_SET_FDFLAG, set or clear
 *    @c O_NONBLOCK flag on iut_s with help of @b fcntl() according
 *    to @p nonblock_set.
 * -# Create a connection between @p iut_s socket on @p pco_iut and
 *    @p tst_s socket on @p pco_tst2. @p tst_s socket  should be bound
 *    to @p tst2_addr address which is not on a vendor interface.
 * -# Check that state of @c O_NONBLOCK flag was not changed after
 *    connection by means of @b fcntl() and data transmitting
 *    function defined by @p test_func.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/nonblock_handover"

#include "sockapi-test.h"
#include "onload.h"

#define  DATA_BULK              2000

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    tst_s_listening = -1;
    rpc_socket_type        sock_type;
    void                  *test_func = NULL;
    te_bool                is_send = FALSE;
    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *tst2_addr = NULL;
    uint8_t               *data_buf = NULL;
    int                    fdflags;
    te_bool                operation_done = TRUE;
    te_bool                nonblock_set = FALSE;
    te_bool                is_failed = FALSE;

    fdflag_set_func_type_t nonblock_func = UNKNOWN_SET_FDFLAG;

    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_FUNC(test_func, is_send);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_FDFLAG_SET_FUNC(nonblock_func);
    TEST_GET_BOOL_PARAM(nonblock_set);

    if (nonblock_set && nonblock_func == SOCKET_SET_FDFLAG)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        iut_s = rpc_socket(pco_iut,
                           rpc_socket_domain_by_addr(iut_addr1),
                           sock_type | RPC_SOCK_NONBLOCK,
                           RPC_PROTO_DEF);
        if (iut_s == -1)
            TEST_VERDICT("Call socket() with %s flag(s) failed",
                         socket_flags_rpc2str(RPC_SOCK_NONBLOCK));
    }
    else
        iut_s = rpc_socket(pco_iut,
                           rpc_socket_domain_by_addr(iut_addr1),
                           sock_type, RPC_PROTO_DEF);

    if (!tapi_onload_is_onload_fd(pco_iut, iut_s))
        TEST_VERDICT("Created socket is not accelerated");

    if (nonblock_func == FCNTL_SET_FDFLAG)
    {
        fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL,
                            RPC_O_NONBLOCK);
        if (fdflags & RPC_O_NONBLOCK)
        {
            RING_VERDICT("O_NONBLOCK is set on socket "
                         "by default");
            if (!nonblock_set)
                rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL,
                          fdflags & ~RPC_O_NONBLOCK &
                          ~RPC_O_NDELAY);
        }
        else if (nonblock_set)
            rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL,
                      fdflags | RPC_O_NONBLOCK);
    }

    fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL,
                        RPC_O_NONBLOCK);

    if ((fdflags & RPC_O_NONBLOCK) && !nonblock_set)
        TEST_VERDICT("O_NONBLOCK flag is unexpectedly set");
    else if (!(fdflags & RPC_O_NONBLOCK) && nonblock_set)
        TEST_VERDICT("O_NONBLOCK flag was not set as expected");

    if (sock_type == RPC_SOCK_DGRAM)
    {
        tst_s = rpc_socket(pco_tst2,
                           rpc_socket_domain_by_addr(tst2_addr),
                           sock_type, RPC_PROTO_DEF);
        rpc_connect(pco_tst2, tst_s, iut_addr1);
        rpc_connect(pco_iut, iut_s, tst2_addr);
    }
    else if (sock_type == RPC_SOCK_STREAM)
    {
        tst_s_listening =
            rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst2_addr),
                       sock_type, RPC_PROTO_DEF);
        rpc_bind(pco_tst2, tst_s_listening, tst2_addr);
        rpc_listen(pco_tst2, tst_s_listening, SOCKTS_BACKLOG_DEF);
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s, tst2_addr);
        if (rc < 0)
        {
            if (RPC_ERRNO(pco_iut) != RPC_EINPROGRESS)
                TEST_FAIL("connect() returned unexpected errno");
            else if (!nonblock_set)
            {
                RING_VERDICT("Blocking connect() failed with "
                             "EINPROGRESS errno");
                is_failed = TRUE;
            }
        }

        tst_s = rpc_accept(pco_tst2, tst_s_listening, NULL, NULL);
        rpc_close(pco_tst2, tst_s_listening);
    }
    else
        TEST_FAIL("Unexpected type of socket");

    if (tapi_onload_is_onload_fd(pco_iut, iut_s))
        TEST_VERDICT("Socket handover didn't happen");

    fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL,
                        RPC_O_NONBLOCK);

    if ((fdflags & RPC_O_NONBLOCK) && !nonblock_set)
    {
        is_failed = TRUE;
        RING_VERDICT("O_NONBLOCK flag is unexpectedly set after "
                     "handover");
    }
    else if (!(fdflags & RPC_O_NONBLOCK) && nonblock_set)
    {
        is_failed = TRUE;
        RING_VERDICT("O_NONBLOCK flag is not set as expected "
                     "after handover");
    }

    if (is_send)
        rpc_overfill_buffers(pco_iut, iut_s, NULL);

    data_buf = te_make_buf_by_len(DATA_BULK);
    pco_iut->op = RCF_RPC_CALL;
    rc = is_send ? ((rpc_send_f)test_func)(pco_iut, iut_s,
                                           data_buf, DATA_BULK, 0)
                 : ((rpc_recv_f)test_func)(pco_iut, iut_s,
                                           data_buf, DATA_BULK, 0);
    TAPI_WAIT_NETWORK;

    rcf_rpc_server_is_op_done(pco_iut, &operation_done);

    if (operation_done)
    {
        if (!nonblock_set)
        {
            ERROR_VERDICT("Data transmitting operation on socket "
                          "was not blocked despite unsetting "
                          "O_NONBLOCK flag before that");
            is_failed = TRUE;
        }

        pco_iut->op = RCF_RPC_WAIT;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = is_send ? ((rpc_send_f)test_func)(pco_iut, iut_s,
                                               data_buf, DATA_BULK, 0)
                     : ((rpc_recv_f)test_func)(pco_iut, iut_s,
                                               data_buf, DATA_BULK, 0);
        if (rc >= 0)
            TEST_VERDICT("Data transmitting operation unexpectedly "
                         "sucesseed");
        else if (!(nonblock_set && RPC_ERRNO(pco_iut) == RPC_EAGAIN))
            TEST_VERDICT("Data transmitting operation returned "
                         "unexpected errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));

    }
    else if (nonblock_set)
        TEST_VERDICT("Data transmitting operation on socket "
                     "was blocked despite setting O_NONBLOCK "
                     "flag before that");

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    free(data_buf);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s);
    if (operation_done)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    else
        rcf_rpc_server_restart(pco_iut);

    TEST_END;
}
