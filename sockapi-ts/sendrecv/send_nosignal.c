/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-send_nosignal SIGPIPE and sender MSG_NOSIGNAL flag
 *
 * @objective Check sending of @c SIGPIPE, if the local end has been
 *            shut down on a connection oriented socket, and support
 *            of @c MSG_NOSIGNAL flag when sending.
 *
 * @type conformance
 *
 * @reference Linux 'send' function map page.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s1    stream socket on @p pco connected to @p tst_s1
 * @param iut_s2    stream socket on @p pco connected to @p tst_s2
 * @param pco_tst   tester PCO
 * @param tst_s1    stream socket on @p pco_tst connected to @p iut_s1
 * @param tst_s2    stream socket on @p pco_tst connected to @p iut_s2
 * @param func      function to be used in test to send data
 *                  (@b send(), @b sendto(), @b sendmsg(), @b sendmmsg(),
 *                   @b onload_zc_send() or @b onload_zc_send_user_buf())
 *
 * -# Register @c SIGPIPE signal handler on @p pco_iut PCO using
 *    @b signal() function.
 * -# Close @p tst_s1 socket.
 * -# Try to send data to @p iut_s1 using @p func function without
 *    @c MSG_NOSIGNAL flag.  The first call must return success
 *    (all data are sent).
 * -# Try to send data to @p iut_s1 using @p func function without
 *    @c MSG_NOSIGNAL flag once more.  The second call must return
 *    @c -1 with @c EPIPE in @b errno.
 * -# Check that registered signal handler caught @c SIGPIPE signal.
 * -# Close @p tst_s2 socket.
 * -# Try to send data to @p iut_s2 using @p func function with
 *    @c MSG_NOSIGNAL flag.  The first call must return success
 *    (all data are sent).
 * -# Try to send data to @p iut_s2 using @p func function with
 *    @c MSG_NOSIGNAL flag once more.  The second call must return
 *    @c -1 with @c EPIPE in @b errno.
 * -# Check that registered signal handler didn't catch @c SIGPIPE
 *    signal.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/send_nosignal"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define DATA_BULK       1024  /**< Data sent via socket per try */


static char tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_send_f func;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int     iut_s1 = -1;
    int     tst_s1 = -1;
    int     iut_s2 = -1;
    int     tst_s2 = -1;
    int     iut_s;
    ssize_t len;
    int     i;
    int     error = 0;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;

    rpc_sigset_p set = RPC_NULL;

    rpc_send_recv_flags flags = 0;

    TEST_START;

    /* Prepare sockets */

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SEND_FUNC(func);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s1, &iut_s1);

    TAPI_SET_NEW_PORT(pco_tst, tst_addr);
    TAPI_SET_NEW_PORT(pco_iut, iut_addr);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s2, &iut_s2);

    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    if ((set = rpc_sigreceived(pco_iut)) == RPC_NULL)
        TEST_FAIL("rpc_sigreceived() failed; errno %r", pco_iut->_errno);

    iut_s = iut_s1;
    for (i = 0; i < 2; i++)
    {
        if (rpc_sigemptyset(pco_iut, set) < 0)
            TEST_FAIL("rpc_sigemptyset() failed; errno %x",
                      pco_iut->_errno);

        if (i == 0)
            RPC_CLOSE(pco_tst, tst_s1);
        else
            RPC_CLOSE(pco_tst, tst_s2);
        TAPI_WAIT_NETWORK;

        RPC_AWAIT_ERROR(pco_iut);
        len = func(pco_iut, iut_s, tx_buf, DATA_BULK, flags);
        if (len < 0)
        {
            TEST_VERDICT("Sending function unexpectedly failed "
                         "with error " RPC_ERROR_FMT " in %d iteration",
                         RPC_ERROR_ARGS(pco_iut), i);
        }

        if (rpc_sigismember(pco_iut, set, RPC_SIGPIPE))
            TEST_VERDICT("Unexpected signal is received");

        /* Ensure there is no error on this socket */
        TAPI_WAIT_NETWORK;
        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &error);

        /* It's ok for the rpc_od_send function to wait longer because it
         * actually sends data by retransmits. */
        if (func == rpc_send_func_od_send)
            TAPI_WAIT_NETWORK;

        RPC_AWAIT_ERROR(pco_iut);
        len = func(pco_iut, iut_s, tx_buf, DATA_BULK, flags);

        if (len >= 0)
            TEST_FAIL("Send function returned non-negative value "
                      "instead expected -1");

        CHECK_RPC_ERRNO(pco_iut, RPC_EPIPE,
                        "Send function returned %d, but", len);

        if ((i == 0) != rpc_sigismember(pco_iut, set, RPC_SIGPIPE))
        {
            if (i == 0)
                TEST_FAIL("Expected signal is not received");
            else
                TEST_VERDICT("Unexpected signal is received");
        }

        iut_s = iut_s2;
        flags = RPC_MSG_NOSIGNAL;
    }

    TEST_SUCCESS;

cleanup:
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act, 
                              SIGNAL_REGISTRAR);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
