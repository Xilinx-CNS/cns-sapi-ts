/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_io_after_listen Usage of send/recv() functions on listening socket
 *
 * @objective Check that it is not permitted to call any send/receive
 *            function on listening socket.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 * @param func      Function to be called:
 *                  SEND type: send, sendto, sendmsg, sendmmsg, write,
 *                             writev, aio_write
 *                  RECV type: recv, recvfrom, recvmsg, read, readv,
 *                             aio_read
 *
 * @par Scenario:
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @b pco_iut.
 * -# @b bind() @p iut_s socket to a local address and port.
 * -# Call @b listen() on @p pco_iut socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @p func on @p iut_s socket.
 * -# Check that function returns @c -1.
 * -# If @p func is one from RECV type, check that @b errno is set to 
 *    @c ENOTCONN and no @c SIGPIPE signal delivered to the @p pco_iut.
 * -# If @p func is one from SEND type, check that @b errno is set to
 *    @c ENOTCONN or @c EPIPE. If @c EPIPE errno is set, @c SIGPIPE 
 *    signal should be delivered to the @p pco_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s socket.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_io_after_listen"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    int                iut_s = -1;

    const struct sockaddr  *iut_addr;
    void                   *func;
    te_bool                 is_send;
    rpc_errno               got_errno;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;
    rpc_sigset_p            received_set = RPC_NULL;

#define BUF_SIZE 100
    unsigned char           buf[BUF_SIZE];
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_FUNC(func, is_send);

    /*
     * Register SIGPIPE signal hander for the case some
     * functions generate it
     */
    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;
     
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = is_send ? ((rpc_send_f)(func))(pco_iut, iut_s, buf, sizeof(buf), 0)
                 : ((rpc_recv_f)(func))(pco_iut, iut_s, buf, sizeof(buf), 0);

    if (rc != -1)                                   
        TEST_FAIL("Function returned %d, but instead -1", rc);

    got_errno = RPC_ERRNO(pco_iut);
    if (got_errno == RPC_ENOTCONN)
    {
        /* The most logical behaviour, be silent */
    }
    else if (got_errno == RPC_EPIPE)
    {
        RING_VERDICT("%s() called on listening socket fails with "
                     "errno EPIPE",
                     is_send ? rpc_send_func_name(func)
                             : rpc_recv_func_name(func));
    }
    else
    {
        TEST_VERDICT("%s() called on listening socket fails with "
                     "unexpected errno %s",
                     is_send ? rpc_send_func_name(func)
                             : rpc_recv_func_name(func),
                     errno_rpc2str(got_errno));
    }

    /* Check that no SIGPIPE signal is sent */
    received_set = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, received_set, RPC_SIGPIPE);
    if (got_errno == RPC_ENOTCONN && rc != 0)
    {
        TEST_VERDICT("Unexpected SIGPIPE signal received while "
                     "calling %s() function on listening socket",
                     is_send ? rpc_send_func_name(func)
                             : rpc_recv_func_name(func));
    }
    else if (got_errno == RPC_EPIPE && rc != 1)
    {
        TEST_VERDICT("SIGPIPE signal is not received while calling %s() "
                     "function on listening socket",
                     is_send ? rpc_send_func_name(func)
                             : rpc_recv_func_name(func));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act, 
                              SIGNAL_REGISTRAR);

    TEST_END;
}

