/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocpgrp Usage of SIOCGPGRP and SIOCSPGRP requests
 *
 * @objective Check that @c SIOCSPGRP request sets the owner of the socket
 *            and @c SIOCGPGRP request to get the current owner of the
 *            socket.
 * 
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on TESTER
 * @param sock_type             Socket type (@c SOCK_STREAM or @c SOCK_DGRAM)
 * @param close_inherited_sock  Wheter to close inheritied after 
 *                              @b fork() socket or not
 * 
 * @param iut_s     Socket reside on @p pco_iut and connected to
 *                  @p tst_s socket
 * @param tst_s     Socket reside on @p pco_tst and connected to
 *                  @p iut_s socket
 *
 * @par Test sequence:
 * -# Create @p tx_buf buffer of size @p buf_len;
 * -# Create @p rx_buf buffer of size @p buf_len;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl() with @c SIOCGPGRP request on @p iut_s socket to
 *    get initial value of this request;
 * -# Check that @b ioctl() returns @c 0 and the value of 
 *    the request is @c 0;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Get pid of the @p pco_iut - @p iut_pid;
 * -# @b fork() @p pco_iut and get pid of @p iut_child - @p iut_child_pid;
 * -# If @p close_inherited_sock parameter is true, @b close @p iut_s 
 *    socket on @p iut_child process (it is inherited from @p pco_iut process)
 * -# Register @p iut_child on receiving @c SIGIO signal;
 * -# Register @p pco_iut on receiving @c SIGIO signal;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl(@p iut_s, @c SIOCSPGRP, @p iut_child_pid) to set the
 *    child process as an owner of @p iut_s socket;
 * -# Log the result of the function and the value of @b errno.
 *    See @ref ioctls_siocgpgrp_1 "note 1";
 * -# There might be two possible cases:
 *        - Function returns @c -1 and sets @b errno to @c EPERM, because
 *          there are not enough rights to set owner different from the 
 *          current process. See @ref ioctls_siocgpgrp_2 "note 2".
 *          In this case call @b ioctl(@p iut_s, @c SIOCSPGRP, @p iut_pid)
 *          to set the @p pco_iut process as the owner of @p iut_s socket;
 *        - Function returns @c 0, allowing to set as an owner child
 *          process.
 *        .
 * -# Call @b ioctl() enabling @c FIOASYNC request on @p iut_s socket;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() @p tx_buf buffer from @p tst_s socket;
 * -# Check that @p pco_iut or @p iut_child receives @c SIGIO signal
 *    (which process should actually get the signal depends on the behaviour
 *    described on step 12);
 * -# @b recv(@p iut_s, @p rx_buf, @p buf_len, @c 0);
 * -# Check that @p tx_buf and @p rx_buf buffers have the same content;
 * -# Call @b ioctl() with @c SIOCGPGRP request on @p iut_s socket to
 *    get current value of this request;
 * -# Check that the value of the request equals to @p iut_pid or 
 *    @p iut_child_pid depending on the behaviour described on step 12)
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete @p tx_buf and @p rx_buf buffers.
 *
 * @note
 * -# @anchor ioctls_siocgpgrp_1
 *    On Linux it is allowed to set any process in the system as an owner of
 *    the socket (under superuser rights), but on FreeBSD the owner can be
 *    only current process @b ioctl() is called from;
 * -# @anchor ioctls_siocgpgrp_2
 *    This behaviour is based on Linux when the process has no superuser
 *    rights, on FreeBSD @b errno is set to @c ESRCH.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocpgrp"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    /* Name of the RPC server */
    const char     *rpc_serv_name = "ioctls-siocpgrp";
    
    rpc_socket_type    sock_type;
    te_bool            close_inherited_sock;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    rcf_rpc_server    *iut_child = NULL;
    int                iut_s = -1;
    int                tst_s = -1;
    te_bool            is_failed = FALSE;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;
    int                     req_val;
    int                     owner_pid;
    rpc_sigset_p            iut_sigmask = RPC_NULL;
    rpc_sigset_p            iut_child_sigmask = RPC_NULL;
    int                     iut_sig_arrived;
    int                     iut_child_sig_arrived;
    te_bool                 iut_child_owner = TRUE;
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;
    te_bool                 use_wildcard = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(close_inherited_sock);
    TEST_GET_BOOL_PARAM(use_wildcard);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, use_wildcard);

    /* Scenario */
    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, RPC_SIOCGPGRP, &req_val);
    if (rc != 0)
    {
        TEST_FAIL("Getting initial value of SIOCGPGRP IOCTL request fails: "
                  "ioctl(SIOCGPGRP) returns %d", rc);
    }
    
    CHECK_RC(rcf_rpc_server_fork(pco_iut, rpc_serv_name, &iut_child));

    /* Close pco_iut socket on 'iut_child' */
    if (close_inherited_sock)
        rpc_close(iut_child, iut_s);
    
    /* Register iut_child on receiving SIGIO signal */
    CHECK_RC(tapi_sigaction_simple(iut_child, RPC_SIGIO,
                                   SIGNAL_REGISTRAR, NULL));
    
    /* Register pco_iut on receiving SIGIO signal */
    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGIO,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    /* 
     * Set owner of pco_iut socket as any arbitrary process
     * (in our case it is a child process)
     */
    owner_pid = req_val = rpc_getpid(iut_child);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, RPC_SIOCSPGRP, &req_val);
    
    if (rc != 0)
    {
        int err = RPC_ERRNO(pco_iut);
        
        iut_child_owner = FALSE;

        if (err != 0)
        {
            RING_VERDICT("It is not allowed to set an arbitrary process as "
                         "the owner of a socket: "
                         "ioctl(SIOCSPGRP) returns %d and sets errno to %X",
                         rc, TE_RC_GET_ERROR(err));

            /* 
             * Set owner of pco_iut socket as the process pco_iut socket is 
             * created in
             */
            owner_pid = req_val = rpc_getpid(pco_iut);
            rpc_ioctl(pco_iut, iut_s, RPC_SIOCSPGRP, &req_val);
        }
    }
    
    /* Turn on FIOASYNC request on 'iut_s' socket */
    req_val = 1;
    rpc_ioctl(pco_iut, iut_s, RPC_FIOASYNC, &req_val);

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);
    TAPI_WAIT_NETWORK;

    /* 
     * Check that SIGIO signal is delivered only to the owner of the socket
     */
    iut_sigmask = rpc_sigreceived(pco_iut);
    iut_child_sigmask = rpc_sigreceived(iut_child);

    iut_sig_arrived = rpc_sigismember(pco_iut, iut_sigmask, RPC_SIGIO);
    iut_child_sig_arrived = rpc_sigismember(iut_child, iut_child_sigmask,
                                            RPC_SIGIO);
    
    if (iut_child_owner)
    {
        if (iut_sig_arrived)
        {
            RING_VERDICT("'pco_iut' process receives SIGIO signal, "
                         "but it is not the owner of 'iut_s' socket");
            is_failed = TRUE;
        }

        if (!iut_child_sig_arrived)
        {
            RING_VERDICT("'iut_child' process does not receive SIGIO signal, "
                         "although it is the owner of 'iut_s' socket");
            is_failed = TRUE;
        }
    }
    else
    {
        if (iut_child_sig_arrived)
        {
            RING_VERDICT("'iut_child' process receives SIGIO signal, "
                         "but it is not the owner of 'iut_s' socket");
            is_failed = TRUE;
        }

        if (!iut_sig_arrived)
        {
            RING_VERDICT("'pco_iut' process does not receive SIGIO signal, "
                         "although it is the owner of 'iut_s' socket");
            is_failed = TRUE;
        }
    }

    /* Receive the data */
    rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);

    if (memcmp(tx_buf, rx_buf, buf_len) != 0)
    {
        TEST_FAIL("The content of 'tx_buf' and 'rx_buf' are not the same");
    }

    /* Check that the owner of 'pco_iut' socket is not changed */
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGPGRP, &req_val);

    if (owner_pid != req_val)
    {
        TEST_VERDICT("Owner of 'iut_s' socket has changed after receiving "
                     "some data on the socket");
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    if (iut_child != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(iut_child));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGIO, &old_act, 
                              SIGNAL_REGISTRAR);
    free(tx_buf);
    free(rx_buf);        
    
    TEST_END;
}

