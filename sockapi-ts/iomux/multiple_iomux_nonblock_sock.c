/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-multiple_iomux_nonblock_sock Calling I/O multiplexer multiple times on nonblocking socket
 *
 * @objective Check behaviour of iomux function when it is called multiple
 *            times on a nonblocking socket
 *
 * @type conformance, compatibility
 *
 * @param pco_iut                       PCO with IUT
 * @param iut_addr                      Network address on IUT
 * @param iomux                         Type of I/O Multiplexing function
 * @param sock_type                     @c SOCK_STREAM or @c SOCK_DGRAM
 * @param ef_poll_nonblock_fast_usec    To which value
 *                                      EF_POLL_NONBLOCK_FAST_USEC
 *                                      environment variable should be set
 *
 * @par Scenario:
 * -# Set EF_POLL_NONBLOCK_FAST_USEC to required value and
 *    restart @p pco_iut.
 * -# Create a socket @p iut_s of type @p sock_type.
 * -# Set @c O_NONBLOCK flag for it.
 * -# @b connect() it to @p iut_addr.
 * -# Call @p iomux several times waiting for readable and
 *    writable events on the socket.
 * -# Check how many times iomux should be called until it
 *    returns 0.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/multiple_iomux_nonblock_sock"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;

    const char         *iomux;
    iomux_func          iomux_int;
    int                 iut_s = -1;
    rpc_socket_type     sock_type;
    int                 fdflags;
    int                 exp_rc = 0;
    int                 number;
    int                 last_rc;

    char                new_val[RCF_MAX_VAL];
    char               *old_env_val = NULL;
    te_bool             env_changed = FALSE;
    int                 ef_poll_nonblock_fast_usec;
    cfg_handle          env_var_handle;
    int                 zero_rc;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(iomux);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(ef_poll_nonblock_fast_usec);

    snprintf(new_val, RCF_MAX_VAL, "%d", ef_poll_nonblock_fast_usec);
    env_var_handle = sockts_set_env(pco_iut, "EF_POLL_NONBLOCK_FAST_USEC",
                                    new_val, &old_env_val);
    env_changed = TRUE;

    iomux_int = str2iomux(iomux);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_GETFL, RPC_O_NONBLOCK);
    fdflags |= RPC_O_NONBLOCK;
    fdflags = rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, fdflags);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, iut_addr);

    if (sock_type == RPC_SOCK_DGRAM && rc < 0)
        RING_VERDICT("connect() unexpectedly failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    else if (sock_type == RPC_SOCK_STREAM)
    {
        if (rc >= 0)
            RING_VERDICT("connect() unexpectedly successeed");
        else if (RPC_ERRNO(pco_iut) != RPC_EINPROGRESS)
            RING_VERDICT("connect() failed with strange errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    /*
     * On not connected SOCK_STREAM socket select() and pselect()
     * report both readable and writable events - so 2 is returned.
     */
    exp_rc = (sock_type == RPC_SOCK_DGRAM ? 1 :
              ((iomux_int == FUNC_SELECT ||
                iomux_int == FUNC_PSELECT) ? 2 : 1));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_multiple_iomux(pco_iut, iut_s, iomux_int,
                            RPC_POLLIN | RPC_POLLOUT, 10, -1,
                            exp_rc, &number, &last_rc, &zero_rc);

    if (rc < 0 && (last_rc >= 0 && number == 10))
        TEST_VERDICT("multiple_iomux() unexpectedly failed");

    if (last_rc < 0)
        TEST_VERDICT("%s() unexpectedly failed with errno %s "
                     "when called %d time",
                     iomux,
                     errno_rpc2str(RPC_ERRNO(pco_iut)),
                     number + 1);
    else if (last_rc != exp_rc && last_rc != 0)
        TEST_VERDICT("%s() returned strange value when called %d time",
                     iomux, number + 1);
    else if (number == 0)
        TEST_VERDICT("%s() does not return any events at all",
                     iomux);
    else if (number == 1)
        TEST_VERDICT("%s() returns events only when called the "
                     "first time", iomux);
    else if (number < 10)
        TEST_VERDICT("%s() returns events only several times",
                     iomux);

    if (zero_rc != 0)
        TEST_VERDICT("iomux returned zero");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (env_changed)
        CLEANUP_CHECK_RC(sockts_restore_env(pco_iut, env_var_handle,
                                            old_env_val));


    TEST_END;
}
