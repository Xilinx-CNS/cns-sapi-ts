/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page sockopts-reuseaddr_tcp_3 Usage of SO_REUSEADDR socket option for binding TCP sockets to the same port but different network addresses
 *
 * @objective Check that @c SO_REUSEADDR socket option allows multiple 
 *            instances of the same server to be started on the same port, 
 *            as long as each instance binds a different local network address.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1, @ref STEVENS
 *
 * @param pco_iut1  PCO on IUT
 * @param pco_iut2  PCO on IUT
 * 
 * @par Test sequence:
 * -# Make sure that there are at least two network addresses assigned on 
 *    the IUT, otherwise add network addresses, so that IUT has two 
 *    addresses @p iut1_addr, and @p iut2_addr.
 * -# Create @p iut1_s socket of type @c SOCK_STREAM on @p pco_iut1.
 * -# Create @p iut2_s socket of type @c SOCK_STREAM on @p pco2_iut.
 * -# Call @b setsockopt() enabling @c SO_REUSEADDR socket option on both 
 *    sockets.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b bind() @p iut1_s socket to @p iut1_addr network address and port @p P.
 * -# Check that the function returns @c 0.
 * -# @b bind() @p iut2_s socket to @p iut2_addr network address and port @p P.
 * -# Check that the function returns @c 0.
 * -# Call @b listen() on @p iut1_s socket.
 * -# Check that the function returns @c 0.
 * -# Call @b listen() on @p iut2_s socket.
 * -# Check that the function returns @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close all the sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/reuseaddr_tcp_3"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut1 = NULL;
    rcf_rpc_server *pco_iut2 = NULL;

    int             iut1_s = -1;
    int             iut2_s = -1;
    int             opt_val;

    const struct sockaddr *iut1_addr;
    const struct sockaddr *iut2_addr;


    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_ADDR(pco_iut1, iut1_addr);
    TEST_GET_ADDR(pco_iut2, iut2_addr);

    iut1_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut1_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut2_s = rpc_socket(pco_iut2, rpc_socket_domain_by_addr(iut2_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

    opt_val = 1;
    rpc_setsockopt(pco_iut1, iut1_s, RPC_SO_REUSEADDR, &opt_val);
    rpc_setsockopt(pco_iut2, iut2_s, RPC_SO_REUSEADDR, &opt_val);

    /* Copy port of 'iut1_addr' to 'iut2_addr' */
    /* FIXME Discard 'const' */
    te_sockaddr_set_port(SA(iut2_addr), te_sockaddr_get_port(iut1_addr));

    rpc_bind(pco_iut1, iut1_s, iut1_addr);
    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rc = rpc_bind(pco_iut2, iut2_s, iut2_addr);
    if (rc != 0)
    {
        TEST_FAIL("bind() on 'iut2_s' socket returns %d instead of 0", rc);
    }

    rpc_listen(pco_iut1, iut1_s, SOCKTS_BACKLOG_DEF);
    rpc_listen(pco_iut2, iut2_s, SOCKTS_BACKLOG_DEF);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_s);

    TEST_END;
}

