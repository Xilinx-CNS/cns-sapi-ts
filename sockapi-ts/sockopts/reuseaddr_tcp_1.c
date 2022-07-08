/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page sockopts-reuseaddr_tcp_1 With TCP it is not allowed to have a completely duplicate binding even if SO_REUSEADDR socket option is enabled
 *
 * @objective Check that @c SO_REUSEADDR socket option does not allow 
 *            to have more than one TCP socket bound to the same address.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1, @ref STEVENS
 *
 * @param pco_iut1  PCO on IUT
 * @param pco_iut2  PCO on IUT
 * 
 * @par Test sequence:
 * -# Create @p iut1_s socket of type @c SOCK_STREAM on @p pco_iut1.
 * -# Create @p iut2_s socket of type @c SOCK_STREAM on @p pco_iut2.
 * -# Call @b setsockopt() enabling @c SO_REUSEADDR socket option on 
 *    both sockets.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b Bind() @p iut1_s socket to a local address @p iut_addr.
 * -# Check that the function returns @c 0.
 * -# @b Bind() @p iut2_s socket to @p iut_addr, the same address @p iut1_s
 *    socket is bound to.
 * -# Check that the function returns @c -1 and sets @b errno to @c EADDRINUSE.
 *    See @ref sockopts_reuseaddr_tcp_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut1_s and @p iut2_s sockets.
 * 
 * @note
 * -# @anchor sockopts_reuseaddr_tcp_1
 *    This step is based on @ref STEVENS section 7.5 page 195, but on Linux 
 *    @b bind() does not check if there is a socket bound to the same address, 
 *    it is checked by @b listen(). So that @b listen() can return @c -1 and 
 *    set @b errno to @c EADDRINUSE, which is not specified in @ref XNS5.
 *    
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/reuseaddr_tcp_1"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut1 = NULL;
    rcf_rpc_server *pco_iut2 = NULL;

    int             iut1_s = -1;
    int             iut2_s = -1;
    int             opt_val = 1;
    
    const struct sockaddr *iut_addr;
    

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);    
    TEST_GET_ADDR(pco_iut1, iut_addr);
    
    iut1_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    iut2_s = rpc_socket(pco_iut2, rpc_socket_domain_by_addr(iut_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    
    rpc_setsockopt(pco_iut1, iut1_s, RPC_SO_REUSEADDR, &opt_val);
    rpc_setsockopt(pco_iut2, iut2_s, RPC_SO_REUSEADDR, &opt_val);
    
    rpc_bind(pco_iut1, iut1_s, iut_addr); 
    
    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rc = rpc_bind(pco_iut2, iut2_s, iut_addr);
    if (rc != -1)
    {
        WARN("bind() on 'iut2_s' socket returns %d instead of -1", rc);
    
        /*
         * Check that at least listen() forbids binding to 
         * the same address for more than one socket.
         */
        RPC_AWAIT_IUT_ERROR(pco_iut1);
        rc = rpc_listen(pco_iut1, iut1_s, SOCKTS_BACKLOG_DEF);
        if (rc == -1) {
            CHECK_RPC_ERRNO(pco_iut1, RPC_EADDRINUSE, "listen() on 'iut1_s' "
                            "socket returns -1, but");
            RING_VERDICT("first listen() failed");
        }
        
        RPC_AWAIT_IUT_ERROR(pco_iut2);
        rc = rpc_listen(pco_iut2, iut2_s, SOCKTS_BACKLOG_DEF);
        if (rc != -1)
        {
            TEST_VERDICT("listen() succeeded after binding to the same address "
                         "more than one socket at the same time");
        }
        CHECK_RPC_ERRNO(pco_iut2, RPC_EADDRINUSE, "listen() on 'iut2_s' "
                        "socket returns -1, but");

        RING_VERDICT("second listen() failed");
        TEST_SUCCESS;
    }
    CHECK_RPC_ERRNO(pco_iut2, RPC_EADDRINUSE, "bind() on 'iut2_s' "
                    "socket to a local address returns -1, but");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_s);

    TEST_END;
}

