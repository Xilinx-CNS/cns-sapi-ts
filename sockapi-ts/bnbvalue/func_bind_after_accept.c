/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_bind_after_accept Using bind() function after accept()
 *
 * @objective Check that @b bind() reports an appropriate error when it is called after @b accept().
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of type @c SOCK_STREAM on @b pco_iut.
 * -# Create @p pco_tst socket of type @c SOCK_STREAM on @b pco_tst.
 * -# Call @b listen() on @p pco_iut socket.
 * -# Call @b getsockname() on @p pco_iut socket to get local address
 *    @p local_addr.
 * -# @b connect() @p pco_tst socket to @p pco_iut socket using 
 *    @p iut_addr as a peer address with port retrieved from @p local_addr.
 * -# Call @b accept() on @p pco_iut socket to get a new @p accepted socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b bind() on @p accepted socket specifying @p local_addr address.
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p accepted, @p pco_iut and @p pco_tst sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_bind_after_accept"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;      
    rcf_rpc_server *pco_tst = NULL;     


    const struct sockaddr   *iut_addr;
    const struct sockaddr   *tst_addr = NULL;
    int                      iut_socket = -1;
    int                      tst_socket = -1;
    int                      accepted_socket = -1;
    struct sockaddr_storage  local_addr;
    socklen_t                local_addrlen;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_socket = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_socket = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_listen(pco_iut, iut_socket, SOCKTS_BACKLOG_DEF);

    local_addrlen = sizeof(local_addr);
    rpc_getsockname(pco_iut, iut_socket, SA(&local_addr), &local_addrlen);

    SIN(iut_addr)->sin_port = SIN(&local_addr)->sin_port;
    rpc_connect(pco_tst, tst_socket, iut_addr);

    accepted_socket = rpc_accept(pco_iut, iut_socket, NULL, NULL);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, accepted_socket, SA(&local_addr));
    if (rc != -1)
    {
        TEST_FAIL("bind() called after accept() on IUT "
                  "returned %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "bind() called after accept() on IUT returns -1");

    TEST_SUCCESS;
    
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);
    CLEANUP_RPC_CLOSE(pco_tst, tst_socket);
    CLEANUP_RPC_CLOSE(pco_iut, accepted_socket);

    TEST_END;
}
