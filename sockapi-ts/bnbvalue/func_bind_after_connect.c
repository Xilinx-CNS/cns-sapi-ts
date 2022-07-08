/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_bind_after_connect Using bind() function after connect()
 *
 * @objective Check that @b bind() reports an appropriate error when
 *            it is called after @b connect().
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
 * -# @b bind() @p pco_tst socket to a local address.
 * -# Call @b listen() on @p pco_tst socket.
 * -# Call @p connect() to connect @p pco_iut socket to @p pco_tst socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b bind() on @p pco_iut socket specifying a local address.
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut and @p pco_tst sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_bind_after_connect"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;         /* pointer to PCO on UIT */
    rcf_rpc_server *pco_tst = NULL;         /* pointer to PCO on TESTER */
        
    
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    
    
    int iut_socket = -1;
    int tst_socket = -1;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_socket = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_socket = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_socket, tst_addr);
    rpc_listen(pco_tst, tst_socket, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_iut, iut_socket, tst_addr);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_socket, iut_addr);
    if (rc != -1)
    {
        TEST_FAIL("bind() called after connect() on IUT returns %d "
                  "instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "bind() called after accept() on IUT returned -1");

    TEST_SUCCESS;
cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);
    CLEANUP_RPC_CLOSE(pco_tst, tst_socket);

    TEST_END;
}
