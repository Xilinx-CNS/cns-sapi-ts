/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_bind_after_listen Using bind() function after listen()
 *
 * @objective Check that @b bind() reports an appropriate error when it is called after listen()
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of type @c SOCK_STREAM on @b pco_iut.
 * -# Call @b listen() on @p pco_iut socket.
 * -# Call @b bind() on @p pco_iut socket specifying a local address.
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 * -# Close @p pco_iut socket.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_bind_after_listen"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    
    
    const struct sockaddr *iut_addr;
    int                    iut_socket = -1;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);

    iut_socket = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_listen(pco_iut, iut_socket, SOCKTS_BACKLOG_DEF);
    if (rc == -1)
    {
        int err = RPC_ERRNO(pco_iut);
        
        if (err == RPC_EINVAL)
            TEST_VERDICT("listen() returns (-1) and "
                         "errno is set to EINVAL");
        else
            TEST_FAIL("listen() returns (-1) but errno"
                      "is set to %s instead of EINVAL",
                      errno_rpc2str(err));
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_socket, iut_addr);
    if (rc != -1)
    {
        TEST_FAIL("bind() called after listen() on IUT returned %d istead"
                  "of -1", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "bind called after listen() on IUT returns -1");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    TEST_END;
}
