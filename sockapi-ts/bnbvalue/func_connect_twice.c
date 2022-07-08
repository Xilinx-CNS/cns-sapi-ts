/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_connect_twice Usage connect() function more than one with connection-oriented sockets
 *
 * @objective Check that @b connect() function reports an error when
 *            it is called more than once on the same socket.
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
 * -# @b bind() @p pco_tst socket to a local address - @p peer_addr.
 * -# Call @b listen() on @p pco_tst socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b connect() to connect @p pco_iut socket to @p pco_tst socket using 
 *    @p peer_addr.
 * -# Check that the function returns @c 0.
 * -# Once again call @b connect() on @p pco_iut socket specifying 
 *    some peer address (it might be even the same @b peer_addr).
 * -# Check that the function returns @c -1 and sets @b errno to @c EISCONN.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut and @p pco_tst sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Dmitrij Komoltsev <Dmitrij.Komoltsev@oktetlabs.ru> (@b ConnectEx())
 */

#define TE_TEST_NAME  "bnbvalue/func_connect_twice"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    const struct sockaddr *tst_addr;
    const struct sockaddr *iut_addr;

    rpc_socket_domain domain;

    TEST_START;

    /* Preambule */
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    domain = rpc_socket_domain_by_addr(tst_addr);

    /* Scenario */
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_iut, iut_s, tst_addr);
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    
    if (rc != -1)
    {
         TEST_FAIL("connect() called  on IUT second time"
                   "returns %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EISCONN,
            "connect() called on IUT second time returns -1");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
