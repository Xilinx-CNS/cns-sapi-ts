/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_listen_after_connect Using of listen() function after connect()
 *
 * @objective Check that @b listen() function reports an appropriate error
 *            when it is used after @b connect()
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
 * -# Call @b connect() to connect @p pco_iut socket to @p pco_tst socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b listen() on @p pco_iut socket.
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 *    See @ref bnbvalue_func_listen_after_connect_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut and @p pco_tst sockets.
 *
 * @note
 * -# @anchor bnbvalue_func_listen_after_connect_1
 *    This step is based on @ref XNS5, but on FreeBSD it is allowed
 *    to call @b listen() on client socket, and this leads to
 *    unpredictable situation.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_listen_after_connect"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr *tst_addr;
    
    rpc_socket_domain domain;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    domain = rpc_socket_domain_by_addr(tst_addr);

    /* Scenario */

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_iut, iut_s, tst_addr);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    if (rc != -1)
    {
         TEST_FAIL("listen() called after connect() on IUT "
                   "returns %d instead of -1", rc);
    }
    
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
            "listen() called after connect() on IUT returns -1");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
