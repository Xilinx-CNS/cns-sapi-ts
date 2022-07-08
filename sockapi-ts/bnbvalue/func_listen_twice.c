/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_listen_twice Usage listen() function more than once on the same socket
 *
 * @objective Check that @b listen() function allows to be called 
 *            more than once on the same socket.
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
 * -# @b bind() @p pco_iut socket to a local address;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b listen() on @p pco_iut socket;
 * -# Check that the function returns @c 0.
 * -# Call @b listen() on @p pco_iut socket;
 * -# Check that the function returns @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b connect() @p pco_tst socket to @p pco_iut socket;
 * -# Check that @b connect() returns @c 0;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut and @p pco_tst sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_listen_twice"

#include "sockapi-test.h"


#define TST_NUMBER_LISTEN_CALLS    2


int
main(int argc, char *argv[])
{
    rcf_rpc_server   *pco_iut = NULL;
    rcf_rpc_server   *pco_tst = NULL;
    int               iut_s = -1;
    int               tst_s = -1;
    int               i;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);

    for (i = 0; i < TST_NUMBER_LISTEN_CALLS; i++)
         rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
