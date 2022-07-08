/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_listen_dgram Usage of listen() function with connectionless sockets
 *
 * @objective Check that @b listen() function reports an appropriate error
 *            when it is used with connectionless sockets.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_listen_dgram"

#include "sockapi-test.h"


/**
 * Call listen and check listen return
 *
 * @param pco_iut         - IUT handle
 * @param iut_s       - socket on IUT
 *
 * @return  FALSE     - listen has returned not (-1)  or
 *                         incorrectly established RPC_errno
 *          TRUE      - listen returned -1 and established
 *                         RPC_errno in RPC_EOPNOTSUPP
 */
te_bool
check_listen_return(rcf_rpc_server *pco_iut, int iut_s)
{
     int   rc;
     int   err;

     RPC_AWAIT_IUT_ERROR(pco_iut);
     rc = rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
     if (rc != -1)
     {
          ERROR("RPC listen() on IUT has returned not (-1)");
          return FALSE;
     }

     err = RPC_ERRNO(pco_iut);
     if (err != RPC_EOPNOTSUPP)
     {
         ERROR("RPC listen() on IUT has incorrectly"
               "established RPC_errno, expected %X (=%X)",
               TE_RC_GET_ERROR(RPC_EOPNOTSUPP), TE_RC_GET_ERROR(err));
         return FALSE;
     }

     return TRUE;
}


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;

    const struct sockaddr  *iut_addr = NULL;

    int                     iut_s = -1;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);

    TEST_STEP("Create @b iut_s socket of type @c SOCK_DGRAM on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Call @b listen() on @b iut_s socket, check that the function "
              "returns @c -1 and sets @b errno to @c EOPNOTSUPP.");
    if (!check_listen_return(pco_iut, iut_s))
        TEST_STOP;

    TEST_STEP("Bind @b iut_s socket to a local address.");
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("Call @b listen() on @b iut_s socket, check that the function "
              "returns @c -1 and sets @b errno to @c EOPNOTSUPP.");
    if (!check_listen_return(pco_iut, iut_s))
        TEST_STOP;

    TEST_STEP("Call @b connect() on @b iut_s socket.");
    rpc_connect(pco_iut, iut_s, iut_addr);

    TEST_STEP("Call @b listen() on @b iut_s socket, check that the function "
              "returns @c -1 and sets @b errno to @c EOPNOTSUPP.");
    if (!check_listen_return(pco_iut, iut_s))
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
