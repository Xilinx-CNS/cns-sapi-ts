/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_accept_dgram Usage of accept() function with connection-less sockets
 *
 * @objective Check that @b accept() function reports an appropriate error
 *            when it is used with connectionless sockets.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 * @param func      Function used to accept connection:
 *                  - @b accept()
 *                  - @b accept4()
 * @param func_flag Only for func=accept4. Possible flags:
 *                  - @b default
 *                  - @b nonblock
 *                  - @b cloexec
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Daria Terskikh <Daria.Terskikh@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_accept_dgram"

#include "sockapi-test.h"
#include "sockapi-ts_tcp.h"
#define BUF_LEN 64

const char    *func;
int            func_flag;

/**
 * Call @p func and check return
 *
 * @param pco_iut       IUT handle
 * @param iut_s         Socket on IUT
 * @param stage         Stage of test when function was called
 *
 */
static void
check_accept_return(rcf_rpc_server *pco_iut, int iut_s, char *stage)
{
    int    rc;

    RPC_AWAIT_IUT_ERROR(pco_iut);

    if (strcmp(func, "accept") == 0)
    {
        rc = rpc_accept(pco_iut, iut_s, NULL, NULL);
    }
    else if (strcmp(func, "accept4") == 0)
    {
	rc = rpc_accept4(pco_iut, iut_s, NULL, NULL, func_flag);
    }
    else
    {
        TEST_VERDICT("Not valid func value: %s", func);
    }
    if (rc != -1)
    {
        TEST_VERDICT("%s() unexpectedly succeded after %s", func, stage);
    }

    if (RPC_ERRNO(pco_iut) != RPC_EOPNOTSUPP)
    {
         TEST_VERDICT("%s() returned unexpected errno %r instead of EOPNOTSUPP "
		      "after %s",
                      func, RPC_ERRNO(pco_iut), stage);
    }
}


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;
    struct sockaddr_storage wildcard_addr;
    int                     iut_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(func);
    SOCKTS_GET_SOCK_FLAGS(func_flag);

    TEST_STEP("Create @b iut_s socket of type @c SOCK_DGRAM on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    TEST_STEP("Call @p func on @b iut_s. "
	      "Check that it returns @c -1 and sets @b errno to @c EOPNOTSUPP.");
    check_accept_return(pco_iut, iut_s, "creating socket");

    TEST_STEP("Bind @b iut_s to a local address.");
    assert(sizeof(wildcard_addr) >= te_sockaddr_get_size(iut_addr));
    memcpy(&wildcard_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));
    rpc_bind(pco_iut, iut_s, SA(&wildcard_addr));
    TEST_STEP("Call @p func on @b iut_s. "
	      "Check that it returns @c -1 and sets @b errno to @c EOPNOTSUPP.");
    check_accept_return(pco_iut, iut_s, "binding socket to local address");

    TEST_STEP("@b connect() @b iut_s to peer address.");
    rpc_connect(pco_iut, iut_s, iut_addr);
    TEST_STEP("Call @p func on @b iut_s. "
	      "Check that it returns @c -1 and sets @b errno to @c EOPNOTSUPP.");
    check_accept_return(pco_iut, iut_s, "connecting socket to peer address");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
