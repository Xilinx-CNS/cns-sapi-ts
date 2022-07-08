/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_accept_stream_client Using accept() function with connection-oriented client sockets
 *
 * @objective Check that @b accept() function reports an error when it
 *            is used with client socket of type @c SOCK_STREAM.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
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

#define TE_TEST_NAME  "bnbvalue/func_accept_stream_client"
#define BUF_LEN 64

#include "sockapi-test.h"
#include "sockapi-ts_tcp.h"

static const char      *func;
int                     func_flag;

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

    if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
    {
         TEST_VERDICT("%s() returned unexpected errno %r instead of EINVAL "
		      "after %s",
                      func, RPC_ERRNO(pco_iut), stage);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;
    rcf_rpc_server  *pco_tst = NULL;
    int              iut_s = -1;
    int              tst_s = -1;

    const struct sockaddr  *tst_addr;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);
    SOCKTS_GET_SOCK_FLAGS(func_flag);

    TEST_STEP("Create @b iut_s socket of type @c SOCK_STREAM on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    
    TEST_STEP("Create @b tst_s socket of type @c SOCK_STREAM on @p pco_tst.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    TEST_STEP("@b bind() @b tst_s to a local address.");
    rpc_bind(pco_tst, tst_s, tst_addr);
    TEST_STEP("Call @b listen() on @b tst_s.");
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Call @p func on @b iut_s. "
	      "Check that it returns @c -1 and sets @b errno to @c EINVAL.");
    check_accept_return(pco_iut, iut_s, "listening on pco_tst socket");

    TEST_STEP("@b connect() @b iut_s to @b tst_s.");
    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("Call @p func on @b iut_s. "
	      "Check that it returns @c -1 and sets @b errno to @c EINVAL.");
    check_accept_return(pco_iut, iut_s, "connecting pco_iut socket to pco_tst socket");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;

}
