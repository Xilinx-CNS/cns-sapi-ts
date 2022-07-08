/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_connect_after_listen Using connect() function after listen()
 *
 * @objective Check that @b connect() function reports an
 *            error when it is used after @b listen() function.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param with_bind Whether to bind tested socket before @b listen() or not
 * @param env Testing environment
 *            - @ref arg_types_env_iut_ucast
 *            - @ref arg_types_env_iut_ucast_ipv6
 *
 *  @note
 * -# @anchor bnbvalue_func_connect_after_listen_1
 *    This step is based on @ref XNS5. But on Linux the function
 *    returns @c -1 and sets @b errno to @c EISCONN, as if the socket
 *    was connected but it is not.
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_connect_after_listen"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    int                iut_s = -1;
    te_bool            with_bind;

    const struct sockaddr  *iut_addr;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(with_bind);

    TEST_STEP("Create @b iut_s socket of type @c SOCK_STREAM on @b pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("If @p with_bind is set, then @b bind() @b iut_s socket to "
              "a local address, otherwise skip this step.");
    if (with_bind)
         rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("Call @b listen() on @b iut_s socket.");
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Call @b connect() on @b iut_s socket specifying some peer "
              "address.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, iut_addr);

    TEST_STEP("Check that the function returns @c -1 and sets @b errno to "
              "@c EOPNOTSUPP. See @ref bnbvalue_func_connect_after_listen_1 "
              "\"note 1\".");
    if (rc != -1)
    {
        TEST_FAIL("connect() called  on IUT returns %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EOPNOTSUPP,
                    "connect() called on IUT returns -1");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
