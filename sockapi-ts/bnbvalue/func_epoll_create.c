/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_epoll_create Using epoll_create() function with incorrect size
 *
 * @objective Check that @b epoll_create() function correctly reports an
 *            error when @c size is negative.
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 *
 * @par Scenario:
 * -# Call @b epoll_create() function with negative value of @c size.
 * -# Check that @b epoll_create() returns @c -1 and sets errno
 *    to @c EINVAL.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_create"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int epfd = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    epfd = rpc_epoll_create(pco_iut, -1);
    if (epfd != -1)
        TEST_VERDICT("epoll_create(-1) returned success");

    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "epoll_create() called with negative timeout "
                    "returns -1");

    TEST_SUCCESS;
    
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd);

    TEST_END;
}
