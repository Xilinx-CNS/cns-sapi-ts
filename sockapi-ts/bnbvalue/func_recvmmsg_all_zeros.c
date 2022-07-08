/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_recvmmsg_all_zeros Using recvmmsg() function with NULL mmsghdr, zero vlen and zero timeout
 *
 * @objective Check that @b recvmmsg() function successfully completes
 *            when it is called with @c NULL @b mmsghdr, zero vlen and
 *            zero timeout.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_recvmmsg_all_zeros"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    int                     iut_s = -1;
    rpc_socket_domain       domain;

    tarpc_timespec  timeout = { 0, 0 };

    TEST_START;

    /* Preambule */
    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);

    TEST_STEP("Create @c SOCK_DGRAM socket @b iut_s on @p pco_iut;");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Call @b recvmmsg() on @b iut_s, passing zero (@c NULL) values "
              "in all other arguments.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvmmsg_alt(pco_iut, iut_s, RPC_NULL, 0, 0, &timeout);

    TEST_STEP("Check that the function returns @c 0 and does not update "
              "@b errno variable.");
    if (rc == -1)
    {
        int err = RPC_ERRNO(pco_iut);

        TEST_VERDICT("recvmmsg() returns (-1) and "
                     "errno is set to %s",
                     errno_rpc2str(err));
    }
    if (rc != 0)
    {
         TEST_FAIL("recvmmsg() called on IUT with { 0, 0 } timeout "
                   "returns not 0 (%d)", rc);
    }
    /* Check that errno is not updated is done by the framework */

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;

}
