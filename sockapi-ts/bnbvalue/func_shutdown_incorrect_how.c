/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_shutdown_incorrect_how Using shutdown() with inappropriate value of how parameter
 *
 * @objective Check that @b shutdown() function reports an error when it is called with unknown value of @a how parameter.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param type          Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param pco_tst       tester PCO
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of type @p type
 *    on @p pco_iut and connect it with socket on @p pco_tst.
 * -# Call @b shutdown() on @p pco_iut socket specifying unknown how as
 *    the value of @a how parameter.
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 * -# Close sockets on @p pco_iut and @p pco_tst.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_shutdown_incorrect_how"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rpc_socket_type    sock_type;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    TEST_START;

    /* Preambule */
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    /* Scenario */
    GEN_CONNECTION_WILD(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s, TRUE);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_UNKNOWN);
    if (rc != -1)
    {
         TEST_FAIL("shutdown() called on IUT returns %d instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "shutdown() called on IUT returns -1");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
