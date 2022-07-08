/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_bind_after_implicit_bind_udp Using bind() function after connect()/sendto() called on socket SOCK_STREAM type
 *
 * @objective Check that @b bind() reports an appropriate error when
 *            it is called after @b connect()/sendto().
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
 * @param func      @b connect(), @b sendto()
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of type @c SOCK_DGRAM on @b pco_iut.
 * -# Call @p func() on @p pco_iut socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b bind() on @p pco_iut socket specifying a local address.
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p pco_iut socket.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_bind_after_implicit_bind_udp"

#include "sockapi-test.h"

#define TST_BUFFER_LEN      1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;


    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    const char            *func;

    int                    iut_s = -1;
    uint8_t                buffer[TST_BUFFER_LEN];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(func, "connect") == 0)
        rc = rpc_connect(pco_iut, iut_s, tst_addr);
    else if (strcmp(func, "sendto") == 0)
        rc = rpc_sendto(pco_iut, iut_s, buffer, TST_BUFFER_LEN, 0, tst_addr);
    else
        TEST_FAIL("Unknown function is testing");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_s, iut_addr);
    if (rc != -1)
    {
        TEST_FAIL("bind() called after %s on IUT returns %d "
                  "instead of -1", func, rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "bind() called after %s on IUT returned -1", func);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
