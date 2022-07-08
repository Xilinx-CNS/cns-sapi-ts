/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_recvmmsg_negative_timeout Using recvmmsg() function with negative timeout
 *
 * @objective Check that @b recvmmsg() function reports an error while using
 *            with negative timeout.
 *
 * @type conformance, robustness
 *
 * @param pco_iut - PCO on IUT
 * @param domain  - PF_INET or PF_INET6
 *
 * @par Scenario:
 * -# Create @c SOCK_DGRAM socket @p iut_s;
 * -# Call @b recvmmsg() with @p iut_s socket with @c NULL @p mmsg and
 *    @c 0 @p vlen parameter. As the value of @a timeout parameter use the
 *    following combinations:
 * @table_start
 * @row_start
 *     @entry_start @a tv_sec @entry_end
 *     @entry_start @a tv_nsec @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c -1 @entry_end
 *     @entry_start @c  0 @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c -1 @entry_end
 *     @entry_start @c  1 @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c 0 @entry_end
 *     @entry_start @c LONG_MIN @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c  0 @entry_end
 *     @entry_start @c -2000 @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c  1 @entry_end
 *     @entry_start @c -2000 @entry_end
 * @row_end
 * @table_end
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL;
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_recvmmsg_negative_timeout"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    unsigned int       i;
    rcf_rpc_server    *pco_iut = NULL;
    int                sock = -1;
    rpc_socket_domain  domain;
    
    struct tarpc_timespec    timeouts[] = {
        { -1,         0 },
        { -1,         1 },
        {  0, INT64_MIN },
        { -1,        -1 },
        /* -2000 is used instead of -1 (see bug 5329 for details) */
        {  0,        -2000 },
        {  1,        -2000 }
    };

    struct tarpc_timespec    output_timeouts[] = {
        { -1,         0 },
        { -1,         1 },
        {  0, INT64_MIN },
        { -1,        -1 },
        {  0,        -2000 },
        {  1,        -2000 }
    };

    TEST_START;

    /* Preambule */
    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);

    sock = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    if (rpc_get_sizeof(pco_iut, "long") == 4) /* 32-bit IUT */
    {
        timeouts[2].tv_nsec = INT32_MIN;
        output_timeouts[2].tv_nsec = INT32_MIN;
    }

    /* Scenario */
    for (i = 0; i < sizeof(timeouts) / sizeof(struct tarpc_timespec); 
                i++)
    {
         RPC_AWAIT_IUT_ERROR(pco_iut);
         rc = rpc_recvmmsg_alt(pco_iut, sock, RPC_NULL, 0, 0, &timeouts[i]);

         if (rc != -1)
         {
              TEST_FAIL("recvmmsg() called  on IUT with %s timeout "
                        "returns %X instead of -1",
                        tarpc_timespec2str(&output_timeouts[i]), rc);
         }

         CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "recvmmsg() called  on IUT with "
                         "%s returns -1", 
                         tarpc_timespec2str(&output_timeouts[i]));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, sock);
    TEST_END;
}
