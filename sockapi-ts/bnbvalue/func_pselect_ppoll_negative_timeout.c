/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_pselect_ppoll_negative_timeout Using pselect() and ppoll() functions with negative timeout
 *
 * @objective Check that @b pselect() and @b ppoll() functions report an
 *            error while using with negative timeout.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut - PCO on IUT
 * @param iomux   - Use @b pselect() or @b ppoll()
 *
 * @note The test is run on @p pco_iut
 *
 * @par Scenario:
 * -# Call @p iomux with @c NULL descriptor sets, @c NULL @a sigmask
 *    parameter. As the value of @a timeout parameter use the following
 *    combinations:
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
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_pselect_ppoll_negative_timeout"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    unsigned int       i;
    rcf_rpc_server    *pco_iut = NULL;
    const char        *iomux;
    te_bool            operation_done;

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
    TEST_GET_STRING_PARAM(iomux);

    if (rpc_get_sizeof(pco_iut, "long") == 4) /* 32-bit IUT */
    {
        timeouts[2].tv_nsec = INT32_MIN;
        output_timeouts[2].tv_nsec = INT32_MIN;
    }

    /* Scenario */
    for (i = 0; i < sizeof(timeouts) / sizeof(struct tarpc_timespec);
                i++)
    {
         pco_iut->op = RCF_RPC_CALL;
         if (strcmp(iomux, "pselect") == 0)
            rc = rpc_pselect(pco_iut, 0, RPC_NULL, RPC_NULL, RPC_NULL,
                             &timeouts[i], RPC_NULL);
         else if (strcmp(iomux, "ppoll") == 0)
            rc = rpc_ppoll(pco_iut, RPC_NULL, 0, &timeouts[i], RPC_NULL);
         else
             TEST_FAIL("Incorrect value of 'iomux' parameter");

         MSLEEP(100);
         rcf_rpc_server_is_op_done(pco_iut, &operation_done);

         if (!operation_done)
         {
             RING_VERDICT("%s() function hangs with %s timeout.", iomux,
                          tarpc_timespec2str(&output_timeouts[i]));
            if ((rc = rcf_rpc_server_restart(pco_iut)) != 0)
                TEST_FAIL("Failed to restart pco_iut: %r", rc);
             continue;
         }

         RPC_AWAIT_IUT_ERROR(pco_iut);
         pco_iut->op = RCF_RPC_WAIT;
         if (strcmp(iomux, "pselect") == 0)
            rc = rpc_pselect(pco_iut, 0, RPC_NULL, RPC_NULL, RPC_NULL,
                             &timeouts[i], RPC_NULL);
         else if (strcmp(iomux, "ppoll") == 0)
            rc = rpc_ppoll(pco_iut, RPC_NULL, 0, &timeouts[i], RPC_NULL);
         else
             TEST_FAIL("Incorrect value of 'iomux' parameter");

         if (rc != -1)
         {
              RING_VERDICT("%s() called  on IUT with %s timeout "
                           "returns %X instead of -1",
                           iomux, tarpc_timespec2str(&output_timeouts[i]),
                           rc);
              continue;
         }

         CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "pselect() called  on IUT "
                         "with %s returns -1",
                         tarpc_timespec2str(&output_timeouts[i]));
    }

    TEST_SUCCESS;

cleanup:
    TEST_END;
}
