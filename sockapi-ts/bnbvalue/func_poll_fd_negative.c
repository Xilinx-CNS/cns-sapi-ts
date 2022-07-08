/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_poll_fd_negative Using poll() function with pollfd entries whose fd member set to a negative value
 *
 * @objective Check that @b poll() function correctly processes situation
 *            when @c pollfd entry contains @a fd field set to a negative
 *            value
 *
 * @type conformance, robustness
 *
 * @reference @ref STEVENS, section 6.10
 *
 * @param pco_iut   PCO on IUT
 * @param evt       Event we are interested in
 * @param nfds      Number of entries with negative @a fd field
 *
 * @par Scenario:
 * -# Prepare @p ufds - an array of @c pollfd structures with @p nfds
 *    elements and fill in each structure as follows:
 *        - @a fd      - @b -1;
 *        - @a events  - @p evt;
 *        - @a revents - @c 0xffff.
 *        .
 * -# Call @b poll(@p ufds, @p nfds, @p timeout);
 * -# Check that the function returns @c 0 and its duration is @p timeout
 *    milliseconds;
 * -# Check that @a revents field of the structure is updated to @c 0.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_poll_fd_negative"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rpc_poll_event     evt;
    int                timeout;
    int                nfds;
    int                i;    
    struct rpc_pollfd *ufds = NULL;


    TEST_START;

    /* Preambule */
    TEST_GET_PCO(pco_iut);
    TEST_GET_POLL_EVT(evt);
    TEST_GET_INT_PARAM(nfds);
                 
    timeout = rand_range(0, 1000);

    if (nfds < 1)
    {
        TEST_FAIL("'nfds' parameter should be at least 1");
    }
    
    CHECK_NOT_NULL(ufds = calloc(nfds, sizeof(*ufds)));

    /* Scenario */
    for (i = 0; i < nfds; i++)
    {
        ufds[i].fd = -1;
        ufds[i].events = evt;
        ufds[i].revents = 0xFFFF;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_poll(pco_iut, ufds, nfds, timeout);
    if (rc != 0)
    {
        TEST_FAIL("poll( {%d, %d, %d} x %d, %d, %d) called on IUT "
                  "returns %d, but it is expected to return 0",
                  ufds[0].fd, ufds[0].events, ufds[0].revents, nfds,
                  nfds, timeout, rc);
    }

    for (i = 0; i < nfds; i++)
    {
        if (ufds[i].revents != 0)
        {
            TEST_FAIL("poll() called on IUT with negative 'fd' not "
                      "update 'revents' field of %d 'ufds' entry to 0, "
                      "but sets it to 0x%x",
                      i, ufds[i].revents);
        }
    }

    TEST_SUCCESS;

cleanup:

    free(ufds);

    TEST_END;
}
