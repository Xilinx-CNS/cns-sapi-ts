/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_poll_nentries nfds parameter of poll() function
 *
 * @objective Check that @b poll() function processes no more than @a nfds
 *            entries of @a fdarray.
 *
 * @type conformance, robustness
 *
 * @reference @ref STEVENS, section 6.10
 *
 * @param domain    Domain used for the test (PF_INET, or smth.)
 * @param pco_iut   PCO on IUT
 * @param nfds      The value of @a nfds parameter in @b poll() function,
 *
 * @par Scenario:
 * -# Create @p iut_s socket from @p domain domain of type @p sock_type 
 *    on @p pco_iut;
 * -# Prepare @p ufds - an array of @c pollfd structures with @p nfds + 1
 *    elements and fill in the first @p nfds entries as follows:
 *        - @a fd      - @b -1;
 *        - @a events  - @c POLLOUT;
 *        - @a revents - @c 0xffff;
 *        .
 *    And the last one as:
 *        - @a fd      - @p iut_s;
 *        - @a events  - @c POLLOUT;
 *        - @a revents - @c 0xffff.
 *        .
 * -# Call @b poll(@p ufds, @p nfds, @p timeout);
 * -# Check that the function returns @c 0 and its duration is @p timeout
 *    milliseconds.
 * -# Check that @a revents field of all first @p nfds entries in @p ufds 
 *    array is updated to @c 0;
 * -# Check that the last entry in the array is not changed.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_poll_nentries"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    int                iut_s = -1;
    int                timeout;
    int                nfds;
    int                i;
    struct rpc_pollfd *ufds = NULL;
    rpc_socket_domain  domain;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(nfds);
    TEST_GET_DOMAIN(domain);

    if (nfds < 1)
    {
        TEST_FAIL("'nfds' parameter should be at least 1");
    }
    
    ufds = (struct rpc_pollfd *)malloc(sizeof(*ufds) * (nfds + 1));
    CHECK_NOT_NULL(ufds);
    
    timeout = rand_range(0, 1000);

    /* Scenario */
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    for (i = 0; i < nfds; i++)
    {
        ufds[i].fd = -1;
        ufds[i].events = RPC_POLLOUT;
        ufds[i].revents = 0xFFFF;
    }
    ufds[i].fd = iut_s;
    ufds[i].events = RPC_POLLOUT;
    ufds[i].revents = 0xFFFF;
    
    rpc_poll(pco_iut, ufds, nfds, timeout);

    for (i = 0; i < nfds; i++)
    {
        if (ufds[i].revents != 0)
        {
            TEST_FAIL("poll() does not update 'revents' field of %d entry "
                      "of 'ufds' to zero, but it is %s",
                      poll_event_rpc2str(ufds[i].revents));
        }
    }
    
    if (ufds[nfds].fd != iut_s)
    {
        TEST_FAIL("poll() updates 'fd' field of the last entry to %d "
                  "(the entry is out of the length passed to the function)",
                  ufds[nfds].fd);
    }
    if (ufds[nfds].events != RPC_POLLOUT)
    {
        TEST_FAIL("poll() updates 'events' field of the last entry to %s "
                  "(the entry is out of the length passed to the function)",
                  poll_event_rpc2str(ufds[i].events));
    }
    if (ufds[nfds].revents != (short)0xFFFF)
    {
        TEST_FAIL("poll() updates 'revents' field of the last entry to %s "
                  "(the entry is out of the length passed to the function)",
                  poll_event_rpc2str(ufds[i].revents));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(ufds);

    TEST_END;
}
