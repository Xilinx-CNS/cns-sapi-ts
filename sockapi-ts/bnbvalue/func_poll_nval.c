/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_poll_nval Using poll() function with incorrect descriptor
 *
 * @objective Check that @b poll() function correctly processes situation
 *            when one of @c pollfd entries contains @a fd field set to
 *            a value that does not correspond to any opened sockets or
 *            files.
 *
 * @type conformance, robustness
 *
 * @reference @ref STEVENS, section 6.10
 *
 * @param pco_iut   PCO on IUT
 * @param evt       Event we are interested in
 * @param nfds      Number of entries 
 * @param timeout   Timeout used in the test
 *                  (@c -1 infinite timeout, or any non negative value)
 *
 * @par Scenario:
 * -# Prepare @p ufds - an array of @c pollfd structures with @p nfds 
 *    elements and fill in each structure as follows:
 *        - @a fd      - descriptor that is not associated with any opened
 *                       device;
 *        - @a events  - @p evt;
 *        - @a revents - @c 0xffff.
 *        .
 * -# Call @b poll(@p ufds, @p nfds, @p timeout);
 * -# Check that the function returns @p nfds and does not modify @b errno;
 * -# Check that @a revents field of each @c pollfd structure is updated 
 *    to @c POLLNVAL;
 * -# Check that @a fd field of each @c pollfd structure is not updated;
 * -# Check that @a events field of each @c pollfd structure is not updated.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_poll_nval"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rpc_poll_event     evt;
    int                sock = -1;
    int                non_exist_descr  = -1;
    int                timeout;
    int                nfds;
    int                i;
    struct rpc_pollfd *ufds = NULL;


    TEST_START;

    /* Preambule */
    TEST_GET_PCO(pco_iut);
    TEST_GET_POLL_EVT(evt);
    TEST_GET_INT_PARAM(nfds);
    TEST_GET_INT_PARAM(timeout);

    if (nfds < 1)
    {
        TEST_FAIL("'nfds' parameter should be at least 1");
    }
    
    /*
     * Create non existing descriptor:
     * 1. Create a socket (it does not matter which domain and type 
     *    we use);
     * 2. Close the socket.
     * Obtained descriptor can be used as non existing
     */
    sock = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    non_exist_descr = sock;
    RPC_CLOSE(pco_iut, sock);

    CHECK_NOT_NULL(ufds = calloc(nfds, sizeof(*ufds)));

    /* Scenario */
    for (i = 0; i < nfds; i++)
    {
        ufds[i].fd = non_exist_descr;
        ufds[i].events = evt;
        ufds[i].revents = 0xFFFF;
    }

    rc = rpc_poll(pco_iut, ufds, nfds, timeout);
    if (rc != nfds)
    {
        TEST_FAIL("poll( {%d, %d, %d} x %d, %d, %d) called on IUT "
                  "returns %d instead of %d",
                  ufds[0].fd, ufds[0].events, ufds[0].revents, nfds,
                  nfds, timeout, rc, nfds);
    }

    for (i = 0; i < nfds; i++)
    {
         if (ufds[i].revents != RPC_POLLNVAL)
         {
             TEST_FAIL("poll() called on IUT with nonexisting descriptors "
                       "does not update 'revents' field to POLLNVAL in %d "
                       "entry of 'ufds' array", i);
         }

         if (ufds[i].fd != non_exist_descr)
         {
             TEST_FAIL("poll() called on IUT with incorrect descriptors "
                       "updates 'fd' field in %d entry of 'ufds' array", i);
         }

         if ((rpc_poll_event)ufds[i].events != evt)
         {
             TEST_FAIL("poll() called on IUT with incorrect descriptors "
                       "updates 'events' field in %d entry of 'ufds' array", i);
         }
    }

    TEST_SUCCESS;

cleanup:
    free(ufds);

    TEST_END;
}

