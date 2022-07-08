/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_poll_zero_evt Using poll() function with structures where events field is set to zero
 *
 * @objective Check that @b poll() function correctly processes situation
 *            when @c pollfd entries contain @a events field set to zero.
 *
 * @type conformance, robustness
 *
 * @reference @ref STEVENS, section 6.10
 *
 * @param domain      Domain used in the test
 * @param sock_type   Socket type used in the test
 * @param pco_iut     PCO on IUT
 *
 * @par Scenario:
 * -# Create @p iut_s socket from @p domain domain of type @p sock_type 
 *    on @p pco_iut;
 * -# Prepare @c pollfd structure as follows:
 *        - @a fd      - @p iut_s;
 *        - @a events  - @c 0;
 *        - @a revents - @c 0xffff.
 *        .
 * -# Call @b poll() with prepared structure specifying some @p timeout;
 * -# Check that the function returns @c 0 and its duration was @p timeout
 *    milliseconds.
 * -# Check that @a revents field of the structure is updated to @c 0.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_poll_zero_evt"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rpc_socket_type    sock_type;
    int                timeout;
    int                iut_s = -1;
    struct rpc_pollfd  fds;
    rpc_socket_domain  domain;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_DOMAIN(domain);

    timeout = rand_range(0, 1000);

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    fds.fd = iut_s;
    fds.events = 0;
    fds.revents = 0xFFFF;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_poll(pco_iut, &fds, 1, timeout);
    if (rc != 0)
    {
        TEST_VERDICT("poll() called on IUT just created socket with zero "
                     "requested events field returns %d instead of 0 "
                     "('revents' field is set to %s)",
                     rc, poll_event_rpc2str(fds.revents));
    }
    if (fds.revents != 0)
    {
        TEST_VERDICT("poll() called on IUT with zero requested events "
                     "field does not update 'revents' field to zero");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
