/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_iomux_signals Using iomux functions with signal mask that contains signals that cannot be caught
 *
 * @objective Check that iomux functions allow to pass signal mask
 *            containing signals that cannot be caught.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut   PCO on IUT
 * @param iomux     iomux function to use:
 *                  - @b pselect
 *                  - @b ppoll()
 *                  - @b epoll_pwait()
 *                  - @b epoll_pwait2()
 *
 * @note The test is run on @p pco_iut
 *
 * @par Scenario:
 * -# Create @p sigmask signal mask;
 * -# Clear @p sigmask with @b sigemptyset();
 * -# Add @c SIGKILL signal to @p sigmask mask with @b sigaddset();
 * -# Call @p iomux with all descriptors set to @c NULL, and some
 *    @p timeout. As the value of @a sigmask parameter use @p sigmask;
 * -# Check that the function returns @c 0 and its duration is about @p
 *    timeout time interval;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME             "bnbvalue/iomux_notmasked_signals"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    iomux_call_type       iomux;
    rcf_rpc_server       *pco_iut = NULL;
    rpc_sigset_p          sigmask = RPC_NULL;
    tarpc_timeval         timeout;

    TEST_START;

    /* Preambule */
    TEST_GET_PCO(pco_iut);
    TEST_GET_IOMUX_FUNC(iomux);

    timeout.tv_sec = rand_range(1, 10);
    timeout.tv_usec = rand_range(1, 1000);

    /* Scenario */
    sigmask = rpc_sigset_new(pco_iut);

    rpc_sigemptyset(pco_iut, sigmask);

    rpc_sigaddset(pco_iut, sigmask, RPC_SIGKILL);

    rc = iomux_call_signal(iomux, pco_iut, NULL, 0, &timeout, sigmask);

    if (rc != 0)
    {
        TEST_FAIL("%s() called on IUT returns not 0 (%d)",
                  iomux_call_en2str(iomux), rc);
    }

    TEST_SUCCESS;

cleanup:
    if (sigmask != RPC_NULL)
        rpc_sigset_delete(pco_iut, sigmask);

    TEST_END;
}
