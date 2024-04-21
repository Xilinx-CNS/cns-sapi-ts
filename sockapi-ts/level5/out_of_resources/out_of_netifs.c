/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific test reproducing run out of hardware resources
 *
 * $Id$
 */

/** @page level5-out_of_resources-out_of_netifs Netifs resource exhaustion caused by calling socket() and exec() operations many times
 *
 * @objective Check that Level5 library does not return error
 *            when there are no more tcp_helper_resources available
 *            when doing exec and creating socket.
 *
 * @type conformance, robustness
 *
 * @param pco_iut       PCO on IUT
 * @param sock_type     Type of socket used in the test
 *                      (@c SOCK_DGRAM or @c SOCK_STREAM)
 * @param netifs_max    Maximum amount of netifs that may be allocated
 *
 * @par Scenario:
 * -# Allow process of @p pco_iut RPC server to create
 *    (@c 2 * @p netifs_max) file descriptors.\n
 *    Use @b setrlimit(@c RLIMIT_NOFILE) call for this purpose.
 * -# Repeat @p netifs_max + @c 1 times.
 *   - Do @b exec() call on @p pco_iut;
 *   - Create @p iut_s[N] socket of @p sock_type type on @p pco_iut;
 *   - Check that @b socket() call does not return error;
 * -# Close all created sockets.
 * -# Check created and accelerated sockets numbers. At the moment it is
 *    possible create 240 Onload stacks at EF10 and 57 at Siena.
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/out_of_resources/out_of_netifs"

#include "out_of_resources.h"

/* Minimum stacks number */
#define MIN_STACKS_NUM 50

int
main(int argc, char *argv[])
{
    rcf_rpc_server   *pco_iut = NULL;
    rpc_socket_type   sock_type;
    int               netifs_max;
    te_bool           ef_no_fail;
    int               num;
    int               acc;
    int               loglevel = -1;
    int               stacks_available = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(netifs_max);
    TEST_GET_BOOL_PARAM(ef_no_fail);

    prepare_parent_pco(pco_iut, netifs_max * 2 + 10);

    TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);

    pco_iut->timeout = 600000; /* 10 min */
    rpc_out_of_netifs(pco_iut, netifs_max, sock_type, &num, &acc);
    RING("Sockets number %d/%d", acc, num);

    stacks_available = sockts_get_limited_stacks(pco_iut);
    if (stacks_available == 0)
        stacks_available = MIN_STACKS_NUM;
    if (acc < stacks_available)
        TEST_VERDICT("Too small number of stacks");

    if (ef_no_fail && acc == num)
        TEST_VERDICT("Total created sockets number should be more then "
                     "accelerated");

    if (!ef_no_fail && acc != num)
        TEST_VERDICT("Total created sockets number "
                     "should be equal to the accelerated one");

    TEST_SUCCESS;

cleanup:
    if (loglevel != -1)
        TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);

    rpc_unsetenv(pco_iut, "LD_PRELOAD");

    TEST_END;
}
