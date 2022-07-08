/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 */

/** @page epoll-create_many_close_all Call epoll_create() until it fails and close all the epoll FDs
 *
 * @objective Check that calling @b epoll_create() in a loop until it
 *            fails and then closing all the epoll descriptors works fine.
 *
 * @type conformance
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_iut_only
 * @param create_socket       If @c TRUE, create a TCP socket before
 *                            the first call of @b epoll_create().
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/create_many_close_all"

#include "sockapi-test.h"

/** Maximum number of epoll FDs to create */
#define MAX_FDS 10000

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    te_bool create_socket;

    int iut_s = -1;
    int epfds[MAX_FDS];
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(create_socket);

    for (i = 0; i < MAX_FDS; i++)
        epfds[i] = -1;

    /* Make sure no Onload stacks exist */
    sockts_kill_zombie_stacks(pco_iut);

    if (create_socket)
    {
        TEST_STEP("If @p create_socket is @c TRUE, create a TCP socket "
                  "on IUT.");
        iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);
    }

    TEST_STEP("Call @b epoll_create() in a loop until it fails with "
              "@c EMFILE.");
    for (i = 0; i < MAX_FDS; i++)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = epfds[i] = rpc_epoll_create(pco_iut, 1);

        if (rc < 0)
        {
            if (RPC_ERRNO(pco_iut) != RPC_EMFILE)
            {
                TEST_VERDICT("epoll_create() failed with unexpected errno "
                             RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
            }

            break;
        }
    }

    if (i == MAX_FDS)
        TEST_VERDICT("All epoll_create() calls were successful");

    TEST_STEP("In cleanup close all the created FDs, check that closing is "
              "successful.");

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < MAX_FDS; i++)
    {
        if (epfds[i] < 0)
            break;

        CLEANUP_RPC_CLOSE(pco_iut, epfds[i]);
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
