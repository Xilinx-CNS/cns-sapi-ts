/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-create_close_many Repeat epoll_create() and then close() many times
 *
 * @objective Check that repeating epoll_create() and then close() many
 *            times doesn't lead to crash
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param domain        Protocol domain to be used for socket creation
 *                      - PF_INET
 *                      - PF_INET6
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/create_close_many"

#include "sockapi-test.h"

#define MAX_BUFF_SIZE 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;

    int                     iut_s = -1;
    int                     epfd = -1;
    int                     iter_num;
    int                     i;
    rpc_socket_domain       domain;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(iter_num);
    TEST_GET_DOMAIN(domain);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    for (i = 0; i < iter_num; i++)
    {
        epfd = rpc_epoll_create(pco_iut, 1);
        RPC_CLOSE(pco_iut, epfd);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
