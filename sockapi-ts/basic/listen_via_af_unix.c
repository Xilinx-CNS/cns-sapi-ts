/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/**
 * @page basic-listen_via_af_unix Pass a listening socket between proccesses via AF_UNIX socket and accept connections using it.
 *
 * @objective Check that a listening socket received from another process via
 *            AF_UNIX can accept connections
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param func Function used to accept:
 *      - @c accept
 *      - @c accept4
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "basic/listen_via_af_unix"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const char *func = NULL;

    int iut_s = -1;
    int iut_s2 = -1;
    int iut_l2 = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);

    TEST_STEP("Create a new @p pco_iut2 process on IUT");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut2", &pco_iut2));

    TEST_STEP("Create and bind @c SOCKT_STREAM socket on @p pco_iut "
              "and on @p pco_tst");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Call @b listen() on @p pco_iut");
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Pass the listening socket from @p pco_iut to @p pco_iut2");
    iut_l2 = sockts_share_socket_2proc(pco_iut, pco_iut2, iut_s);

    TEST_STEP("Connect Tester socket to IUT adress");
    rc = rpc_connect(pco_tst, tst_s, iut_addr);
    if (rc < 0)
    {
        TEST_VERDICT("connect() failed with errno %r",
                     RPC_ERRNO(pco_tst));
    }

    TEST_STEP("Accept a connection on @p pco_iut2 using @p func");
    RPC_AWAIT_ERROR(pco_iut2);
    if (strcmp(func, "accept") == 0)
        iut_s2 = rpc_accept(pco_iut2, iut_l2, NULL, NULL);
    else if (strcmp(func, "accept4") == 0)
        iut_s2 = rpc_accept4(pco_iut2, iut_l2, NULL, NULL, RPC_SOCK_NONBLOCK);
    else
        TEST_FAIL("Invalid @p func");

    if (iut_s2 == -1)
    {
        TEST_VERDICT("accept() failed with errno %r",
                      RPC_ERRNO(pco_iut2));
    }

    TEST_STEP("Check that data may be sent/received via connection "
              "between @p pco_iut2 and @p pco_tst");
    sockts_test_connection(pco_iut2, iut_s2, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_l2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut2));

    TEST_END;
}
