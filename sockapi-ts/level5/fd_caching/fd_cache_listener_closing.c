/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * FD caching
 * 
 * $Id$
 */

/** @page fd_caching-fd_cache_listener_closing Close listener socket with a few accepted sockets in different states
 *
 * @objective  Accept a few sockets close or shutdown some of them and close
 *             or shutdown the listener socket, check that all accepted
 *             sockets become uncached.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param shutdown_how  How to shutdown or close listener socket
 * @param cache_socket  Create cached socket to be reused.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/fd_caching/fd_cache_listener_closing"

#include "sockapi-test.h"
#include "onload.h"
#include "fd_cache.h"

#define SOCKETS_NUM 10

#define PACKET_SIZE 500

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rpc_shut_how shutdown_how;
    int iut_l = -1;
    int *iut_s = NULL;
    int *tst_s = NULL;

    char    buf[PACKET_SIZE];
    te_bool cache_socket;
    te_bool reuse;
    int     init_avail_cache = 0;
    int     i;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SHUT_HOW(shutdown_how);
    TEST_GET_BOOL_PARAM(cache_socket);

    domain = rpc_socket_domain_by_addr(iut_addr);

    iut_s = te_calloc_fill(SOCKETS_NUM, sizeof(*iut_s), -1);
    tst_s = te_calloc_fill(SOCKETS_NUM, sizeof(*tst_s), -1);

    TEST_STEP("Create listener socket.");
    iut_l = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_l, iut_addr);
    rpc_listen(pco_iut, iut_l, -1);

    if (cache_socket)
        init_avail_cache = tapi_onload_get_free_cache(pco_iut2, FALSE, NULL);

    TEST_STEP("Accept, close connection to make cached fd.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, iut_l,
                                FALSE, cache_socket);

    TEST_STEP("Accept a few connections.");
    for (i = 0; i < SOCKETS_NUM; i++)
    {
        tst_s[i] = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM,
                              RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s[i], iut_addr);
        iut_s[i] = rpc_accept(pco_iut, iut_l, NULL, NULL);
    }

    TEST_STEP("Shutdown or close few sockets.");
    rpc_shutdown(pco_iut, iut_s[1], RPC_SHUT_RD);
    rpc_shutdown(pco_iut, iut_s[2], RPC_SHUT_WR);
    rpc_shutdown(pco_iut, iut_s[3], RPC_SHUT_RDWR);
    RPC_CLOSE(pco_iut, iut_s[4]);
    RPC_CLOSE(pco_tst, tst_s[5]);

    TEST_STEP("Shutdown or close in dependence on @p shutdown_how the listener "
              "socket.");
    if (shutdown_how == RPC_SHUT_NONE)
        RPC_CLOSE(pco_iut, iut_l);
    else
        rpc_shutdown(pco_iut, iut_l, shutdown_how);

    TEST_STEP("Check that data can be transmitted where it is possible.");
    if (rpc_send(pco_iut, iut_s[1], buf, PACKET_SIZE, 0) != PACKET_SIZE ||
        rpc_send(pco_tst, tst_s[2], buf, PACKET_SIZE, 0) != PACKET_SIZE ||
        rpc_read(pco_iut, iut_s[2], buf, PACKET_SIZE) != PACKET_SIZE)
        TEST_VERDICT("Unexpected amount of data was passed");
    RPC_CLOSE(pco_iut, iut_s[3]);

    for (i = 6; i < SOCKETS_NUM; i++)
        sockts_test_connection(pco_iut, iut_s[i], pco_tst, tst_s[i]);

    TEST_STEP("Check that cache is not empty if @p shutdown_how is "
              "@c SHUT_WR, otherwise it must be empty.");
    rc = tapi_onload_get_free_cache(pco_iut2, FALSE, &reuse);

    if (shutdown_how == RPC_SHUT_WR)
    {
        if (rc != init_avail_cache - 2 && cache_socket)
            TEST_VERDICT("It was expected to get free cache size %d",
                         init_avail_cache - 2);
    }
    else if (rc > 0 || reuse)
        TEST_VERDICT("All sockets must be uncached");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);

    clean_sockets(pco_iut, iut_s, SOCKETS_NUM);
    clean_sockets(pco_tst, tst_s, SOCKETS_NUM);

    TEST_END;
}
