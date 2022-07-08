/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * FD caching
 * 
 * $Id$
 */

/** @page fd_caching-fd_cache_wild FD caching with using wildcard addresses and two interfaces
 *
 * @objective  Check FD caching work when two interfaces and wildcard
 *             address are used.
 *
 * @type conformance
 *
 * @param pco_iut       RPC server on iut node
 * @param pco_tst       RPC server on tester node
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cache_wild"

#include "sockapi-test.h"
#include "fd_cache.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr1;
    const struct sockaddr *iut_addr2;
    struct sockaddr        wildcard_addr;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    int iut_acc1 = -1;
    int iut_acc2 = -1;
    int tst_s1 = -1;
    int tst_s2 = -1;
    int iut_s = -1;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);

    domain = rpc_socket_domain_by_addr(iut_addr1);

    TEST_STEP("Open TCP socket.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    memcpy(&wildcard_addr, iut_addr1, sizeof(wildcard_addr));
    te_sockaddr_set_wildcard(&wildcard_addr);
    te_sockaddr_set_port(SA(iut_addr2), te_sockaddr_get_port(iut_addr1));

    TEST_STEP("Bind the socket to the wildcard address, turn on listening.");
    rpc_bind(pco_iut, iut_s, &wildcard_addr);
    rpc_listen(pco_iut, iut_s, -1);

    TEST_STEP("Open two sockets on tester, bind them to different interfaces.");
    tst_s1 = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s2 = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s1, iut_addr1);
    rpc_connect(pco_tst, tst_s2, iut_addr2);

    TEST_STEP("Accept both connection on IUT.");
    iut_acc1 = rpc_accept(pco_iut, iut_s, NULL, NULL);
    iut_acc2 = rpc_accept(pco_iut, iut_s, NULL, NULL);

    TEST_STEP("Close both connected sockets on IUT.");
    rpc_close(pco_iut, iut_acc1);
    rpc_close(pco_iut, iut_acc2);

    TEST_STEP("Check that both closed sockets are cached.");
    if (!tapi_onload_socket_is_cached(pco_iut, iut_acc1))
        TEST_VERDICT("The first accepted socket was not cached");
    if (!tapi_onload_socket_is_cached(pco_iut, iut_acc2))
        TEST_VERDICT("The second accepted socket was not cached");
    iut_acc1 = -1;
    iut_acc2 = -1;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);

    TEST_END;
}
