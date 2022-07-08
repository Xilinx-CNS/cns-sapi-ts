/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * FD caching
 * 
 * $Id$
 */

/** @page fd_caching-fd_cache_opt Socket option inheritance after reincarnation
 *
 * @objective  Check that reused accepted socket inheritances correct socket
 *             option value.
 *
 * @type conformance
 *
 * @param pco_iut       RPC server on iut node
 * @param pco_tst       RPC server on tester node
 * @param opt_name      Tested option
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cache_opt"

#include "sockapi-test.h"
#include "fd_cache.h"

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rpc_sockopt opt_name;

    int iut_acc = -1;
    int tst_s = -1;
    int iut_s = -1;
    int val;
    int val_scd;
    int sockcache_contention;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCKOPT(opt_name);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Open TCP socket.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    sockcache_contention = tapi_onload_get_stats_val(
                               pco_iut2,  "sockcache_contention");

    TEST_STEP("Bind it and call listen().");
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, -1);

    TEST_STEP("Set socket option @p opt_name");
    switch (opt_name)
    {
        case RPC_SO_KEEPALIVE:
        case RPC_TCP_KEEPCNT:
        case RPC_TCP_KEEPIDLE:
        case RPC_TCP_KEEPINTVL:
            val = 1;
            break;

        default:
            TEST_FAIL("Test does not support option %s",
                      sockopt_rpc2str(opt_name));
    }
    rpc_setsockopt_int(pco_iut, iut_s, opt_name, val);

    TEST_STEP("Open TCP socket on tester and connect it to IUT.");
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Accept the connection request on the IUT side.");
    iut_acc = rpc_accept(pco_iut, iut_s, NULL, NULL);

    TEST_STEP("Set another value to the socket option @p opt_name.");
    switch (opt_name)
    {
        case RPC_SO_KEEPALIVE:
        case RPC_TCP_KEEPCNT:
        case RPC_TCP_KEEPIDLE:
        case RPC_TCP_KEEPINTVL:
            val_scd = 2;
            break;

        default:
            TEST_FAIL("Test does not support option %s",
                      sockopt_rpc2str(opt_name));
    }
    rpc_setsockopt_int(pco_iut, iut_acc, opt_name, val_scd);

    TEST_STEP("Close the tester socket and the accepted IUT socket.");
    sockts_pair_close_check(pco_iut, pco_tst, iut_acc, tst_s);

    if (!tapi_onload_check_socket_caching(pco_iut, iut_acc, pco_iut2,
                                          sockcache_contention))
    {
        TEST_VERDICT("Accepted socket was not cached");
    }

    TEST_STEP("Open new TCP socket on tester and connect it to IUT.");
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Accept the second connection request on the IUT side.");
    iut_acc = rpc_accept(pco_iut, iut_s, NULL, NULL);

    TEST_STEP("Check the accepted socket inherited the socket option value from the "
              "listener socket.");
    rpc_getsockopt(pco_iut, iut_acc, opt_name, &val_scd);
    if (val_scd != val)
        TEST_VERDICT("Socket option %s value is not equal to the listener "
                     "socket value");

    TEST_STEP("Close the accepted socket.");
    sockts_pair_close_check(pco_iut, pco_tst, iut_acc, tst_s);
    tst_s = -1;

    if (!tapi_onload_check_socket_caching(pco_iut, iut_acc, pco_iut2,
                                          sockcache_contention))
    {
        TEST_VERDICT("Reused socket was not cached");
    }
    iut_acc = -1;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
