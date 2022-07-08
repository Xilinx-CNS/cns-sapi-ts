/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * FD caching
 * 
 * $Id$
 */

/** @page fd_caching-fd_cache_linger  FD caching with SO_LINGER option
 *
 * @objective  Check that FD caching is disbled when SO_LINGER is set.
 *
 * @type conformance
 *
 * @param pco_iut       RPC server on iut node
 * @param pco_tst       RPC server on tester node
 * @param listener      Enable linger for the listener socket
 * @param overfill      Overfill buffers
 * @param linger        Enable linger option if @c TRUE
 * @param active        IUT is active in TCP connection.
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "level5/fd_caching/fd_cache_linger"

#include "sockapi-test.h"
#include "fd_cache.h"

/** Linger timeout in seconds. */
#define LINGER_TIMEOUT 1

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;

    te_bool listener;
    te_bool overfill;
    te_bool linger;
    te_bool cached;
    te_bool active;

    tarpc_linger linger_val = {.l_onoff = 1, .l_linger = LINGER_TIMEOUT};

    int aux_ls = -1;
    int tst_s = -1;
    int iut_s = -1;
    int sockcache_contention;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, tst_addr);
    TEST_GET_BOOL_PARAM(overfill);
    TEST_GET_BOOL_PARAM(linger);
    TEST_GET_BOOL_PARAM(listener);
    TEST_GET_BOOL_PARAM(active);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Open TCP sockets on IUT and tester.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    aux_ls = (active) ? tst_s : iut_s;

    sockcache_contention = tapi_onload_get_stats_val(
                               pco_iut2,  "sockcache_contention");

    TEST_STEP("Enable SO_LINGER for the listener socket if @p listener "
              "is @c TRUE and @p active is @c FALSE.");
    if (linger && listener && !active)
        rpc_setsockopt(pco_iut, aux_ls, RPC_SO_LINGER, &linger_val);

    TEST_STEP("Establish TCP connection in according with @p active");
    if (active)
    {
        rpc_bind(pco_tst, aux_ls, tst_addr);
        rpc_listen(pco_tst, aux_ls, -1);
        rpc_connect(pco_iut, iut_s, tst_addr);
        tst_s = rpc_accept(pco_tst, aux_ls, NULL, NULL);
    }
    else
    {
        rpc_bind(pco_iut, aux_ls, iut_addr);
        rpc_listen(pco_iut, aux_ls, -1);
        rpc_connect(pco_tst, tst_s, iut_addr);
        iut_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    }

    TEST_STEP("Set SO_LINGER for the connected or accepted socket depending on "
              "@p active and @p lsitener.");
    if (linger && (!listener || active))
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &linger_val);

    TEST_STEP("Overfill send buffers for IUT and recv buffer for tester "
              "if @p overfill is @c TRUE.");
    if (overfill)
        rpc_overfill_buffers(pco_iut, iut_s, NULL);

    TEST_STEP("Close the cached socket.");
    rpc_close(pco_iut, iut_s);

    TEST_STEP("Socket must not be cached if SO_LINGER was set");
    cached = tapi_onload_check_socket_caching(pco_iut, iut_s, pco_iut2,
                                              sockcache_contention);
    iut_s = -1;
    if (linger && cached)
        TEST_VERDICT("The socket was cached");
    else if (!linger && !cached)
        TEST_VERDICT("The socket was not cached");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(active ? pco_tst : pco_iut, aux_ls);

    TEST_END;
}

