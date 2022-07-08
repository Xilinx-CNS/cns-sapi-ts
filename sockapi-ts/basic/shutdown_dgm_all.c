/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-shutdown_dgm_all shutdown(RDWR) on UDP socket
 *
 * @objective Check simultaneous read/write shutdown of datagram socket
 *            in connected state.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/shutdown_dgm_all"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    int                     iut_s  = -1;
    int                     tst_s  = -1;

    const struct sockaddr  *tst_addr;
    const struct sockaddr  *iut_addr;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);

    TEST_STEP("Create socket @b tst_s on @p pco_tst of @c SOCK_DGRAM type.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Create socket @b iut_s on @p pco_iut of @c SOCK_DGRAM type.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("@b connect() @b iut_s to the @p tst_addr "
              "and @b tst_s to @p iut_addr.");
    rpc_connect(pco_iut, iut_s, tst_addr);
    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Check that obtained state of @b iut_s is @c STATE_CONNECTED. ");
    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED);

    TEST_STEP("@b shutdown() @b iut_s for read/write.");
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);

    TEST_STEP("Check that obtained state of @b iut_s is @c STATE_SHUT_RDWR. ");
    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_SHUT_RDWR);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
