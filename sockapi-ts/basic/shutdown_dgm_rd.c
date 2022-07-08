/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-shutdown_dgm_rd Consistently shutdown(RD) and shutdown(WR) on UDP socket
 *
 * @objective Check shutdown of datagram socket in connected state
 *            in sequence @c SHUT_RD, then @c SHUT_WR.
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

#define TE_TEST_NAME  "basic/shutdown_dgm_rd"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    tx_buf = sockts_make_buf_dgram(&buf_len);
    rx_buf = TE_ALLOC(buf_len);

    TEST_STEP("Create socket @b iut_s on @p pco_iut of @c SOCK_DGRAM type.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Create socket @b tst_s on @p pco_tst of @c SOCK_DGRAM type.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("@b bind() @b iut_s to @p iut_addr.");
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("@b bind() @b tst_s to @p tst_addr.");
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("@b connect() @b iut_s to @p tst_addr.");
    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_STEP("@b connect() @b tst_s to @p iut_addr.");
    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Check that obtained state of @p iut_s is @c STATE_CONNECTED.");
    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED);

    TEST_STEP("@b send() data from @b tst_s.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);

    TEST_STEP("Call @b recv() on @b iut_s.");
    rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);

    TEST_STEP("Check that @b iut_s received message with the same length "
              "as was sent from @b tst_s.");
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, buf_len, rc);

    TEST_STEP("Call @b shutdown(@c SHUT_RD) on @b iut_s.");
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);

    TEST_STEP("Check that obtained state of @b iut_s is @c STATE_SHUT_RD.");
    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_SHUT_RD);

    TEST_STEP("Call @b shutdown(@c SHUT_WR) on @b iut_s.");
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);

    TEST_STEP("Check that obtained state of @b iut_s is @c STATE_SHUT_RDWR.");
    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_SHUT_RDWR);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
