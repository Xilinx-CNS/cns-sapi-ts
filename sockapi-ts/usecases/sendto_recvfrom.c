/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-sendto_recvfrom The sendto()/recvfrom() operations on the SOCK_DGRAM socket

 *
 * @objective Test on reliability of @b sendto()/recvfrom() operations on BSD
 *            compatible sockets.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_p2p_ip6ip4mapped
 *                  - @ref arg_types_env_p2p_ip6
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 *
 * @par Scenario:
 * -# Create @p pco_iut socket of the @c SOCK_DGRAM type on the
 *    @p IUT side;
 * -# Create @p pco_tst socket of the @c SOCK_DGRAM type on the
 *    @p TESTER side;
 * -# @b bind() @p pco_iut socket to the local address/port;
 * -# @b bind() @p pco_tst socket to the local address/port;
 * -# Call blocking @b recvfrom() on the @p pco_iut socket;
 * -# @b sendto() data to the @p pco_tst socket;
 * -# Wait for @b recvfrom() completion on the @p pco_iut socket;
 * -# Call @b sendto() of the obtained data on the @p pco_iut socket;
 * -# Call @b recvfrom() on the @p pco_tst socket to obtain data from
 *    @p pco_iut socket;
 * -# Compare transmitted and received data.
 * -# Close created sockets;
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/sendto_recvfrom"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    int             err;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    void           *tx_buf = NULL;
    size_t          tx_buf_len;
    void           *rx_buf = NULL;
    size_t          rx_buf_len;

    struct sockaddr_storage from;
    socklen_t               fromlen;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    struct sockaddr_storage conn_iut_addr;
    struct sockaddr_storage conn_tst_addr;

    ssize_t len;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    GEN_DGRAM_CONN_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, iut_addr,
                        tst_addr, &iut_s, &tst_s, FALSE, FALSE, TRUE);

    sockts_ip6_get_ll_remote_addr(iut_addr, tst_addr,
                                  &conn_iut_addr);
    sockts_ip6_get_ll_remote_addr(tst_addr, iut_addr, &conn_tst_addr);

    tx_buf = sockts_make_buf_dgram(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    fromlen = sizeof(from);
    memset(&from, 0, sizeof(from));
    pco_iut->op = RCF_RPC_CALL;

    rpc_recvfrom(pco_iut, iut_s, rx_buf, rx_buf_len, 0,
                 (struct sockaddr *)&from, &fromlen);

    len = rpc_sendto(pco_tst, tst_s, tx_buf, tx_buf_len, 0,
                     SA(&conn_iut_addr));
    if ((size_t)len != tx_buf_len)
    {
        err = RPC_ERRNO(pco_tst);
        TEST_FAIL("RPC sendto() on TESTER failed retval=%d "
                  "RPC_errno=%X", len, TE_RC_GET_ERROR(err));
    }

    pco_iut->op = RCF_RPC_WAIT;

    len = rpc_recvfrom(pco_iut, iut_s, rx_buf, rx_buf_len, 0,
                       (struct sockaddr *)&from, &fromlen);

    if ((size_t)len != tx_buf_len)
        TEST_FAIL("Part of sent data is received by IUT: expected %u, "
                  "received %d", tx_buf_len, len);

    if (memcmp(tx_buf, rx_buf, tx_buf_len) != 0)
        TEST_FAIL("Recevied data are not equal to sent");

    if (te_sockaddrcmp((struct sockaddr *)&from, fromlen,
                       SA(&conn_tst_addr),
                       te_sockaddr_get_size(SA(&conn_tst_addr))) != 0)
    {
        TEST_FAIL("Invalid peer address returned by recvfrom() on IUT");
    }

    len = rpc_sendto(pco_iut, iut_s, tx_buf, tx_buf_len, 0,
                     SA(&conn_tst_addr));
    if ((size_t)len != tx_buf_len)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC sendto() on IUT failed retval=%d "
                  "RPC_errno=%X", len, TE_RC_GET_ERROR(err));
    }

    fromlen = sizeof(from);
    len = rpc_recvfrom(pco_tst, tst_s, rx_buf, rx_buf_len, 0,
                      (struct sockaddr *)&from, &fromlen);
    if ((size_t)len != tx_buf_len)
    {
        ERROR("Only part of sent data is received by TESTER");
        VERB("TESTER received:%d, expected:%d", len, tx_buf_len);
        TEST_STOP;
    }

    if (memcmp(tx_buf, rx_buf, tx_buf_len) != 0)
        TEST_FAIL("Recevied by TESTER data are not equal to sent by IUT");

    if (te_sockaddrcmp((struct sockaddr *)&from, fromlen,
                       SA(&conn_iut_addr),
                       te_sockaddr_get_size(SA(&conn_iut_addr))) != 0)
    {
        TEST_FAIL("Invalid peer address returned by recvfrom() on TESTER");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
