/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-ioctl The IOCTL operation on BSD compatible sockets
 *
 * @objective Test on reliability of @b ioctl() operation
 *            on BSD compatible sockets.
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
 * -# Create @p pco_iut socket of the @c SOCK_DGRAM type on the @p IUT side;
 * -# Create @p pco_tst socket of the @c SOCK_DGRAM type on the @p TESTER side;
 * -# @b bind() @p pco_iut socket to the local address/port;
 * -# @b bind() @p pco_tst socket to the local address/port;
 * -# Request @b ioctl() (@c FIONBIO) to set a nonblocking mode
 *    on @p pco_iut socket;
 * -# Call @b recvfrom() on the @p pco_iut socket;
 * -# Check that @b recvfrom() returns immediately and receive buffer
 *    is empty;
 * -# Request @b ioctl() (@c FIONBIO) to set a blocking mode
 *    on @p pco_iut socket;
 * -# Call @b recvfrom() on the @p pco_iut socket;
 * -# @b sendto() data to the @p pco_tst socket;
 * -# Wait for @b recvfrom() completion on the @p pco_iut socket;
 * -# Compare transmitted and received data.
 * -# Close created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/ioctl"

#include "sockapi-test.h"


#define TST_SENDRECV_FLAGS    0
#define TST_OPTION_ON         1
#define TST_OPTION_OFF        !TST_OPTION_ON


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
    int             intval;

    struct sockaddr_storage from;
    socklen_t               fromlen;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    tx_buf = sockts_make_buf_dgram(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    GEN_DGRAM_CONN_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, iut_addr,
                        tst_addr, &iut_s, &tst_s, FALSE, FALSE, TRUE);

    intval = TST_OPTION_ON;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &intval);

    fromlen = sizeof(from);
    memset(&from, 0, sizeof(from));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvfrom(pco_iut, iut_s, rx_buf, rx_buf_len, TST_SENDRECV_FLAGS,
                      (struct sockaddr *)&from, &fromlen);

    if (rc != -1)
        TEST_FAIL("RPC recvfrom() on IUT socket unexpected return code");

    err = RPC_ERRNO(pco_iut);
    if (err != RPC_EAGAIN)
        TEST_FAIL("RPC recvfrom() on IUT socket unexpected errno");

    intval = TST_OPTION_OFF;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &intval);

    pco_iut->op = RCF_RPC_CALL;
    rpc_recvfrom(pco_iut, iut_s, rx_buf, rx_buf_len, TST_SENDRECV_FLAGS,
                 (struct sockaddr *)&from, &fromlen);

    RPC_SENDTO(rc, pco_tst, tst_s, tx_buf, tx_buf_len, TST_SENDRECV_FLAGS,
               iut_addr);

    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recvfrom(pco_iut, iut_s, rx_buf, rx_buf_len, TST_SENDRECV_FLAGS,
                 (struct sockaddr *)&from, &fromlen);

    if (rc != (int)tx_buf_len)
    {
        ERROR("Only part of sent data is received by IUT");
        VERB("Data is received on IUT: expected %u, "
             "received %d", tx_buf_len, rc);
        TEST_STOP;
    }
    if (memcmp(tx_buf, rx_buf, tx_buf_len) != 0)
        TEST_FAIL("Recevied data are not equal to sent");

    if (te_sockaddrcmp((struct sockaddr *)&from, fromlen,
                       tst_addr, te_sockaddr_get_size(tst_addr)) != 0)
    {
        TEST_FAIL("Invalid peer address returned by recvfrom() on IUT");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
