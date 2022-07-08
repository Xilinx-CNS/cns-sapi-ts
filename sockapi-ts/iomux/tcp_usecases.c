/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 *
 * $Id$
 */

/** @page iomux-tcp_usecases The iomux functionality on BSD compatible sockets
 *
 * @objective Test on reliability of the @b iomux() operation
 *            on BSD compatible sockets.
 *
 * @type use case
 *
 * @reference @ref WBS-PD, @ref XNS5, @ref STEVENS
 *
 * @param iomux  iomux function for testing
 *
 * @par Scenario:
 *
 * -# Create @p pco_iut socket of the @c SOCK_STREAM type on the
 *    @p IUT side;
 * -# Create @p pco_tst1 socket of the @c SOCK_STREAM type on the
 *    @p TESTER side;
 * -# Create @p pco_tst2 socket of the @c SOCK_STREAM type on the
 *    @p TESTER side;
 * -# @b bind() @p pco_iut socket to the local address/port;
 * -# Call @b listen() on the @p pco_iut socket;
 * -# Call @b iomux() with @c EVT_WR | @c EVT_RD | @c EVT_EXC on the
 *    @p pco_iut socket;
 * -# @b connect() @p pco_tst1 socket to the @p pco_iut one;
 * -# Check that @b iomux() returns with @a EVT_RD event;
 * -# Call @b accept() on the @p pco_iut to establish
 *    new connection with @p pco_tst1 socket;
 * -# Call @b getsockname()/getpeername() on @p pco_iut @p accepted1 socket;
 * -# Validate information returned by @b getsockname()/getpeername()
 *    operation on @p pco_iut @p accepted1 socket;
 * -# Call @b iomux() with @c EVT_WR | @c EVT_RD | @c EVT_EXC on the
 *    @p pco_iut socket;
 * -# @b connect() @p pco_tst2 socket to the @p pco_iut one;
 * -# Check that @b iomux() returns with @a EVT_RD event;
 * -# Call @b accept() on the @p pco_iut to establish
 *    new connection with @p pco_tst2 socket;
 * -# Call @b getsockname()/getpeername() on @p pco_iut @p accepted2 socket;
 * -# Validate information returned by @b getsockname()/getpeername()
 *    operation on @p pco_iut @p accepted2 socket;
 * -# Call @b iomux() with @c EVT_WR | @c EVT_RD | @c EVT_EXC events for
 *    @p pco_iut, @p accepted1 and @p accepted2 sockets with some positive
 *    timeout on @p pco_iut;
 * -# Check that @b iomux() on the @p pco_iut returns @c 0;
 * -# Call @b iomux() with @c EVT_RD event on the @p pco_iut @p accepted1
 *    socket;
 * -# @b send() data to the @p pco_tst1 socket;
 * -# Check that @b iomux() returning with the @p pco_iut @b accepted1
 *    socket file descriptor;
 * -# Call @b recv() on the @p pco_iut @p accepted1 socket;
 * -# Call @b iumox() with @c EVT_RD event on the @p pco_iut @p accepted2
 *    socket;
 * -# @b send() data to the @p pco_tst2 socket;
 * -# Check that @b iomux() returning with the @p pco_iut @b accepted2
 *    socket file descriptor;
 * -# Call @b recv() on the @p pco_iut @p accepted2 socket;
 * -# Call @b send() of the obtained data on the @p pco_iut @b accepted1
 *    socket;
 * -# Call @b recv() on the @p pco_tst1 socket to obtain data from
 *    @p pco_iut @p accepted1 socket;
 * -# Call @b send() of the obtained data on the @p pco_iut @b accepted2
 *    socket;
 * -# Call @b recv() on the @p pco_tst2 socket to obtain data from
 *    @p pco_iut @p accepted2 socket;
 * -# Close created sockets on the both sides;
 * -# Compare transmitted and received data.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/tcp_usecases"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    int             err;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    int             iut_s = -1;
    int             tst1_s = -1;
    int             tst2_s = -1;
    int             accepted1 = -1;
    int             accepted2 = -1;
    void           *tx_buf1 = NULL;
    size_t          tx_buf1_len;
    void           *rx_buf1 = NULL;
    size_t          rx_buf1_len;
    void           *tx_buf2 = NULL;
    size_t          tx_buf2_len;
    void           *rx_buf2 = NULL;
    size_t          rx_buf2_len;
    tarpc_timeval   timeout;

    const struct sockaddr  *iut_addr;

    iomux_call_type         iomux;
    iomux_evt_fd            event[3];


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_IOMUX_FUNC(iomux);

    tx_buf1 = sockts_make_buf_stream(&tx_buf1_len);
    rx_buf1 = te_make_buf_min(tx_buf1_len, &rx_buf1_len);
    tx_buf2 = sockts_make_buf_stream(&tx_buf2_len);
    rx_buf2 = te_make_buf_min(tx_buf2_len, &rx_buf2_len);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

    event[0].fd = iut_s;
    event[0].events = EVT_RDWR | EVT_EXC;
    pco_iut->op = RCF_RPC_CALL;
    iomux_call(iomux, pco_iut, event, 1, NULL);
    rpc_connect(pco_tst1, tst1_s, iut_addr);

    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, event, 1, NULL);

    if (event[0].revents != EVT_RD)
        TEST_FAIL("Incorrect event on iut_s socket.");

    accepted1 = rpc_accept(pco_iut, iut_s, NULL, NULL);
    rc = sockts_compare_sock_peer_name(pco_iut, accepted1,
                                       pco_tst1, tst1_s);
    if (rc != 0)
        TEST_FAIL("accepted1 local address is not validated");

    rc = sockts_compare_sock_peer_name(pco_tst1, tst1_s,
                                       pco_iut, accepted1);
    if (rc != 0)
        TEST_FAIL("accepted1 remote address is not validated");

    event[0].events = EVT_RD;
    pco_iut->op = RCF_RPC_CALL;
    iomux_call(iomux, pco_iut, event, 1, NULL);
    rpc_connect(pco_tst2, tst2_s, iut_addr);
    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, event, 1, NULL);

    if (event[0].revents != EVT_RD)
        TEST_FAIL("Incorrect event on iut_s socket.");

    accepted2 = rpc_accept(pco_iut, iut_s, NULL, NULL);

    rc = sockts_compare_sock_peer_name(pco_iut, accepted2,
                                       pco_tst2, tst2_s);
    if (rc != 0)
        TEST_FAIL("accepted2 local address is not validated");

    rc = sockts_compare_sock_peer_name(pco_tst2, tst2_s,
                                       pco_iut, accepted2);
    if (rc != 0)
        TEST_FAIL("accepted2 remote address is not validated");

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    event[0].events = EVT_RDWR | EVT_EXC;
    event[1].fd = accepted1;
    event[1].events = EVT_RD | EVT_EXC;
    event[2].fd = accepted2;
    event[2].events = EVT_RD | EVT_EXC;

    pco_iut->op = RCF_RPC_CALL_WAIT;
    rc = iomux_call(iomux, pco_iut, event, 3, &timeout);
    if (rc != 0)
        TEST_FAIL("RPC iomux(timeout) on IUT unexpected behaviour");

    event[1].events = EVT_RD;
    pco_iut->op = RCF_RPC_CALL;
    iomux_call(iomux, pco_iut, &event[1], 1, NULL);

    rc = rpc_send(pco_tst1, tst1_s, tx_buf1, tx_buf1_len, 0);
    if (rc != (int)tx_buf1_len)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC send() on TESTER tst1_s  failed RPC_errno=%X",
                  TE_RC_GET_ERROR(err));
    }

    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, &event[1], 1, NULL);

    if (rc != 1 || event[1].revents != EVT_RD)
        TEST_FAIL("RPC iomux() on IUT (accepted1) unexpected behaviour");

    pco_iut->op = RCF_RPC_CALL_WAIT;
    rc = rpc_recv_gen(pco_iut, accepted1, rx_buf1, tx_buf1_len, 0,
                      rx_buf1_len);

    if (rc != (int)tx_buf1_len)
        TEST_FAIL("Only part of data received");

    if (memcmp(tx_buf1, rx_buf1, tx_buf1_len))
        TEST_FAIL("Invalid data received (tx_buf1/rx_buf1)");

    event[2].events = EVT_RD;
    pco_iut->op = RCF_RPC_CALL;
    iomux_call(iomux, pco_iut, &event[2], 1, NULL);
    SLEEP(1);

    rc = rpc_send(pco_tst2, tst2_s, tx_buf2, tx_buf2_len, 0);
    if (rc != (int)tx_buf2_len)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC send() on pco_tst2 failed RPC_errno=%X",
                  TE_RC_GET_ERROR(err));
    }

    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, &event[2], 1, NULL);

    if (rc != 1 || event[2].revents != EVT_RD)
        TEST_FAIL("RPC iomux() on IUT (accepted2) unexpected behaviour");

    pco_iut->op = RCF_RPC_CALL_WAIT;
    rc = rpc_recv_gen(pco_iut, accepted2, rx_buf2, tx_buf2_len, 0,
                      rx_buf2_len);
    if (rc != (int)tx_buf2_len)
        TEST_FAIL("Only part of data received (tx_buf2)");

    if (memcmp(tx_buf2, rx_buf2, tx_buf2_len))
        TEST_FAIL("Invalid data received (tx_buf2/rx_buf2)");

    rc = rpc_send(pco_iut, accepted1, rx_buf1, tx_buf1_len, 0);
    if (rc != (int)tx_buf1_len)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC send() on IUT accepted1 socket failed "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    rc = rpc_recv_gen(pco_tst1, tst1_s, rx_buf1, tx_buf1_len, 0,
                      rx_buf1_len);
    if (rc != (int)tx_buf1_len)
        TEST_FAIL("Only part of data received (pco_tst1) ");

    if (memcmp(tx_buf1, rx_buf1, tx_buf1_len))
        TEST_FAIL("Invalid data received (pco_tst1)");

    rc = rpc_send(pco_iut, accepted2, rx_buf2, tx_buf2_len, 0);
    if (rc != (int)tx_buf2_len)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC send() on IUT accepted2 socket failed "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    rc = rpc_recv_gen(pco_tst2, tst2_s, rx_buf2, tx_buf2_len, 0,
                      rx_buf2_len);
    if (rc != (int)tx_buf2_len)
        TEST_FAIL("Only part of data received (pco_tst2) ");

    if (memcmp(tx_buf2, rx_buf2, tx_buf2_len))
        TEST_FAIL("Invalid data received (pco_tst2)");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, accepted1);
    CLEANUP_RPC_CLOSE(pco_iut, accepted2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    free(tx_buf1);
    free(rx_buf1);
    free(tx_buf2);
    free(rx_buf2);

    TEST_END;
}
