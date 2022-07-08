/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-pending_error IOMUX function return "ready" if pending error exists on the socket
 *
 * @objective Check that IOMUX function return "ready" if a pending error 
 *            exists on the socket and read operation on the socket
 *            will not block and return (-1) with errno ECONNRESET.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 6.3, 6.4
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TST
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll())
 *
 * @par Scenario:
 * -# Create @p iut_s socket of the @c SOCK_STREAM type on the @p PCO_IUT;
 * -# Create @p tst_s socket of the @c SOCK_STREAM type on the @p PCO_TST;
 * -# @b bind() @p iut_s socket to the iut_addr;
 * -# @b bind() @p tst_s socket to the tst_addr;
 * -# Call @b listen() on the @p tst_s socket;
 * -# @b connect() @p iut_s socket to the @p tst_s one;
 * -# Close @p tst_s socket. After it, RST segment should be received on the
 *    @p iut_s stream connection end and errno should be set;
 * -# Call @p iomux function on @p pco_iut with 2 seconds timeout to wait
 *    for @e read event on @p iut_s socket.
 * -# Check that @p iomux function returns @c 1 as reaction on pending error;
 * -# If @p iomux function returns @c 0, then unexpected behaviour;
 * -# Call blocking @b recv() on the @p iut_s socket;
 * -# Check that previous read operation returns -1 and errno ECONNRESET;
 * -# Close created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/pending_error"

#include "sockapi-test.h"
#include "iomux.h"

#define TST_BUF_LEN 10


int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    unsigned char           buf[TST_BUF_LEN];
    
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    tarpc_timeval           timeout;
    iomux_evt_fd            event;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_iut, iut_s, tst_addr);

    
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    event.fd = iut_s;
    event.events = EVT_RD;

    pco_iut->op = RCF_RPC_CALL;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (rc < 0)
    {
        TEST_FAIL("iomux_call() failed");
    }

    RPC_CLOSE(pco_tst, tst_s);

    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (rc < 0)
    {
        TEST_VERDICT("%s() failed unexpectedly with errno %s",
                      iomux_call_en2str(iomux),
                      errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else if (rc == 0)
    {
        TEST_VERDICT("%s() unexpected timeout", iomux_call_en2str(iomux));
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, buf, sizeof(buf), 0);
    if (rc != -1)
    {
        TEST_VERDICT("recv() from reseted connection return %d "
                     "instead of -1", rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET,
                    "Peer has closed listening socket with a pending "
                    "connection, recv() on another side of "
                    "connection fails");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
