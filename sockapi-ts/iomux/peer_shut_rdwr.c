/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-peer_shut_rdwr Peer shuts down reading and writing
 *
 * @objective Check I/O multiplexing functions behaviour when peer
 *            shuts down connection for reading and writing.
 *
 * @type conformance, compatibility
 *
 * @requirement REQ-1, REQ-2, REQ-3, REQ-13
 *
 * @reference @ref STEVENS section 6.3, 6.6, 6.9, 6.10
 *
 * @param pco_iut   PCO on IUT
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param pco_tst   Auxiliary PCO
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll())
 *
 * @par Scenario:
 * -# Create stream connection between @p pco_iut and @p pco_tst using
 *    @ref lib-stream_client_server algorithm with the following
 *    parameters:
 *      - @a srvr: @p pco_tst;
 *      - @a clnt: @p pco_iut;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p tst_addr;
 *      - @a srvr_wild: @c FALSE;
 *      - @a clnt_addr: @p iut_addr;
 *      .
 *    Created sockets are further named as @p iut_s and @p tst_s;
 * -# Wait for @e write event on @p iut_s socket using @p iomux function
 *    and, then, send data to it using @b send() function, until
 *    waiting for @e write event times out;
 * -# Wait for @e read and @e write events on @p iut_s socket using
 *    @b iomux function with 10 seconds timeout.
 * -# @b shutdown() @p tst_s socket for reading and writing (@c SHUT_RDWR);
 * -# Check that @b iomux function returns @c 1;
 * -# Check that @p iut_s socket is not reported as ready for writing;
 * -# Check that @p iut_s is reported as ready for reading;
 * -# @b read() data from @p iut_s socket, it must return @c 0;
 * -# Close @b iut_s and @b tst_s sockets.
 * 
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/peer_shut_rdwr"
#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    iomux_evt               event = EVT_RDWR;
    unsigned char           buffer[SOCKTS_BUF_SZ];
    int                     err = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    err = iomux_common_steps(iomux, pco_iut, iut_s, &event, IOMUX_TIMEOUT_RAND, 
                             TRUE, pco_tst, tst_s, RPC_SHUT_RDWR, &rc);
    if (err != 0)
    {
        TEST_FAIL("iomux_common_steps() failed");
    }

    if (rc != 1)
    {
        TEST_FAIL("Peer shut down its socket for reading and writing, "
                  "%s() returns %d instead of 1",
                  iomux_call_en2str(iomux), rc);
    }
    if (event != EVT_RD)
    {
        TEST_FAIL("The socket is not reported as ready for reading only "
                  "when its peer shuts down reading and writing");
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, buffer, sizeof(buffer), 0);
    if (rc != 0)
        TEST_FAIL("Unexpected recv() behaivour after peer shutdown");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
