/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-sock_shut_rd Socket was shut down for reading
 *
 * @objective Check I/O multiplexing functions behaviour when socket
 *            was shut down for reading.
 *
 * @type conformance, compatibility
 *
 * @requirement REQ-1, REQ-2, REQ-3, REQ-13
 *
 * @reference @ref STEVENS section 6.3, 6.6, 6.9, 6.10
 *
 * @param sock_type Type of the socket (@c SOCK_DGRAM, @c SOCK_STREAM, etc)
 * @param pco_iut   PCO on IUT
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param pco_tst   Auxiliary PCO
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll())
 *
 * @par Scenario:
 * -# Create connection between @p pco_iut and @p pco_tst using
 *    @ref lib-gen_connection algorithm with the following parameters:
 *      - @a srvr: @p pco_iut;
 *      - @a clnt: @p pco_tst;
 *      - @a sock_type: @p sock_type;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut_addr;
 *      - @a clnt_addr: @p tst_addr;
 *      - @a srvr_s: stored in @p iut_s;
 *      - @a clnt_s: stored in @p tst_s;
 * -# @b shutdown(@p iut_s, @c SHUT_RD) IUT socket for reading;
 * -# Wait for @e read event on the socket using @b iomux function
 *    with zero timeout;
 * -# Check that @p iomux function return @c 1 and @e read event;
 * -# Close @p iut_s and @p tst_s sockets.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/sock_shut_rd"
#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rpc_socket_type         type;
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    iomux_evt               event = EVT_RD;
    int                     err = -1;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(type);
    TEST_GET_IOMUX_FUNC(iomux);

    GEN_CONNECTION(pco_iut, pco_tst, type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);

    err = iomux_common_steps(iomux, pco_iut, iut_s, &event, IOMUX_TIMEOUT_RAND,
                             FALSE, pco_tst, tst_s, RPC_SHUT_NONE, &rc);
    if (err != 0)
    {
        TEST_FAIL("Siomux_common_steps() function failed");
    }

    if ((rc != 1) || (event != EVT_RD))
    {
        TEST_VERDICT("Waiting for read event on shut down for reading "
                     "socket using %s() returns %d(%s) instead of %d(%s)",
                     iomux_call_en2str(iomux),
                     rc, iomux_event_rpc2str(event),
                     1, iomux_event_rpc2str(EVT_RD));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
