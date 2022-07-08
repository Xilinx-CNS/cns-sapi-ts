/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-write_timeout Write event and timeout
 *
 * @objective Check support of @e write event and possibility of
 *            timeout on @e write event.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 6.3, 6.9, 6.10
 *
 * @param pco_iut   PCO on IUT
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param pco_tst   Auxiliary PCO
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll())
 *
 * @pre It's assumed than sum of send buffer on @p iut_s and receive
 *      buffer on @p tst_s is less than 1M.
 *
 * @par Scenario:
 * -# Create stream connection between @p pco_iut and @p pco_tst using
 *    @ref lib-stream_client_server algorithm with the following
 *    parameters:
 *      - @a srvr: @p pco_iut;
 *      - @a clnt: @p pco_tst;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut_addr;
 *      - @a srvr_wild: @c FALSE;
 *      - @a clnt_addr: @p tst_addr;
 *      .
 *    Created sockets are further named as @p iut_s and @p tst_s;
 * -# Call @p iomux function on @p pco_iut with 1 second timeout to wait
 *    for @e write event on @p iut_s socket;
 * -# If @p iomux function returns @c 1, write 4K bytes of data
 *    using @b send() function and go to the step 1;
 * -# If @p iomux function returns @c 0, then waiting of @e write
 *    event is timed out, go to the next step;
 * -# Close created sockets.
 *
 * @par Pass/Fail Criteria:
 * Test should finish all steps until 1M bytes of data are sent
 * from @p iut_s to @p tst_s socket.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/write_timeout"
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

    tarpc_timeval           timeout;
    iomux_evt_fd            event;
    unsigned char           buffer[SOCKTS_BUF_SZ];
    size_t                  total_sent = 0;
    ssize_t                 sent;
    int                     req_val = TRUE;


    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Put the socket to non-blocking state (instead using MSG_DONTWAIT) */
    req_val = TRUE;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);
    
    do {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        event.fd = iut_s;
        event.events = EVT_WR;

        rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
        if (rc == -1)
        {
            TEST_FAIL("Call of %s() function failed", 
                      iomux_call_en2str(iomux));
        }

        if (rc == 1)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            sent = rpc_send(pco_iut, iut_s, buffer, sizeof(buffer), 0);
            if (sent == -1)
            {
                TEST_FAIL("send() in non-blocking mode failed");
            }
            total_sent += sent;
        }
    } while ((rc == 1) && (total_sent < (4 << 20)));

    if (total_sent == 0)
    {
        TEST_FAIL("Write timed out, no data are sent");
    }
    if (rc != 0)
    {
        TEST_FAIL("After sending 1M bytes of data the buffer is not filled");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;   
}
