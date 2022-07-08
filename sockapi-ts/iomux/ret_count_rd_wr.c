/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-ret_count_rd_wr Read and write events return count
 *
 * @objective Check that I/O Multiplexing functions correctly counts
 *            events in return value when the same socket is waited
 *            for reading and writing.
 *
 * @type conformance, compatibility
 *
 * @requirement REQ-1, REQ-2, REQ-3, REQ-13
 *
 * @reference @ref STEVENS
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
 * -# Send data from @p tst_s socket on @b pco_tst PCO using @b send()
 *    function;
 * -# Call @b iomux function on @p pco_iut PCO with zero timeout to wait 
 *    for @e read and @e write events on @p iut_s socket;
 * -# Check that @b iomux function returns @c 2 and @p iut_s socket is
 *    ready for reading and writing;
 * -# If the socket is ready for reading, read data from it using
 *    @b recv() function (sent data must be received);
 * -# Close created sockets.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/ret_count_rd_wr"
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

    iomux_evt               event = EVT_RDWR;
    char                    buffer[301];
    char                    buffer_cp[301];
    int                     err = -1;


    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_SOCK_TYPE(type);

    te_fill_buf(buffer, sizeof(buffer));
    strcpy(buffer_cp, buffer);

    GEN_CONNECTION_WILD(pco_iut, pco_tst, type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    RPC_SEND(rc, pco_tst, tst_s, buffer, sizeof(buffer), 0);
    TAPI_WAIT_NETWORK;
    
    err = iomux_common_steps(iomux, pco_iut, iut_s, &event, IOMUX_TIMEOUT_RAND, 
                             FALSE, pco_tst, tst_s, RPC_SHUT_NONE, &rc);

    if (err != 0)
    {
        TEST_FAIL("Something went wrong in iomux_common_steps() function");
    }

    if (IOMUX_IS_POLL_LIKE(iomux))
    {
        if (rc != 1) 
            TEST_FAIL("%s() called on pco_iut returns %d instead of 1", 
                      iomux_call_en2str(iomux), rc);
    }
    else 
    {
        if (rc != 2)
            TEST_FAIL("%s() called on IUT returns %d instead of 2", 
                      iomux_call_en2str(iomux), rc);
    }


    if ((event & ~(EVT_RD_NORM | EVT_WR_NORM)) != EVT_RDWR)
    {
        TEST_FAIL("%s() function returns not read and write events as "
                  "expected", iomux_call_en2str(iomux));
    }
        
    rc = rpc_recv(pco_iut, iut_s, buffer_cp, sizeof(buffer_cp), 0);
    if (rc != sizeof(buffer_cp))
    {
        TEST_FAIL("Wrong size of recieved buffer");
    }

    if (strcmp(buffer, buffer_cp) != 0)
    {
        TEST_FAIL("Wrong buffer recieved");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
