/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 *
 * $Id$
 */

/** @page sendrecv-recv_zero_dgram Zero-length packet handling by receive functions
 *
 * @objective Check receive functions behaviour when zero-length
 *            packet is received.
 *
 * @type conformance, compatibility
 *
 * @param pco_iut   PCO on IUT
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param pco_tst   Auxiliary PCO
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param func      Function to be used in test to receive data
 *                  (@b read(), @b readv(), @b recv(), @b recvfrom(),
 *                  @b recvmsg() or @b zc_recv())
 *
 * @par Scenario:
 * -# Create @c SOCK_DGRAM connection between @p pco_iut and
 *    @p pco_tst by means of @c GEN_CONNECTION and return socket
 *    descriptors for both client and server side.
 * -# Send zero-lenght datagram to @p iut_s.
 * -# Call @b func function and check it's result.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "sendrecv/recv_zero_dgram"
#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static char rx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char *func;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);

    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    RPC_SEND(rc, pco_tst, tst_s, "", 0, 0);
    TAPI_WAIT_NETWORK;

    if ((rc = recv_by_func(func, pco_iut, iut_s, rx_buf, DATA_BULK, 0))
        != 0)
        TEST_VERDICT("Receive function returned %d instead of 0", rc);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
