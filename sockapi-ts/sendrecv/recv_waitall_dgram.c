/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recv_waitall_dgram MSG_WAITALL flag for datagram sockets
 *
 * @objective Check what happens when @c MSG_WAITALL flag is used
 *            with a datagram socket.
 *
 * @type conformance, compatibility
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func      Function to be used in the test to receive data:
 *                  - @ref arg_types_recv_func_with_flags
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_waitall_dgram"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"


#define DATA_BULK       1024  /**< Size of data to be sent */


static char rx_buf[DATA_BULK * 2] = { 0, };
static char tx_buf[DATA_BULK] = { 0, };


int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char *func;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;
    ssize_t len;

    TEST_START;

    /* Prepare sockets */

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);

    TEST_STEP("Create a pair of connected UDP sockets on IUT and "
              "Tester.");
    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    TEST_STEP("Send a packet from the Tester socket.");
    te_fill_buf(tx_buf, DATA_BULK);
    if (rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK) != DATA_BULK)
        TEST_FAIL("Cannot send a datagram from TST");

    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @p func on the IUT socket, passing to it buffer "
              "with more bytes than was sent and @c MSG_WAITALL flag.");
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf),
                       RPC_MSG_WAITALL);

    TEST_STEP("Check that @c MSG_WAITALL flag is ignored and datagram "
              "is received as usual.");

    if (len < 0)
    {
        TEST_VERDICT("Receive function failed with error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }

    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, DATA_BULK, len);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
