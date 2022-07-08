/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocatmark_oobinline SIOCATMARK for sockets with SO_OOBINLINE enabled
 *
 * @objective Check that @c SIOCATMARK behaivour when
 *            option @c SO_OOBINLINE is set on the socket.
 * 
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_s         TCP socket on @p pco_iut
 * @param tst_s         TCP socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Test sequence:
 * -# setsockopt(SO_OOBINLINE) to enable out-of-band data in-line.
 * -# Call @b ioctl() on @p iut_s socket with @c SIOCATMARK.
 * -# Send one byte with MSG_OOB flag from @p pco_tst.
 * -# Call @b ioctl() on @p iut_s socket with @c SIOCATMARK.
 * -# Receive the byte on @p pco_iut. Send N bytes with @c MSG_OOB 
 *    flag from @p pco_tst.
 * -# Call @b ioctl() on @p iut_s socket with @c SIOCATMARK.
 * -# Receive N - 1 bytes on @p pco_iut.
 * -# Call @b ioctl() on @p iut_s socket with @c SIOCATMARK.
 * -# Receive 1 byte on @p pco_iut.
 * -# Call @b ioctl() on @p iut_s socket with @c SIOCATMARK.
 * -# Send one byte without MSG_OOB flag from @p pco_tst.
 * -# Call @b ioctl() on @p iut_s socket with @c SIOCATMARK.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocatmark_oobinline"

#include "sockapi-test.h"

#define DATA_BULK       8

#define CALL_IOCTL(_expected) \
    do {                                                                \
        rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &req_val);            \
        if (req_val != _expected)                                       \
        {                                                               \
            TEST_VERDICT("SIOCATMARK is unexpected: %d instead of %d",  \
                         req_val, _expected);                           \
        }                                                               \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    int                    req_val = 1;
    unsigned char          tx_buf[DATA_BULK];
    unsigned char          rx_buf[DATA_BULK];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    te_fill_buf(tx_buf, sizeof(tx_buf));

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    rpc_setsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &req_val);

    CALL_IOCTL(0);

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, 1, RPC_MSG_OOB);
    TAPI_WAIT_NETWORK;
    CALL_IOCTL(1);
    rpc_recv(pco_iut, iut_s, rx_buf, 1, 0);

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, DATA_BULK, RPC_MSG_OOB);
    TAPI_WAIT_NETWORK;
    CALL_IOCTL(0);
    rpc_recv(pco_iut, iut_s, rx_buf, DATA_BULK - 1, 0);
    CALL_IOCTL(1);
    rpc_recv(pco_iut, iut_s, rx_buf, 1, 0);
    CALL_IOCTL(0);

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, 1, 0);
    TAPI_WAIT_NETWORK;
    CALL_IOCTL(0);

    TEST_SUCCESS;

cleanup:

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

