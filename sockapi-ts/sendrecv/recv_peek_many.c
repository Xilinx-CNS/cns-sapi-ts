/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-recv_peek_many MSG_PEEK may be used many times
 *
 * @objective Check that @c MSG_PEEK flag many be used many times on the
 *            same data.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param func      Function to be used in the test to receive data:
 *                  - @b recv()
 *                  - @b recvfrom()
 *                  - @b recvmsg()
 *                  - @b recvmmsg()
 *                  - @b onload_zc_recv()
 *                  - @b onload_zc_hlrx_recv_zc()
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * -# Send data from @p tst_s socket.
 * -# Random number of times receive data from @p iut_s socket using 
 *    @p func with @c MSG_PEEK flag and random size buffers.
 *    Received data must be equal to corresponding sent data.
 * -# Receive data once more without @c MSG_PEEK flag.
 *    Received data must be equal to corresponding sent data.
 *
 * @post Sockets @p iut_s and @p tst_s are kept connected.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recv_peek_many"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define BUF_SIZE      4096  /**< Top margin for size of data to be sent */

static char tx_buf[BUF_SIZE];
static char rx_buf[BUF_SIZE * 2];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;
    const char         *func;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;
    int     n;
    ssize_t len;
    size_t  pkt_len;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(pkt_len);

    /* Fixme: disable msg_flags auto check for datagrams. In case of
     * incomplete reading of a datagram flag MSG_TRUNC is set, what is
     * detected by the check. If msg_flags check is desired then explicit
     * call of recvmsg() like functions should be done with subsequent
     * flags check.
     *
     * This does not require any reversion, i.e. the check is disabled only
     * for the current test run. */
    if (sock_type == RPC_SOCK_DGRAM)
        tapi_rpc_msghdr_msg_flags_init_check(FALSE);

    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    te_fill_buf(tx_buf, pkt_len);
    if (rpc_write(pco_tst, tst_s, tx_buf, pkt_len) != (int)pkt_len)
        TEST_FAIL("Cannot send data from TST");

    MSLEEP(10);

    for (n = rand_range(2, 10); n > 0; n--)
    {
        int rx_len = sizeof(rx_buf);

        memset(rx_buf, 0, sizeof(rx_buf));
        if (strcmp(func, "onload_zc_recv") == 0)
        {
            int msgs_num = rand_range(0, 3);

            if (msgs_num == 0)
                msgs_num = -1; /* Maximum number of messages */

            /*
             * In case of onload_zc_recv() we cannot specify
             * how many bytes we want to receive; we can only
             * specify after which number of messages callback
             * will return ONLOAD_ZC_TERMINATE to avoid processing
             * remaining packets.
             */
            RPC_AWAIT_ERROR(pco_iut);
            len = sockts_recv_by_zc_recv(pco_iut, iut_s, rx_buf,
                                         rx_len, msgs_num,
                                         RPC_MSG_PEEK);
            RING("%" TE_PRINTF_SIZE_T "d bytes received", len);
            if (msgs_num > 0)
                rx_len = len;
            else
                rx_len = pkt_len;
        }
        else
        {
            rx_len = rand_range(1, sizeof(rx_buf));
            RPC_AWAIT_ERROR(pco_iut);
            len = recv_by_func(func, pco_iut, iut_s, rx_buf, rx_len,
                               RPC_MSG_PEEK);

            if (rx_len > (int)pkt_len)
                rx_len = pkt_len;
        }

        if (len == 0)
            TEST_VERDICT("Zero bytes was received with MSG_PEEK");
        SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf, rx_buf, rx_len, len,
                              "Receiving with MSG_PEEK");
    }

    memset(rx_buf, 0, sizeof(rx_buf));
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func(func, pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);
    SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf, rx_buf, pkt_len, len,
                          "Receiving without MSG_PEEK");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
