/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-data_before_accept Check possibility to obtain the data sent before TCP connection was accepted
 *
 * @objective Check that data sent before TCP connection was accepted by
 *            TCP server can be successfully obtained.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func          Tested function:
 *                      - recv()
 * @param before_accept An action to do by Tester while the connections is not
 *                      accepted:
 *                      - data: send data;
 *                      - close: close tester socket;
 *                      - both: send data and close the socket.
 *
 * @par Scenario:
 *
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst.
 * -# Install TCP server on @p iut_s socket (don't call @c accept()).
 * -# @c connect() @p tst_s to the TCP server on @p iut_s.
 * -# @c sent() data to the @p tst_s while socket is writable to fill in
 *    the both local and remote end buffers.
 * -# Call @c accept() on @p iut_s to return @p accepted_s.
 * -# Retrieve length of the both send buffer of @p tst_s and receive buffer
 *    of @p accepted_s by means of @c getsockopt() to check the quantity 
 *    of the sent data.
 * -# Receive data on @p accepted_s while socket is readable.
 * -# Check that obtained data is the same as sent to the @p tst_s socket.
 * -# Close created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/data_before_accept"

#include "sockapi-test.h"

#define TST_BUF_SIZE       65536

int
main(int argc, char *argv[])
{
    rcf_rpc_server      *pco_iut = NULL;
    rcf_rpc_server      *pco_tst = NULL;
    rpc_recv_f           func;

    int                  iut_s = -1;
    int                  tst_s = -1;
    int                  acc_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    uint8_t             *tx_buf;
    uint8_t             *rx_buf;
    int                  sent, rcv;
    unsigned int         i;
    unsigned int         sent_blocks = 0;
    size_t              *sent_lens = NULL;
    const char          *before_accept;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_RECV_FUNC(func);
    TEST_GET_STRING_PARAM(before_accept);
    
    tx_buf = te_make_buf_by_len(TST_BUF_SIZE);
    rx_buf = te_make_buf_by_len(TST_BUF_SIZE);

    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, TRUE, iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_connect(pco_tst, tst_s, iut_addr);
    TAPI_WAIT_NETWORK;

    if (strcmp(before_accept, "close") != 0)
    {
        do {
            memset(tx_buf, sent_blocks, TST_BUF_SIZE);
            RPC_AWAIT_IUT_ERROR(pco_tst);
            sent = rpc_send(pco_tst, tst_s, tx_buf, TST_BUF_SIZE,
                            RPC_MSG_DONTWAIT);
            if (sent < 0)
            {
                CHECK_RPC_ERRNO(pco_tst, RPC_EAGAIN,
                                "send() called on 'pco_tst' "
                                "returns -1, but");
                break;
            }
            ++sent_blocks;
            sent_lens = realloc(sent_lens,
                                sent_blocks * sizeof(*sent_lens));
            CHECK_NOT_NULL(sent_lens);
            sent_lens[sent_blocks - 1] = sent;

            /* Sleep to allow TCP to push the data */
            TAPI_WAIT_NETWORK;
        } while (1);
        INFO("send() transmitted %u buffers", sent_blocks);
    }
    if (strcmp(before_accept, "data") != 0)
    {
        RPC_CLOSE(pco_tst, tst_s);
        rcf_rpc_server_restart(pco_tst);
        TAPI_WAIT_NETWORK;
    }

    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    for (i = 0; i < sent_blocks; i++)
    {
        memset(tx_buf, i, sent_lens[i]);
        rcv = 0;

        do {
            RPC_AWAIT_ERROR(pco_iut);
            rc = func(pco_iut, acc_s, rx_buf + rcv, sent_lens[i] - rcv,
                      RPC_MSG_DONTWAIT);
            if (rc < 0)
            {
                ERROR("Receive function returned %d bytes instead of %u",
                      (int)rcv, (unsigned int)sent_lens[i]);
                TEST_VERDICT("Receive function failed with errno %r",
                             RPC_ERRNO(pco_iut));
            }
            rcv += rc;
        } while(rcv < (long int)sent_lens[i]);

        if (memcmp(tx_buf, rx_buf, sent_lens[i]) != 0)
        {
            TEST_VERDICT("data received through 'acc_s' is not the same "
                         "as sent through 'tst_s'");
        }
    }
    if (strcmp(before_accept, "data") != 0)
    {
        rcv = func(pco_iut, acc_s, rx_buf, 1, 0);
        if (rcv != 0)
            TEST_VERDICT("Receive function returned %d instead of 0.");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
