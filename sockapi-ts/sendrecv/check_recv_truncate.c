/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 */

/**
 * @page sendrecv-check_recv_truncate  Discarding received data in TCP case and partially receiving in UDP case with MSG_TRUNC
 *
 * @objective Check that on a TCP socket part of received data may be discarded
 *            and on a UDP socket part of data will be received and rest of
 *            data will be discarded by calling receive function with
 *            MSG_TRUNC flag.
 *
 * @param func        Function to be used in the test to receive data:
 *      - recv
 *      - recvfrom
 *      - recvmsg
 *      - recvmmsg
 * @param null_buffer Use @c NULL or non-NULL buffer in @b recv() function:
 *      - FALSE
 *      - TRUE
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Scenario:
 *
 * @author Anton Protasov <Anton.Protasov@oktetlabs.ru>
 * @author Demid Trempolskii <Demid.Trempolskii@arknetworks.am>
 */

#define TE_TEST_NAME "sendrecv/check_recv_truncate"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    int                         iut_s = -1;
    int                         tst_s = -1;
    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;
    rpc_socket_type             sock_type;

    rpc_recv_f                  func;
    char                       *tx_buf;
    char                       *rx_buf;
    char                        rx_buf_orig[SOCKTS_MSG_STREAM_MAX];
    size_t                      tx_buf_len = SOCKTS_MSG_STREAM_MAX;
    size_t                      buf_trunc_size;
    te_bool                     is_readable = FALSE;
    te_bool                     null_buffer;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_RECV_FUNC(func);
    TEST_GET_BOOL_PARAM(null_buffer);
    TEST_GET_SOCK_TYPE(sock_type);

    /*
     * In case of UDP it is needed to avoid flag check in receiving functions
     * to prevent unneeded verdict.
     */
    if (sock_type == RPC_SOCK_DGRAM)
        tapi_rpc_msghdr_msg_flags_init_check(FALSE);

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    buf_trunc_size = rand_range(tx_buf_len / 3, 2 * tx_buf_len / 3);
    rx_buf = te_make_buf_by_len(SOCKTS_MSG_STREAM_MAX);
    memcpy(rx_buf_orig, rx_buf, SOCKTS_MSG_STREAM_MAX);

    TEST_STEP("Create two TCP or UDP sockets and connect them");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("Send some data from TST to IUT");
    rpc_send(pco_tst, tst_s, tx_buf, tx_buf_len, 0);

    TEST_STEP("Call @p func with @c MSG_TRUNC flag to discard some data "
              "received in case of TCP and partially receive in case of UDP "
              "from TST");
    if (sock_type == RPC_SOCK_DGRAM && null_buffer)
        rc = func(pco_iut, iut_s, NULL, 0, RPC_MSG_TRUNC);
    else
        rc = func(pco_iut, iut_s, (null_buffer ? NULL : rx_buf),
                  buf_trunc_size, RPC_MSG_TRUNC);

    TEST_STEP("In case of TCP check, that right amount of data was discarded "
              "and in case of UDP check that size of datagram sended and "
              "received are equal");
    if (sock_type == RPC_SOCK_STREAM)
    {
        if (rc != (long int)buf_trunc_size)
            TEST_VERDICT("Size mismatch with MSG_TRUNC");
    }
    else
    {
        if (rc != (long int)tx_buf_len)
            TEST_VERDICT("Size of the datagram mismatch with sended buffer");
    }

    if (!null_buffer)
    {
        if (sock_type == RPC_SOCK_STREAM)
        {
            if (memcmp(rx_buf, rx_buf_orig, buf_trunc_size) != 0)
                TEST_VERDICT("Received buffer with MSG_TRUNC was modified");
        }
        else
        {
            if (memcmp(rx_buf, tx_buf, buf_trunc_size) != 0)
                TEST_VERDICT("Received buffer with MSG_TRUNC differs from expected");
        }
    }

    TEST_STEP("In case of TCP call @p func without MSG_TRUNC,"
              " check that it returns remained data");

    if (sock_type == RPC_SOCK_STREAM)
    {
        rc = func(pco_iut, iut_s, rx_buf, tx_buf_len, 0);
        SOCKTS_CHECK_RECV(pco_iut, tx_buf + buf_trunc_size, rx_buf,
                          tx_buf_len - buf_trunc_size, rc);
    }

    RPC_GET_READABILITY(is_readable, pco_iut, iut_s, 0);
    if (is_readable)
        TEST_VERDICT("Socket is readable after reading all the data");

    TEST_STEP("Send and receive packet without @c MSG_TRUNC flag");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
