/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * This test package contains tests for special cases of TCP protocol, such
 * as ICMP and routing table handling, small and zero window, fragmentation
 * of TCP packets, etc.
 */

/**
 * @page tcp-send_block_unblock TCP send() blocking and un-blocking
 *
 * @objective Check that a process is blocked in send call when buffers are
 *            full and unblocked as soon there is enough space in send
 *            buffer.
 *
 * @param sock_type         Socket type:
 *                          - tcp active
 *                          - tcp passive
 * @param cache_socket      Create cached socket to be reused.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/send_block_unblock"

#include "sockapi-test.h"
#include "tapi_mem.h"
#include "tcp_test_macros.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    sockts_socket_type      sock_type;

    uint64_t sent;
    char    *buf = NULL;
    char    *sndbuf = NULL;
    size_t   sndbuf_len;
    size_t   rcvbuf_len;
    size_t   len;
    size_t   rlen;
    int      tst_rcvbuf;
    size_t   iut_sndbuf;
    te_bool  done;
    te_bool  cache_socket;
    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(cache_socket);

    sndbuf = sockts_make_buf_stream(&sndbuf_len);

    TEST_STEP("If @p cache_socket is @c TRUE and  sock_type is "
              "@c SOCKTS_SOCK_TCP_ACTIVE create cached socket.");
    if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
    {
        sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                    TRUE, cache_socket);
    }

    TEST_STEP("Establish TCP connection.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    /* Pass some data through the connection to increase congestion window
     * and send/receive buffer sizes. */
    rpc_overfill_buffers(pco_iut, iut_s, &sent);
    rcvbuf_len = sent/10;
    buf = tapi_malloc(rcvbuf_len);
    do {
        sent -= rpc_read(pco_tst, tst_s, buf, rcvbuf_len);
    } while (sent > 0);

    TEST_STEP("Overfill IUT send buffer.");
    rpc_overfill_buffers(pco_iut, iut_s, &sent);

    TEST_STEP("Try to write more data to IUT socket.");
    pco_iut->op = RCF_RPC_CALL;
    rpc_write(pco_iut, iut_s, sndbuf, sndbuf_len);

    TEST_STEP("Check the call is blocked.");
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
        ERROR_VERDICT("write() was not blocked");

    TEST_STEP("Read some data (up to IUT send buffer size) by tester.");
    rpc_ioctl(pco_tst, tst_s, RPC_FIONREAD, &tst_rcvbuf);
    iut_sndbuf = sent - tst_rcvbuf;

    TEST_STEP("Read by 10%% of send buffer size a time.");
    rcvbuf_len = iut_sndbuf / 10;
    buf = tapi_malloc(rcvbuf_len);

    len = iut_sndbuf;
    do {
        rc = rpc_read(pco_tst, tst_s, buf, len > rcvbuf_len ?
                                           rcvbuf_len : len);
        if (rc == 0)
            TEST_VERDICT("Tester unexpectedly got EOF");
        len -= rc;

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
        if (done)
            break;
    } while (len > 0);
    rlen = iut_sndbuf - len;

    RING("Total sent data amount %llu, read %"TE_PRINTF_SIZE_T"d",
         sent, rlen);

    TEST_STEP("IUT send operation should be unblocked, check returned value.");
    rc = rpc_write(pco_iut, iut_s, sndbuf, sndbuf_len);
    if (rc != (int)sndbuf_len)
        TEST_VERDICT("IUT send operation returned incorrect value after "
                     "unblocking.");

    TEST_STEP("Check there is still some data in send buffer apart from the last "
              "chunk.");
    rpc_ioctl(pco_tst, tst_s, RPC_FIONREAD, &tst_rcvbuf);
    RING("tst_rcvbuf=%d must be < than sent=%d - rlen=%d - sndbuf_len=%d = %d",
          tst_rcvbuf, sent, rlen, sndbuf_len, sent - rlen - sndbuf_len);
    if ((size_t)tst_rcvbuf >= sent - rlen - sndbuf_len)
        TEST_FAIL("Write call was not unblocked until send buffer is empty");

    TEST_STEP("Read the rest of data by tester, check data amount.");
    len = sent - rlen;
    do {
        rc = rpc_read(pco_tst, tst_s, buf, len > rcvbuf_len ?
                                           rcvbuf_len : len);
        if (rc == 0)
            TEST_VERDICT("Tester unexpectedly got EOF");
        len -= rc;
    } while (len > 0);

    TEST_STEP("Read the last chunk of data, validate it.");
    rc = rpc_read(pco_tst, tst_s, buf, sndbuf_len);
    SOCKTS_CHECK_RECV(pco_tst, sndbuf, buf, sndbuf_len, rc);

    TEST_STEP("Check no extra data comes to tester.");
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_recv(pco_tst, tst_s, buf, rcvbuf_len, RPC_MSG_DONTWAIT);
    if (rc > 0)
        TEST_VERDICT("Extra data was received");
    if (rc != -1 || RPC_ERRNO(pco_tst) != RPC_EAGAIN)
        TEST_VERDICT("Tester recv() call had to fails with EAGAIN");

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
