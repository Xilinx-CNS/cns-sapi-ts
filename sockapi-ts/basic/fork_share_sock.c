/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-fork_share_sock Check sharing a socket between processes using a unix domain socket
 *
 * @objective Check that sharing a socket between processes using a unix
 *            domain socket works properly.
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Scenario:
 * -# Make two child processes of @p pco_iut: @p pco_chld1 and @p pco_chld2;
 * -# Create socket @p chld1_rs on @p pco_chld1 and @p tst_rs on @p pco_tst;
 * -# Share the socket @p chld1_rs with process @p pco_chld2 via UNIX
 *    socket, in result @p chld2_rs;
 * -# In case if @p sock_type is @c SOCK_STREAM make TCP connection using
 *    the @p chld2_rs and @p tst_rs sockets, in result oscket @p tst_conn_s
 *    on the @p pco_tst;
 * -# In case if @p sock_type is @c SOCK_DGRAM will mind that @p tst_conn_s
 *    is equal to @p tst_rs;
 * -# Send a packet via @p chld1_rs, receive it via @p tst_conn_s and check
 *    the received packet;
 * -# Repeat the previous step but use @p chld2_rs instead @p chld1_rs.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/fork_share_sock"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_chld1 = NULL;
    rcf_rpc_server         *pco_chld2 = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *tst_addr = NULL;

    int                     tst_rs = -1;
    int                     tst_conn_s = -1;
    int                     chld1_rs = -1;
    int                     chld2_rs = -1;

    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;
    size_t                  res;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    tx_buf = sockts_make_buf_stream(&buf_len);
    rx_buf = te_make_buf_by_len(buf_len);

    rcf_rpc_server_fork(pco_iut, "pco_iut_chld1", &pco_chld1);
    rcf_rpc_server_fork(pco_iut, "pco_iut_chld2", &pco_chld2);

    chld1_rs = rpc_socket(pco_chld1, rpc_socket_domain_by_addr(tst_addr),
                          sock_type, RPC_PROTO_DEF);
    tst_rs = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                        sock_type, RPC_PROTO_DEF);

    chld2_rs = sockts_share_socket_2proc(pco_chld1, pco_chld2, chld1_rs);

    rpc_bind(pco_tst, tst_rs, tst_addr);
    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_tst, tst_rs, 10);
        rpc_connect(pco_chld2, chld2_rs, tst_addr);
        tst_conn_s = rpc_accept(pco_tst, tst_rs, NULL, NULL);
    }
    else
    {
        rpc_connect(pco_chld2, chld2_rs, tst_addr);
        tst_conn_s = tst_rs;
    }

#define RECV_AND_CHECK_BUF \
do {                                                            \
    res = rpc_recv(pco_tst, tst_conn_s, rx_buf, buf_len, 0);    \
    if (res != buf_len)                                         \
        TEST_FAIL("Only part of data received");                \
    if (memcmp(tx_buf, rx_buf, buf_len))                        \
        TEST_FAIL("Invalid data received");                     \
} while(0)

    RPC_AWAIT_IUT_ERROR(pco_chld1);
    rc = rpc_send(pco_chld1, chld1_rs, tx_buf, buf_len, 0);
    if (rc < 0 && RPC_ERRNO(pco_chld1) == RPC_EPIPE)
        RING_VERDICT("send() failed with errno EPIPE");
    else if (rc < 0)
        TEST_FAIL("Send failed with unexpected errno %s",
                  errno_rpc2str(RPC_ERRNO(pco_chld1)));
    else
        RECV_AND_CHECK_BUF;

    memset(rx_buf, 0, buf_len);

    rpc_send(pco_chld2, chld2_rs, tx_buf, buf_len, 0);
    RECV_AND_CHECK_BUF;

#undef RECV_AND_CHECK_BUF

    TEST_SUCCESS;

cleanup:
    if (sock_type == RPC_SOCK_STREAM)
        CLEANUP_RPC_CLOSE(pco_tst, tst_conn_s);

    CLEANUP_RPC_CLOSE(pco_chld1, chld1_rs);
    CLEANUP_RPC_CLOSE(pco_chld2, chld2_rs);
    CLEANUP_RPC_CLOSE(pco_tst, tst_rs);

    rcf_rpc_server_destroy(pco_chld1);
    rcf_rpc_server_destroy(pco_chld2);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
