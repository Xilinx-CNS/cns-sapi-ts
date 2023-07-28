/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page extension-onload_zc_send onload_zc_send() operation on the SOCK_STREAM socket
 *
 * @objective Test on reliability of the @b onload_zc_send() operation 
 *            on BSD compatible sockets.
 *
 * @type use case
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst1              PCO on TESTER or IUT
 * @param pco_tst2              Another PCO on TESTER or IUT
 * @param iut_addr1             Network address on IUT
 * @param iut_addr2             Another network address on IUT
 * @param tst_addr1             Network address for @p pco_tst1
 * @param tst_addr2             Network address for @p pco_tst2
 * @param first_active          Whether the first connection should be
 *                              opened actively on @ pco_iut or not
 * @param second_active         Whether the second connection should be
 *                              opened actively on @ pco_iut or not
 * @param alloc_another_sock    Whether to allocate Onload buffer for
 *                              other socket than from which to send
 *                              a data or not
 * @param diff_stacks           Whether to create the second pair of
 *                              connected sockets in a child process
 *                              or in the same one
 * @param use_exec              Whether to call @b exec() before creation
 *                              of the second pair of connected sockets
 *                              or not
 * @param user_buf              If @c TRUE, use
 *                              @b onload_zc_register_buffers(); otherwise
 *                              use @b onload_zc_alloc_buffers().
 *
 * @par Scenario:
 *
 * -# Create a pair of @c SOCK_STREAM type connected sockets - @p iut_s1
 *    on @p pco_iut and @p tst_s1 on @p pco_tst1.
 * -# If @p alloc_another_sock, create @p aux_s @c SOCK_STREAM type
 *    socket on @p pco_iut.
 * -# If @p diff_stacks, call @b fork() to create @p pco_aux child
 *    process; otherwise set @p pco_aux = @p pco_iut.
 * -# If @p use_exec, call @b exec() in @p pco_aux.
 * -# Create the second pair of @c SOCK_STREAM type connected
 *    sockets - @p iut_s2 on @p pco_aux and @p tst_s2 on @p pco_tst2.
 * -# Send data from @p iut_s1 and @p iut_s2 by a single call of
 *    @p onload_zc_send(). If @p alloc_another_sock, Onload buffer
 *    should be allocated using @p aux_s descriptor for both
 *    sockets.
 * -# Check return value of @b onload_zc_send().
 * -# Receive data on @p tst_s1 and @p tst_s2, check it for
 *    correctness.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/onload_zc_send"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_aux = NULL;
    rcf_rpc_server     *pco_tst1 = NULL;
    rcf_rpc_server     *pco_tst2 = NULL;
    int                 iut_s1 = -1;
    int                 iut_s2 = -1;
    int                 aux_s = -1;
    int                 tst_s1 = -1;
    int                 tst_s2 = -1;
    void               *tx_buf1 = NULL;
    size_t              tx_buf1_len;
    void               *tx_buf2 = NULL;
    size_t              tx_buf2_len;
    void               *rx_buf1 = NULL;
    size_t              rx_buf1_len;
    void               *rx_buf2 = NULL;
    size_t              rx_buf2_len;

    const struct sockaddr  *iut_addr1;
    const struct sockaddr  *iut_addr2;
    const struct sockaddr  *tst_addr1;
    const struct sockaddr  *tst_addr2;

    struct rpc_iovec iov1;
    struct rpc_iovec iov2;
    struct rpc_onload_zc_mmsg msgs[2];

    te_bool first_active = FALSE;
    te_bool second_active = FALSE;
    te_bool alloc_another_sock = FALSE;
    te_bool diff_stacks = FALSE;
    te_bool use_exec = FALSE;
    te_bool user_buf = FALSE;
    te_bool op_done = FALSE;
    te_bool readable = FALSE;
    te_bool is_failed = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst_addr1);
    TEST_GET_ADDR(pco_tst2, tst_addr2);
    TEST_GET_BOOL_PARAM(first_active);
    TEST_GET_BOOL_PARAM(second_active);
    TEST_GET_BOOL_PARAM(alloc_another_sock);
    TEST_GET_BOOL_PARAM(diff_stacks);
    TEST_GET_BOOL_PARAM(use_exec);
    TEST_GET_BOOL_PARAM(user_buf);

    tx_buf1 = sockts_make_buf_stream(&tx_buf1_len);
    rx_buf1 = te_make_buf_min(tx_buf1_len, &rx_buf1_len);
    tx_buf2 = sockts_make_buf_stream(&tx_buf2_len);
    rx_buf2 = te_make_buf_min(tx_buf2_len, &rx_buf2_len);

    if(alloc_another_sock)
        aux_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

    if (first_active)
        GEN_CONNECTION(pco_tst1, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                       tst_addr1, iut_addr1, &tst_s1, &iut_s1);
    else
        GEN_CONNECTION(pco_iut, pco_tst1, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                       iut_addr1, tst_addr1, &iut_s1, &tst_s1);

    if (diff_stacks)
    {
        if (use_exec)
            CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, "child", &pco_aux));
        else
            CHECK_RC(rcf_rpc_server_fork(pco_iut, "child", &pco_aux));
        rcf_rpc_setlibname(pco_aux, pco_iut->nv_lib);
    }
    else
    {
        pco_aux = pco_iut;
        if (use_exec)
            CHECK_RC(rcf_rpc_server_exec(pco_aux));
    }

    if (second_active)
        GEN_CONNECTION(pco_tst2, pco_aux, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                       tst_addr2, iut_addr2, &tst_s2, &iut_s2);
    else
        GEN_CONNECTION(pco_aux, pco_tst2, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                       iut_addr2, tst_addr2, &iut_s2, &tst_s2);

    memset(msgs, 0, sizeof(msgs));

    msgs[0].fd = iut_s1;
    msgs[1].fd = iut_s2;
    iov1.iov_base = tx_buf1;
    iov1.iov_len = iov1.iov_rlen = tx_buf1_len;
    iov2.iov_base = tx_buf2;
    iov2.iov_len = iov2.iov_rlen = tx_buf2_len;
    msgs[0].msg.msg_iov = &iov1;
    msgs[0].msg.msg_iovlen = msgs[0].msg.msg_riovlen = 1;
    msgs[1].msg.msg_iov = &iov2;
    msgs[1].msg.msg_iovlen = msgs[1].msg.msg_riovlen = 1;

    pco_aux->op = RCF_RPC_CALL;
    rc = rpc_simple_zc_send_gen(pco_aux, msgs, 2, 0, aux_s, user_buf,
                                RPC_NULL, NULL);

    TAPI_WAIT_NETWORK;

    rc = rcf_rpc_server_is_op_done(pco_aux, &op_done);

    if (rc != 0)
    {
        if (pco_aux != pco_iut)
        {
            rcf_rpc_server_destroy(pco_aux);
            pco_aux = pco_iut;
        }
        else
        {
            rcf_rpc_server_restart(pco_iut);
            iut_s1 = -1;
            iut_s2 = -1;
            aux_s = -1;
        }

        if (TE_RC_GET_ERROR(rc) == TE_ERPCDEAD ||
            TE_RC_GET_ERROR(rc) == TE_ESUNRPC)
            TEST_VERDICT("RPC server crashed after @b onload_zc_recv()"
                         " call");
        else
            TEST_VERDICT("Failed to get onload_zc_send() call status: %s",
                         errno_rpc2str(TE_RC_GET_ERROR(rc)));
    }

    RPC_AWAIT_ERROR(pco_aux);
    pco_aux->op = RCF_RPC_WAIT;

    rc = rpc_simple_zc_send_gen(pco_aux, msgs, 2, 0, aux_s, user_buf,
                                RPC_NULL, NULL);

    if (rc < 0)
    {
        TEST_VERDICT("onload_zc_send() failed with errno " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_aux));
    }

    RPC_GET_READABILITY(readable, pco_tst1, tst_s1, 1000);

    if (!readable)
    {
        ERROR_VERDICT("Data didn't arrive on the first socket");
        is_failed = TRUE;
    }
    else
    {
        rc = rpc_read(pco_tst1, tst_s1, rx_buf1, rx_buf1_len);
        if (rc != (int)tx_buf1_len)
            TEST_FAIL("Only part of data received");
        if (memcmp(tx_buf1, rx_buf1, tx_buf1_len))
            TEST_FAIL("Invalid data received on the first connection");
    }

    RPC_GET_READABILITY(readable, pco_tst2, tst_s2, 1000);

    if (!readable)
    {
        ERROR_VERDICT("Data didn't arrive on the second socket");
        is_failed = TRUE;
    }
    else
    {
        rc = rpc_read(pco_tst2, tst_s2, rx_buf2, rx_buf2_len);
        if (rc != (int)tx_buf2_len)
            TEST_FAIL("Only part of data received");

        if (memcmp(tx_buf2, rx_buf2, tx_buf2_len))
            TEST_FAIL("Invalid data received on the second connection");
    }


    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    if (pco_aux == pco_iut)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut, aux_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s2);
    if (pco_aux != pco_iut)
        rcf_rpc_server_destroy(pco_aux);
    free(tx_buf1);
    free(tx_buf2);
    free(rx_buf1);
    free(rx_buf2);
    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
