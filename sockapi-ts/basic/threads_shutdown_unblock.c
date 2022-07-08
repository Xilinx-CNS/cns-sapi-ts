/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-threads_shutdown_unblock Shutdown on socket shared by many threads
 *
 * @objective Check the behavior in the case if shutdown() is called
 *            on the socket that is shared between several threads and that
 *            action in any thread changes the socket state for other thread.
 *
 * @type Conformance, compatibility
 *
 *
 * @param env   Testing environment:
 *              - Private environments similar to @ref arg_types_env_peer2peer
 *              and @ref arg_types_env_peer2peer but with three threads on IUT.
 *              - The same but tester RPC server is on IUT host - loopback
 *              testing.
 * @param func_thread2  Function to be called in thread #2 in the blocking
 *                      mode:
 *                      - recv
 *                      - send
 * @param func_thread3  Function to be called in thread #3 in the blocking
 *                      mode:
 *                      - recv
 *                      - send
 * @param howto         Action which should be performed by @b shutdown()
 *                      called in thread #1:
 *                      - SHUT_RD
 *                      - SHUT_WR
 *                      - SHUT_RDWR
 *
 * @note @p func_thread2 and @p func_thread3 are: combinations of @b read(),
 *       @b write().
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut1 of the @c SOCK_STREAM type;
 * -# @b bind() @p iut_s to the @p iut_addr;
 * -# Create socket @p tst_s on @p pco_tst of the @c SOCK_STREAM type;
 * -# @b bind() @p tst_s to the @p tst_addr;
 * -# Call @b listen() on @p tst_s;
 * -# @b connect() @p iut_s to the @p tst_s;
 * -# Call @b accept() on @p tst_s to get @p acc_s socket descriptor;
 * -# According to @p func_thread2 and @p func_thread3 create conditions
 *    to block checked function;
 * -# Call @p func_thread2 and @p func_thread3;
 * -# @b shutdown() with action pointed by @p howto.
 * -# Check behavior @p func_thread2 and @p func_thread3 on action of
 *    @b shutdown();
 * -# Close all sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/threads_shutdown_unblock"

#include "sockapi-test.h"
#include "iomux.h"
#include "sendrecv_call_wait.h"

#define TST_BUF_LEN             4096
#define TST_BUF_RW              10

#define TST_CALL_FUNC(_i) \
    CALL_SR_FUNC(pco_iut##_i, func_thread##_i, thr##_i##_write,     \
                 iut_s, tx_buf, TST_BUF_RW, rx_buf, TST_BUF_RW)

#define TST_WAIT_FUNC(_i, _exit) \
    WAIT_SR_FUNC(pco_iut##_i, func_thread##_i, thr##_i##_write,     \
                 iut_s, tx_buf, TST_BUF_RW, rx_buf, TST_BUF_RW,     \
                 _exit)

int
main(int argc, char *argv[])
{
    void                       *func_thread2;
    void                       *func_thread3;
    rpc_shut_how                howto;
    int                         thr2_write;
    int                         thr3_write;

    rcf_rpc_server             *pco_iut1;
    rcf_rpc_server             *pco_iut2;
    rcf_rpc_server             *pco_iut3;
    rcf_rpc_server             *pco_tst;

    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;

    int                         iut_s = -1;
    int                         tst_s = -1;
    int                         acc_s = -1;

    int                         recv;
    int                         sent;

    char                       *rx_buf = NULL;
    char                       *tx_buf = NULL;

    int                         buf_len = TST_BUF_LEN;

    uint64_t                    overfill_sent;
    
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_iut3);
    TEST_GET_PCO(pco_tst);
    TEST_GET_FUNC(func_thread2, thr2_write);
    TEST_GET_FUNC(func_thread3, thr3_write);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SHUT_HOW(howto);

    rx_buf = te_make_buf_by_len(buf_len);
    tx_buf = te_make_buf_by_len(buf_len);

    iut_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut1, iut_s, iut_addr);

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_iut1, iut_s, tst_addr);

    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    rpc_overfill_buffers(pco_iut2, iut_s, &overfill_sent);

    CHECK_RC(tapi_sigaction_simple(pco_iut1, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    TST_CALL_FUNC(2);
    TST_CALL_FUNC(3);
    TAPI_WAIT_NETWORK;

    rpc_shutdown(pco_iut1, iut_s, howto);
    TAPI_WAIT_NETWORK;

    switch (howto)
    {
        case RPC_SHUT_RD:
            if (thr2_write || thr3_write)
            {
                do {
                    RPC_AWAIT_IUT_ERROR(pco_tst);
                    recv = rpc_recv(pco_tst, acc_s, rx_buf, TST_BUF_LEN,
                                    RPC_MSG_DONTWAIT);
                } while (recv != -1);
                CHECK_RPC_ERRNO(pco_tst, RPC_EAGAIN,
                                "recv() returns -1, but");
            }
            TST_WAIT_FUNC(2, thr2_write ? TST_BUF_RW : 0);
            TST_WAIT_FUNC(3, thr3_write ? TST_BUF_RW : 0);
            break;
            
        case RPC_SHUT_WR:
            if (!thr2_write || !thr3_write)
            {
                RPC_SEND(sent, pco_tst, acc_s, rx_buf, TST_BUF_LEN,
                         RPC_MSG_DONTWAIT);
                if(sent != TST_BUF_LEN)
                {
                    TEST_FAIL("It's impossible to send %d, returned %d",
                              TST_BUF_LEN, sent);
                }
            }
            TST_WAIT_FUNC(2, thr2_write ? -1 : TST_BUF_RW);
            TST_WAIT_FUNC(3, thr3_write ? -1 : TST_BUF_RW);
            break;
            
        case RPC_SHUT_RDWR:
            TST_WAIT_FUNC(2, thr2_write ? -1 : 0);
            TST_WAIT_FUNC(3, thr3_write ? -1 : 0);
            break;

        default:
            TEST_FAIL("Unexpected shutdown() operation %d", howto);
            break;
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut1, RPC_SIGPIPE, &old_act, 
                              SIGNAL_REGISTRAR);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}

