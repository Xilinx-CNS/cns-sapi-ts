/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-exec_fork_multithread Performing fork()/exec() calls in multithread environment
 *
 * @objective Check affecting of the @b fork()/exec() operations to be
 *            performed in one executing thread on socket operations
 *            blocked in other one.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_twothr2peer
 *              - @ref arg_types_env_twothr2peer_ipv6
 * @param func  Tested function:
 *              - read()
 *              - recv()
 *              - write()
 *              - send()
 * @param method    Determines what exactly to do creating the first new
 *                  process:
 *                  - inherit: means just calling @b fork().
 *
 * @par Scenario:
 *
 * -# Create network connection of sockets of @c SOCK_STREAM type by means of
 *    @c GEN_CONNECTION with @p pco_iut1 and @p pco_tst as PCOs to interact,
 *    obtain sockets @p iut_s on @p pco_iut1 and @p tst_s on @p pco_tst.
 * -# Perform @c CHECK_SOCKET_STATE for @p pco_iut1, @p iut_s.
 * -# Check that obtained state of @p iut_s is @c STATE_CONNECTED.
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Create conditions to block @p func and call it in @p pco_iut1.
 * -# Split process @p iut_child from @p pco_iut2 with @b fork().
 * -# Change image of forked process @p iut_child by means of
 *    @b execve() call.
 * -# Block @p func in changed image;
 * -# Create conditions to unblock @p func called in @p pco_iut1 and
 *    in changed image;
 * -# Check that @p func successfuly completes in @p pco_iut1 and
 *    in changed image;
 * -# @b close() all sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/exec_fork_multithread"

#include "sockapi-test.h"
#include "iomux.h"


#define TST_CMP_BUFFERS(_x) \
    do {                                                     \
        if (memcmp(tx_buf, rx_buf, buf_len) != 0)            \
        {                                                    \
            TEST_FAIL("data received on "#_x" differ "       \
                    "than was sent from pco_tst");           \
        }                                                    \
    } while (0)

#define TST_CALL_FUNC(_pco, _sock, _func, _exit) \
    do {                                                                \
        _pco->op = RCF_RPC_CALL;                                        \
        _pco->timeout = TE_SEC2MS(30);                                  \
        switch (_func)                                                  \
        {                                                               \
            case T_READ:                                                \
                rpc_read(_pco, _sock, rx_buf, _exit);                   \
                break;                                                  \
            case T_RECV:                                                \
                rpc_recv(_pco, _sock, rx_buf, _exit, 0);                \
                break;                                                  \
            case T_WRITE:                                               \
                rpc_write(_pco, _sock, tx_buf, _exit);                  \
                break;                                                  \
            case T_SEND:                                                \
                rpc_send(_pco, _sock, tx_buf, _exit, 0);                \
                break;                                                  \
            case T_UNKNOWN:                                             \
            default:                                                    \
                TEST_FAIL("Unexpected function to be tested");          \
        }                                                               \
    } while (0)

#define TST_WAIT_FUNC(_pco, _sock, _func, _exit) \
    do {                                                                \
        _pco->op = RCF_RPC_WAIT;                                        \
        switch (_func)                                                  \
        {                                                               \
            case T_READ:                                                \
            {                                                           \
                rc = rpc_read(_pco, _sock, rx_buf, _exit);              \
                INFO("Received by read() %d bytes", rc);                \
                break;                                                  \
            }                                                           \
            case T_RECV:                                                \
            {                                                           \
                rc = rpc_recv(_pco, _sock, rx_buf, _exit, 0);           \
                INFO("Received by recv()%d bytes", rc);                 \
                break;                                                  \
            }                                                           \
            case T_WRITE:                                               \
                RPC_WRITE(rc, _pco, _sock, tx_buf, _exit);              \
                break;                                                  \
            case T_SEND:                                                \
                RPC_SEND(rc, _pco, _sock, tx_buf, _exit, 0);            \
                break;                                                  \
            case T_UNKNOWN:                                             \
            default:                                                    \
                TEST_FAIL("Unexpected function to be tested");          \
        }                                                               \
    } while (0)

#define TESTED_FUNC(_t_func) \
    strcmp(_t_func, "read") ?                           \
    (strcmp(_t_func, "recv") ?                          \
    (strcmp(_t_func, "write") ?                         \
    (strcmp(_t_func, "send") ? T_UNKNOWN : T_SEND) :    \
    T_WRITE) :  T_RECV) : T_READ;

enum tested_func {
    T_READ,
    T_RECV,
    T_WRITE,
    T_SEND,
    T_UNKNOWN
};

/* NOTE:
 * There is a problem with TST_BUF_LEN equal to 10000.
 * In this case blocked send() on iut_child does not return.
 * It seems this is TCP problem.
 */
#define TST_BUF_LEN       20000
#define TST_BUF_PART      4096
#define TST_ERROR     -1

int
main(int argc, char *argv[])
{

    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *iut_child = NULL;
    rpc_socket_domain       domain;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    const char             *func;
    enum tested_func        tested_func;
    const char             *method;
    
    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     child_s = -1;
    
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len = TST_BUF_LEN;

    int         rx_buf_len;
    uint64_t    total_filled = 0;
    uint64_t    all_received = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    domain = rpc_socket_domain_by_addr(iut_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_STRING_PARAM(method);

    tested_func = TESTED_FUNC(func);

    tx_buf = te_make_buf_by_len(buf_len);

    GEN_CONNECTION(pco_iut1, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Prepare receive buffer with length equal to SO_RCVBUF */
    rpc_getsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &rx_buf_len);
    RING("'tst_s' socket receive buffer length is %d", rx_buf_len);
    rx_buf = te_make_buf_by_len(rx_buf_len);

    /* Prepare conditions to block func */
    if ((tested_func == T_WRITE) || (tested_func == T_SEND))
    {
        rpc_overfill_buffers(pco_iut1, iut_s, &total_filled);
        RING("To overfill the both send and received buffers "
             "%d bytes are written", (unsigned int)total_filled);
    }

    TST_CALL_FUNC(pco_iut1, iut_s, tested_func, TST_BUF_PART);

    rpc_create_child_process_socket(method, pco_iut2, iut_s, domain,
                                    RPC_SOCK_STREAM, &iut_child, &child_s);

    CHECK_RC(rcf_rpc_server_exec(iut_child));

    TST_CALL_FUNC(iut_child, child_s, tested_func, TST_BUF_PART);

    /* Prepare conditions to unblock func */
    if ((tested_func == T_READ) || (tested_func == T_RECV))
    {
        rpc_send(pco_tst, tst_s, tx_buf, TST_BUF_LEN, RPC_MSG_DONTWAIT);
    }
    else
    {
        int         received;

        while (all_received <= total_filled / 2)
        {
            rpc_ioctl(pco_tst, tst_s, RPC_FIONREAD, &received);
            RING("%d bytes are ready to be read", received);
            if (received > rx_buf_len)
            {
                rc = rpc_read(pco_tst, tst_s, rx_buf, rx_buf_len);
            }
            else
                rc = rpc_read(pco_tst, tst_s, rx_buf, received);
            all_received += rc;
        }
    }

    TST_WAIT_FUNC(pco_iut1, iut_s, tested_func, TST_BUF_PART);
    TST_WAIT_FUNC(iut_child, child_s, tested_func, TST_BUF_PART);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);

    if (iut_child)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(iut_child));

    free(rx_buf);
    free(tx_buf);

    TEST_END;
}
