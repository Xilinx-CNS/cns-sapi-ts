/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 */

/** @page ioctls-fionbio Usage of FIONBIO or NONBLOCK request with receive functions
 *
 * @objective Check that @c FIONBIO /@c O_NONBLOCK request affects
 *            the behaviour of receive functions.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type     Socket type:
 *                      - @c SOCK_STREAM
 *                      - @c SOCK_DGRAM
 * @param func          Function used in the test:
 *                      - @b read()
 *                      - @b readv()
 *                      - @b recv()
 *                      - @b recvfrom()
 *                      - @b recvmsg()
 *                      - @b recvmmsg()
 *                      - @b onload_zc_recv()
 *                      - @b onload_zc_hlrx_recv_zc()
 *                      - @b onload_zc_hlrx_recv_copy()
 * @param nonblock_func Function used to set nonblocking state to socket
 *                      ("fcntl", "ioctl")
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionbio"

#include "sockapi-test.h"

typedef enum test_rx_mode {
    RX_BLK,
    RX_NBLK
} test_rx_mode;

static void check_rx_func_mode(const char *func,
                               rcf_rpc_server *pco_iut, int iut_s,
                               rcf_rpc_server *pco_tst, int tst_s,
                               test_rx_mode rx_mode,
                               const char *err_msg);

int
main(int argc, char *argv[])
{
    rpc_socket_type    sock_type;
    const char        *func;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                srv_s = -1;
    int                iut_s = -1;
    int                tst_s = -1;

    struct sockaddr_storage  peer_addr;
    socklen_t                peer_addrlen = sizeof(peer_addr);
    const struct sockaddr   *iut_addr;
    const struct sockaddr   *tst_addr;

    fdflag_set_func_type_t nonblock_func = UNKNOWN_SET_FDFLAG;

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_FDFLAG_SET_FUNC(nonblock_func);

    TEST_STEP("Create a pair of connected sockets on IUT and Tester "
              "of type @p sock_type.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        srv_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

        TEST_SUBSTEP("If @p sock_type is @c SOCK_STREAM, set nonblocking state "
                     "for the listener socket on IUT before establishing "
                     "connection to check that it is not inherited.");
        set_sock_non_block(pco_iut, srv_s, nonblock_func == FCNTL_SET_FDFLAG,
                           pco_iut->use_libc, TRUE);


        /* Create a connection */
        rpc_bind(pco_iut, srv_s, iut_addr);
        rpc_listen(pco_iut, srv_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_tst, tst_s, iut_addr);

        /* To become more confident that client is connected */
        TAPI_WAIT_NETWORK;
        iut_s = rpc_accept(pco_iut, srv_s, SA(&peer_addr), &peer_addrlen);
    }
    else if (sock_type == RPC_SOCK_DGRAM)
    {
        GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                            iut_addr, tst_addr, &iut_s, &tst_s, TRUE);
    }
    else
    {
        TEST_FAIL("The test does not support 'sock_type' parameter "
                  "other than SOCK_STREAM or SOCK_DGRAM");
    }

    TEST_STEP("Call @p func on IUT with @c RCF_RPC_CALL, wait for a "
              "while, send data from Tester to unblock it if it was "
              "blocked. Finish @p func call and check that it "
              "successfully returned sent data, not failed prematurely "
              "with @c EAGAIN.");
    check_rx_func_mode(func, pco_iut, iut_s, pco_tst, tst_s, RX_BLK,
                       "Checking before nonblocking state is enabled");

    TEST_STEP("Enable nonblocking state on the IUT socket.");
    set_sock_non_block(pco_iut, iut_s, nonblock_func == FCNTL_SET_FDFLAG,
                       pco_iut->use_libc, TRUE);

    TEST_STEP("Again call @p func on IUT with @c RCF_RPC_CALL, wait for "
              "a while, send data from Tester to unblock it if it was "
              "blocked. Finish @p func call and check that this time it "
              "failed with @c EAGAIN. Then read data from the IUT "
              "socket to clean its receive buffer.");
    check_rx_func_mode(func, pco_iut, iut_s, pco_tst, tst_s, RX_NBLK,
                       "Checking after nonblocking state is enabled");

    TEST_STEP("Disable nonblocking state on the IUT socket.");
    set_sock_non_block(pco_iut, iut_s, nonblock_func == FCNTL_SET_FDFLAG,
                       pco_iut->use_libc, FALSE);

    TEST_STEP("Again call @p func on IUT with @c RCF_RPC_CALL, wait for "
              "a while, send data from Tester to unblock it if it was "
              "blocked. Finish @p func call and check that it "
              "successfully returned sent data.");
    check_rx_func_mode(func, pco_iut, iut_s, pco_tst, tst_s, RX_BLK,
                       "Checking after nonblocking state is disabled");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, srv_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

static void
check_rx_func_mode(const char *func, rcf_rpc_server *pco_iut, int iut_s,
                   rcf_rpc_server *pco_tst, int tst_s, test_rx_mode rx_mode,
                   const char *err_msg)
{
    unsigned int duration = 1;
    int          rc;

    struct sockaddr_storage  peer_addr;
    socklen_t                peer_addrlen = sizeof(peer_addr);

#define BUF_LEN 1
    unsigned char    tx_buf[BUF_LEN];
    size_t           tx_buf_len = sizeof(tx_buf);
    unsigned char    rx_buf[BUF_LEN];
    size_t           rx_buf_len = sizeof(rx_buf);
    struct rpc_iovec iov = { .iov_base = rx_buf,
                             .iov_len = rx_buf_len,
                             .iov_rlen = rx_buf_len };
    struct rpc_mmsghdr mmsg = {
        {
            .msg_name = &peer_addr,
            .msg_namelen = peer_addrlen,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
            .msg_rnamelen = peer_addrlen,
            .msg_riovlen = 1,
            .msg_cmsghdr_num = 0,
            .msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK
        },
        .msg_len = 0
    };
    rpc_msghdr        *msg = &mmsg.msg_hdr;

#define CHECK_FUNCTION(func_name_, params_...) \
    do {                                                                \
        pco_iut->op = RCF_RPC_CALL;                                     \
        rpc_ ## func_name_(pco_iut, params_);                           \
        SLEEP(duration);                                                \
                                                                        \
        RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);            \
                                                                        \
        pco_iut->op = RCF_RPC_WAIT;                                     \
        RPC_AWAIT_ERROR(pco_iut);                                       \
        rc = rpc_ ## func_name_(pco_iut, params_);                      \
                                                                        \
        if (rx_mode == RX_BLK)                                          \
        {                                                               \
            if (rc < 0)                                                 \
            {                                                           \
                TEST_VERDICT("%s: tested function unexpectedly "        \
                             "failed with error " RPC_ERROR_FMT,        \
                             err_msg, RPC_ERROR_ARGS(pco_iut));         \
            }                                                           \
            else if (rc != (int)tx_buf_len)                             \
            {                                                           \
                TEST_VERDICT("%s: tested function returned unexpected " \
                             "number of bytes", err_msg);               \
            }                                                           \
            if (pco_iut->duration <                                     \
                ((duration * 1000000) - TST_TIME_INACCURACY))           \
            {                                                           \
                TEST_VERDICT("%s: tested function returned earlier "    \
                             "than expected", err_msg);                 \
            }                                                           \
        }                                                               \
        else                                                            \
        {                                                               \
            if (rc >= 0)                                                \
            {                                                           \
                TEST_VERDICT("%s: tested function succeeded instead "   \
                             "of failing with EAGAIN", err_msg);        \
            }                                                           \
            else if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)                  \
            {                                                           \
                TEST_VERDICT("%s: tested function failed with "         \
                             "unexpected error " RPC_ERROR_FMT,         \
                             err_msg, RPC_ERROR_ARGS(pco_iut));         \
            }                                                           \
                                                                        \
            /*                                                          \
             * Socket contains not read data received after             \
             * returning from rx function, so just clear RX buffer      \
             * reading them                                             \
             */                                                         \
            TAPI_WAIT_NETWORK;                                          \
            rc = rpc_ ## func_name_(pco_iut, params_);                  \
            if (rc != -1 && strcmp(#func_name_, "recvmmsg_alt") == 0)   \
                rc = mmsg.msg_len;                                      \
            if (rc < 0)                                                 \
            {                                                           \
                TEST_VERDICT("%s: failed to read received data, "       \
                             "error " RPC_ERROR_FMT, err_msg,           \
                             RPC_ERROR_ARGS(pco_iut));                  \
            }                                                           \
            else if (rc != (int)tx_buf_len)                             \
            {                                                           \
                TEST_VERDICT("%s: unexpected value obtained when "      \
                             "trying to read received data from "       \
                             "socket", err_msg);                        \
            }                                                           \
        }                                                               \
                                                                        \
        if (rc == (int)tx_buf_len &&                                    \
            memcmp(tx_buf, rx_buf, rc) != 0)                            \
        {                                                               \
            TEST_VERDICT("%s: unexpected data was received", err_msg);  \
        }                                                               \
    } while (0)

    te_fill_buf(tx_buf, sizeof(tx_buf));

    if (strcmp(func, "read") == 0)
    {
        CHECK_FUNCTION(read, iut_s, rx_buf, rx_buf_len);
    }
    else if (strcmp(func, "recv") == 0)
    {
        CHECK_FUNCTION(recv, iut_s, rx_buf, rx_buf_len, 0);
    }
    else if (strcmp(func, "recvfrom") == 0)
    {
        CHECK_FUNCTION(recvfrom, iut_s, rx_buf, rx_buf_len, 0,
                       SA(&peer_addr), &peer_addrlen);
    }
    else if (strcmp(func, "recvmsg") == 0)
    {
        CHECK_FUNCTION(recvmsg, iut_s, msg, 0);
    }
    else if (strcmp(func, "recvmmsg") == 0)
    {
        CHECK_FUNCTION(recvmmsg_alt, iut_s, &mmsg, 1, 0, NULL);
    }
    else if (strcmp(func, "onload_zc_recv") == 0)
    {
        CHECK_FUNCTION(simple_zc_recv, iut_s, msg, 0);
    }
    else if (strcmp(func, "onload_zc_hlrx_recv_zc") == 0)
    {
        CHECK_FUNCTION(simple_hlrx_recv_zc, iut_s, msg, 0, TRUE);
    }
    else if (strcmp(func, "onload_zc_hlrx_recv_copy") == 0)
    {
        CHECK_FUNCTION(simple_hlrx_recv_copy, iut_s, msg, 0, TRUE);
    }
    else if (strcmp(func, "readv") == 0)
    {
        CHECK_FUNCTION(readv, iut_s, &iov, 1);
    }
    else
    {
        TEST_FAIL("Function '%s' is not supported", func);
    }
}
