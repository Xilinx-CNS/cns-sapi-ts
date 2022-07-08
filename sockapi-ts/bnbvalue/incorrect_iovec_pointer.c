/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page bnbvalue-incorrect_iovec_pointer Behavior of recvmsg()/readv()/writev()/sendmsg()/template_send() functions if NULL passed as a pointer to the iovec structures
 *
 * @objective Check that @b recvmsg(), @b recvmmsg(), @b readv(),
 *            @b writev(), @b sendmsg(), @b sendmmsg() or @b template_send
 *            functions correctly process @c NULL as a pointer to @c struct
 *            @c iovec and value of the @c iov_len.
 *
 * @type conformance
 *
 * @param env           Test environment
 *                       - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param func          Tested function:
 *                      - @b readv
 *                      - @b recvmsg
 *                      - @b recvmmsg
 *                      - @b writev
 *                      - @b sendmsg
 *                      - @b sendmmsg
 *                      - @b template_send
 * @param vector        @c TRUE if vector passed to the @p func is a
 *                      valid value; @c FALSE if @c NULL should be used as
 *                      a vector value;
 * @param veclen        @c TRUE if length of the vector is @c 1;
 *                      @c FALSE if vector length is @c 0.
 *                      (Only values @c 0 or @c 1 as vector length can
 *                       be used in this test).
 * @param sock_type     Type of tested socket. @c SOCK_STREAM or @c SOCK_DGRAM
 *
 *
 * @par Test sequence:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/incorrect_iovec_pointer"

#include "sockapi-test.h"

#define TST_BUF_LEN  300

#define CHECK_FUNCTION(func_name_, params_...) \
    do {                                                       \
        if (strcmp(func, #func_name_) == 0)                    \
        {                                                      \
            unknown_func = FALSE;                              \
            RPC_AWAIT_ERROR(pco_iut);                          \
            ret = rpc_ ## func_name_(pco_iut, iut_s, params_); \
        }                                                      \
    } while (0)

int
main(int argc, char *argv[])
{
    int                sent;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;
    rpc_socket_type    sock_type;
    te_bool            unknown_func = TRUE;
    const char        *func;
    te_bool            vector;
    te_bool            veclen;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    void                   *tx_buf = NULL;
    size_t                  rxbuf_len;
    size_t                  txbuf_len;
    void                   *rx_buf = NULL;

    struct rpc_iovec        rx_vector[1];
    struct rpc_iovec       *rx_vec = NULL;
    size_t                  iovec_len;
    struct rpc_mmsghdr      mmsghdr;
    rpc_msghdr             *rx_msghdr = &mmsghdr.msg_hdr;

    struct sockaddr_storage name;

    ssize_t ret = -1;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(vector);
    TEST_GET_BOOL_PARAM(veclen);
    TEST_GET_STRING_PARAM(func);

    if (strcmp(func, "template_send") == 0)
        sockts_kill_zombie_stacks(pco_iut);

    rxbuf_len = txbuf_len = TST_BUF_LEN;
    rx_buf = te_make_buf_by_len(rxbuf_len);
    tx_buf = te_make_buf_by_len(txbuf_len);

    if (strcmp(func, "onload_zc_send") == 0 ||
        strcmp(func, "onload_zc_send_user_buf") == 0)
    {
        TEST_VERDICT("onload_zc_send() checking is not supported");
    }

    /* all of the vector elements are the same buffer */
    rx_vector[0].iov_base = rx_buf;
    rx_vector[0].iov_len = rx_vector[0].iov_rlen = rxbuf_len;

    /* process test parameters */
    rx_vec = vector ? rx_vector : NULL;
    iovec_len = veclen ? 1 : 0;

    /* recvmsg() */
    memset(rx_msghdr, 0, sizeof(*rx_msghdr));
    rx_msghdr->msg_iovlen = rx_msghdr->msg_riovlen = iovec_len;
    rx_msghdr->msg_iov = rx_vec;
    if (rx_vec)
        rx_msghdr->msg_riovlen = 1;

    TEST_STEP("Create network connection of sockets of @p sock_type by means "
              "of @c GEN_CONNECTION, obtain sockets @b iut_s on @p pco_iut and "
              "@b tst_s on @p pco_tst.");
    GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("If @p func is function for sending:");
    TEST_SUBSTEP("Call @p func with data prepared according to @p vector and "
                 "@p veclen");
    CHECK_FUNCTION(writev, rx_vec, iovec_len);
    CHECK_FUNCTION(sendmsg, rx_msghdr, 0);
    if (strcmp(func, "template_send") == 0)
    {
        unknown_func = FALSE;
        RPC_AWAIT_ERROR(pco_iut);
        ret = rpc_template_send(pco_iut, iut_s, rx_vec, iovec_len,
                                rx_vec == NULL ? 0 : iovec_len, 0);
    }
    if (strcmp(func, "onload_zc_send") == 0)
    {
        unknown_func = FALSE;
        RPC_AWAIT_ERROR(pco_iut);
        ret = rpc_simple_zc_send(pco_iut, iut_s, rx_msghdr, 0);
    }
    if (strcmp(func, "sendmmsg") == 0)
    {
        unknown_func = FALSE;
        RPC_AWAIT_ERROR(pco_iut);
        ret = rpc_sendmmsg_as_sendmsg(pco_iut, iut_s, rx_msghdr, 0);
    }

    if (!unknown_func)
    {
        if (vector && veclen)
        {
            TEST_SUBSTEP("If @p vector and @p veclen are @c TRUE check that "
                         "the function returns number of sent bytes.");
            if (ret != (ssize_t)txbuf_len)
            {
                TEST_VERDICT("Function %s() returned %d. Errno is set to "
                             "%s", func, (int)ret,
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
        }
        else if (veclen &&
                 ((strcmp(func, "writev") == 0) ||
                  (strcmp(func, "sendmsg") == 0) ||
                  (strcmp(func, "sendmmsg") == 0) ||
                  (strcmp(func, "onload_zc_send") == 0) ||
                  (strcmp(func, "template_send") == 0)))
        {
            TEST_SUBSTEP("Otherwise, if function is @b sendmsg() or "
                         "@b sendmmsg() or @b onload_zc_send() or "
                         "@b template_send() or @b writev, @p vector is "
                         "@c FALSE and @p veclen is @c TRUE check that it "
                         "returns @c -1 and sets @b errno to @c EFAULT.");
            if (ret != -1)
            {
                TEST_VERDICT("Function %s() returned %d. Errno is set to "
                             "%s", func, (int)ret,
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
            CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                            "%s() function called on 'iut_s' returns -1, "
                            "but", func);
        }
        else
        {
            TEST_SUBSTEP("Otherwise check that @p func returns @c 0 without "
                         "any errors");
            if (ret != 0)
                TEST_VERDICT("Function %s() returned %d. Errno is set to "
                             "%s", func, (int)ret,
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
        }

        TEST_SUCCESS;
    }

    TEST_STEP("If @p func is for receiving do following steps:");

    TEST_SUBSTEP("Send data through @p tst_s.");
    RPC_WRITE(sent, pco_tst, tst_s, tx_buf, txbuf_len);

    memset(rx_msghdr, 0, sizeof(*rx_msghdr));
    rx_msghdr->msg_name = (struct sockaddr *)&name;
    rx_msghdr->msg_namelen = rx_msghdr->msg_rnamelen = sizeof(name);
    rx_msghdr->msg_iovlen = rx_msghdr->msg_riovlen = iovec_len;
    rx_msghdr->msg_iov = rx_vec;

    TEST_SUBSTEP("Call @p func function on @p iut_s.");
    CHECK_FUNCTION(readv, rx_vec, iovec_len);

    /* Do not do msg_flags auto check in recvmsg()-like calls because
     * @c MSG_TRUNC flag is set when a datagram is read incompletely. */
    if (sock_type == RPC_SOCK_DGRAM && veclen == FALSE)
        rx_msghdr->msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;

    CHECK_FUNCTION(recvmsg, rx_msghdr, 0);
    if (strcmp(func, "recvmmsg") == 0)
    {
        unknown_func = FALSE;
        RPC_AWAIT_ERROR(pco_iut);
        ret = rpc_recvmmsg_alt(pco_iut, iut_s, &mmsghdr, 1, 0, NULL);
    }
    if (ret != -1 && (strcmp(func, "recvmmsg") == 0))
        ret = mmsghdr.msg_len;
    if (strcmp(func, "onload_zc_recv") == 0)
        TEST_VERDICT("This test is not applicable for onload_zc_recv() "
                     "function");
    if (unknown_func)
        TEST_FAIL("Unknown 'func' parameter %s", func);

    if (vector && veclen)
    {
        TEST_SUBSTEP("Check that if @p vector and @p veclen are @c TRUE "
                     "function return number of received bytes.");
        if (ret != sent)
        {
            TEST_VERDICT("Function %s() returned %d. Errno is set to %s",
                         func, (int)ret, errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    if (veclen == FALSE)
    {
        TEST_SUBSTEP("Check that if @p veclen is @c FALSE function returns "
                     "@c 0");
        if (ret == -1)
        {
            TEST_VERDICT("%s() with zero vector length fails with "
                         "errno %s", func,
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        else if (ret != 0)
        {
            TEST_VERDICT("%s() with zero vector length passes unexpectedly",
                         func);
        }

        TEST_SUBSTEP("Check that if @p func is not @b readv(), @p veclen is "
                     "@c FALSE and @p sock_type is @c SOCK_DGRAM it returns "
                     "with flag @c MSG_TRUNC.");
        if (sock_type == RPC_SOCK_DGRAM && strcmp(func, "readv") != 0 &&
            rx_msghdr->msg_flags != RPC_MSG_TRUNC)
            TEST_VERDICT("Flag MSG_TRUNC should be set by recvmsg()-like "
                         "call");
    }

    if (veclen == TRUE && vector == FALSE)
    {
        if (strcmp(func, "recvmsg") == 0 ||
            strcmp(func, "recvmmsg") == 0 ||
            strcmp(func, "readv") == 0)
        {
            TEST_SUBSTEP("Check that if @p func is @b recvmsg() or "
                         "@b recvmmsg() or @b readv, @p veclen is @c TRUE and "
                         "@p vector is @c FALSE it returns @c -1 and sets "
                         "@b errno to @c EFAULT.");
            if (ret != -1)
            {
                TEST_VERDICT("Function %s() returned %d. Errno is set to %s",
                             func, (int)ret, errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
            CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT,
                            "%s() function called on 'iut_s' returns -1, but",
                            func);
        }
        else
        {
            TEST_SUBSTEP("Check that if @p func is @b onload_zc_recv(), "
                         "@p veclen is @c TRUE and @p vector is @c FALSE "
                         "it returns @c 0 without any errors.");
            if (ret != 0)
            {
                TEST_VERDICT("Function %s() returned %d. Errno is set to %s",
                             func, (int)ret, errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
