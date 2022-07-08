/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 */

/** @page level5-interop-onload_msg_recv_os_inline Check that ONLOAD_MSG_RECV_OS_INLINE flag works
 *
 * @objective Check that setting @c ONLOAD_MSG_RECV_OS_INLINE flag
 *            allows to receive kernel traffic via @b onload_zc_recv(),
 *            and not setting it disables this option.
 *
 * @type interop
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_two_nets_iut_first
 * @param os_inline         Whether to set @c ONLOAD_MSG_RECV_OS_INLINE
 *                          flag or not
 * @param kernel_traffic    Whether there should be traffic via kernel or
 *                          not
 * @param release_zc_bufs   If @c TRUE, in ZC callback return
 *                          @c ONLOAD_ZC_KEEP and release buffers after
 *                          onload_zc_recv() call with
 *                          onload_zc_release_buffers().
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/onload_msg_recv_os_inline"

#include "sockapi-test.h"

#define BUF_LEN 512

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;

    const struct sockaddr *iut_addr2 = NULL;
    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *tst2_addr = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    const struct sockaddr *conn_addr = NULL;
    struct sockaddr        bind_addr;
    te_bool                os_inline = FALSE;
    te_bool                kernel_traffic = FALSE;
    te_bool                release_zc_bufs = FALSE;

    char               *iut_buf = NULL;
    char               *tst_buf = NULL;
    struct rpc_iovec    vector;

    struct rpc_onload_zc_mmsg mmsg = { .saved_recv_bufs = RPC_NULL };
    te_bool recv_check_passed = FALSE;
    te_bool msg_received = TRUE;

    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_BOOL_PARAM(os_inline);
    TEST_GET_BOOL_PARAM(kernel_traffic);
    TEST_GET_BOOL_PARAM(release_zc_bufs);

    TEST_STEP("If @p kernel_traffic is @c TRUE, set @b pco_tst to "
              "@b pco_tst2, @b tst_addr to @p tst2_addr and @b conn_addr "
              "to @p iut_addr2. Otherwise set @b pco_tst to @p pco_tst1, "
              "@b tst_addr to @p tst1_addr and @p conn_addr to "
              "@p iut_addr1.");

    if (kernel_traffic)
    {
        memcpy(&bind_addr, iut_addr2, sizeof(bind_addr));
        pco_tst = pco_tst2;
        tst_addr = tst2_addr;
        conn_addr = iut_addr2;
    }
    else
    {
        memcpy(&bind_addr, iut_addr1, sizeof(bind_addr));
        pco_tst = pco_tst1;
        tst_addr = tst1_addr;
        conn_addr = iut_addr1;
    }

    iut_buf = te_make_buf_by_len(BUF_LEN);
    tst_buf = te_make_buf_by_len(BUF_LEN);

    TEST_STEP("Create UDP socket @b iut_s on IUT.");

    iut_s = rpc_socket(pco_iut,
                       rpc_socket_domain_by_addr(iut_addr2),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind it to wildcard address with the same port as in "
              "@p iut_addr2 if @p kernel_traffic is @c TRUE or as in "
              "@p iut_addr1 otherwise.");

    SIN(&bind_addr)->sin_addr.s_addr = htonl(INADDR_ANY);
    rpc_bind(pco_iut, iut_s, &bind_addr);

    TEST_STEP("Create UDP socket @b tst_s on @b pco_tst, @b connect() "
              "it to @b conn_addr.");
    tst_s = rpc_socket(pco_tst,
                       rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, conn_addr);

    vector.iov_base = iut_buf;
    vector.iov_len = vector.iov_rlen = BUF_LEN;

    memset(&mmsg, 0, sizeof(mmsg));
    mmsg.msg.msg_iov = &vector;
    mmsg.msg.msg_iovlen = mmsg.msg.msg_riovlen = 1;

    mmsg.keep_recv_bufs = release_zc_bufs;

    TEST_STEP("Send some data from @b tst_s.");
    rpc_send(pco_tst, tst_s, tst_buf, BUF_LEN, 0);

    TEST_STEP("Receive the data on @b iut_s with @b onload_zc_recv(), "
              "setting or not setting @c ONLOAD_MSG_RECV_OS_INLINE flag "
              "according to @p os_inline.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_simple_zc_recv_gen(pco_iut, iut_s, &mmsg, 1, NULL, 0, NULL,
                                os_inline);
    if (rc == 0 || rc > 1)
        TEST_VERDICT("onload_zc_recv() returned unexpected value");
    else if (rc == 1)
        rc = mmsg.rc;

    TEST_STEP("Check that data is not received in case when @p os_inline "
              "is @c FALSE and @p kernel_traffic is @c TRUE, and is "
              "received correctly in all other cases.");
    if (rc == 0)
    {
        ERROR_VERDICT("onload_zc_recv() returned a message with zero "
                      "bytes");
    }
    else if (!os_inline && kernel_traffic)
    {
        if (rc > 0)
        {
            ERROR_VERDICT("onload_zc_recv() succeed however "
                          "ONLOAD_MSG_RECV_OS_INLINE flag was not set "
                          "and traffic was via kernel");
        }
        else if (RPC_ERRNO(pco_iut) != RPC_ENOTEMPTY)
        {
            ERROR_VERDICT("onload_zc_recv() returned unexpected error "
                          RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
            msg_received = FALSE;
        }
        else
        {
            recv_check_passed = TRUE;
            msg_received = FALSE;
        }
    }
    else
    {
        if (rc < 0)
        {
            ERROR_VERDICT("onload_zc_recv() unexpectedly failed "
                          "with error " RPC_ERROR_FMT,
                          RPC_ERROR_ARGS(pco_iut));
            msg_received = FALSE;
        }
        else if (rc != BUF_LEN ||
                 memcmp(iut_buf, tst_buf, BUF_LEN) != 0)
        {
            ERROR_VERDICT("Received data check failed");
        }
        else
        {
            recv_check_passed = TRUE;
        }
    }

    if (release_zc_bufs && msg_received && mmsg.msg.msg_iovlen > 0)
    {
        TEST_STEP("If some message was received and @p release_zc_bufs is "
                  "@c TRUE, release ZC buffers calling "
                  "@b onload_zc_release_buffers().");

        if (mmsg.saved_recv_bufs == RPC_NULL)
            TEST_VERDICT("Pointer to received buffers was not returned");

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_free_onload_zc_buffers(pco_iut, iut_s,
                                        mmsg.saved_recv_bufs, 1);
        if (rc < 0)
        {
            TEST_VERDICT("onload_zc_release_buffers() failed with error "
                         RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
        }
    }

    if (!recv_check_passed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (mmsg.saved_recv_bufs != RPC_NULL)
        rpc_free(pco_iut, mmsg.saved_recv_bufs);

    free(iut_buf);
    free(tst_buf);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
