/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/** @page extension-zc_recv_oob Receiving OOB data with onload_zc_recv()
 *
 * @objective Check what happens when OOB data arrives and
 *            @b onload_zc_recv() is used to receive data.
 *
 * @type use case
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_ipv6
 *                      - @ref arg_types_env_peer2peer_lo
 *                      - @ref arg_types_env_peer2peer_lo_ipv6
 * @param os_inline     If @c TRUE, pass @c ONLOAD_MSG_RECV_OS_INLINE
 *                      flag to @b onload_zc_recv().
 * @param oob_inline    If @c TRUE, enable @c SO_OOBINLINE socket option
 *                      on IUT socket.
 * @param unblock_zc    If @c TRUE, @b onload_zc_recv() should block waiting
 *                      for data when OOB data arrives.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/zc_recv_oob"

#include "sockapi-test.h"
#include "onload.h"

#include "te_dbuf.h"

/** Number of messages expected from onload_zc_recv() */
#define MSGS_NUM 3

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut;
    rcf_rpc_server *pco_tst;

    int iut_s = -1;
    int tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    char send_buf1[SOCKTS_MSG_STREAM_MAX];
    size_t send_len1;
    char oob_byte;
    char send_buf2[SOCKTS_MSG_STREAM_MAX];
    size_t send_len2;

    char recv_bufs[MSGS_NUM][SOCKTS_MSG_STREAM_MAX];
    rpc_iovec iovs[MSGS_NUM];
    rpc_msghdr *msg;
    struct rpc_mmsghdr mmsgs[MSGS_NUM];
    int i;

    te_bool oob_inline;
    te_bool os_inline;
    te_bool unblock_zc;

    te_dbuf dbuf1 = TE_DBUF_INIT(0);
    te_dbuf dbuf2 = TE_DBUF_INIT(0);
    te_dbuf dbuf_recv = TE_DBUF_INIT(0);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(os_inline);
    TEST_GET_BOOL_PARAM(oob_inline);
    TEST_GET_BOOL_PARAM(unblock_zc);

    TEST_STEP("Establish TCP connection between IUT and Tester sockets.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("If @p oob_inline is @c TRUE, enable @c SO_OOBINLINE option "
              "on the IUT socket.");
    if (oob_inline)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_OOBINLINE, 1);

    TEST_STEP("Enable @c TCP_NODELAY option on the Tester socket to ensure "
              "that packets are sent immediately.");
    rpc_setsockopt_int(pco_tst, tst_s, RPC_TCP_NODELAY, 1);

    memset(&mmsgs, 0, sizeof(mmsgs));
    for (i = 0; i < MSGS_NUM; i++)
    {
        iovs[i].iov_base = recv_bufs[i];
        iovs[i].iov_len = iovs[i].iov_rlen = SOCKTS_MSG_STREAM_MAX;

        msg = &mmsgs[i].msg_hdr;
        msg->msg_iov = &iovs[i];
        msg->msg_iovlen = msg->msg_riovlen = 1;
    }

    if (unblock_zc)
    {
        TEST_STEP("If @b unblock_zc is @c TRUE, call @b onload_zc_recv() "
                  "with @c RCF_RPC_CALL.");
        pco_iut->op = RCF_RPC_CALL;
        rpc_simple_zc_recv_gen_mmsg(pco_iut, iut_s, mmsgs, MSGS_NUM,
                                    NULL, 0, NULL, os_inline);
        send_len1 = 0;
    }
    else
    {
        TEST_STEP("If @b unblock_zc is @c FALSE, send a normal "
                  "packet from the Tester socket.");
        send_len1 = rand_range(1, sizeof(send_buf1));
        te_fill_buf(send_buf1, send_len1);
        RPC_SEND(rc, pco_tst, tst_s, send_buf1, send_len1, 0);
    }

    TEST_STEP("Send OOB byte from the Tester socket.");
    oob_byte = rand_range(0, 255);
    RPC_SEND(rc, pco_tst, tst_s, &oob_byte, 1, RPC_MSG_OOB);

    TEST_STEP("Send a normal packet from the Tester socket.");
    send_len2 = rand_range(1, sizeof(send_buf2));
    te_fill_buf(send_buf2, send_len2);
    RPC_SEND(rc, pco_tst, tst_s, send_buf2, send_len2, 0);

    TEST_STEP("Wait for a while to ensure that all the data sent "
              "arrived on IUT.");
    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @b onload_zc_recv() (or wait for its termination if "
              "it was called before with @c RCF_RPC_CALL). Check that it "
              "succeeds.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_simple_zc_recv_gen_mmsg(pco_iut, iut_s, mmsgs, MSGS_NUM,
                                     NULL, 0, NULL, os_inline);
    if (rc < 0)
    {
        TEST_VERDICT("onload_zc_recv() called without MSG_OOB flag failed "
                     "with error " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc == 0)
    {
        TEST_VERDICT("onload_zc_recv() called without MSG_OOB flag "
                     "returned zero messages");
    }

    TEST_STEP("Check that only normal data sent from Tester was returned "
              "if @b oob_inline is @c FALSE. Check that OOB byte was "
              "returned together with normal data if @b oob_inline is "
              "@c TRUE.");

    /* dbuf_recv contains data received with onload_zc_recv() */
    for (i = 0; i < rc; i++)
    {
        CHECK_RC(te_dbuf_append(&dbuf_recv, recv_bufs[i], mmsgs[i].msg_len));
    }

    /* dbuf1 contains data without OOB byte */
    CHECK_RC(te_dbuf_append(&dbuf1, send_buf1, send_len1));
    CHECK_RC(te_dbuf_append(&dbuf1, send_buf2, send_len2));

    /* dbuf2 contains data with OOB byte */
    CHECK_RC(te_dbuf_append(&dbuf2, send_buf1, send_len1));
    CHECK_RC(te_dbuf_append(&dbuf2, &oob_byte, 1));
    CHECK_RC(te_dbuf_append(&dbuf2, send_buf2, send_len2));

    if (dbuf_recv.len == dbuf1.len &&
        memcmp(dbuf_recv.ptr, dbuf1.ptr, dbuf_recv.len) == 0)
    {
        if (oob_inline)
        {
            TEST_VERDICT("onload_zc_recv() retrieved only normal data "
                         "when SO_OOBINLINE was set");
        }
    }
    else if (dbuf_recv.len == dbuf2.len &&
             memcmp(dbuf_recv.ptr, dbuf2.ptr, dbuf2.len) == 0)
    {
        if (!oob_inline)
        {
            TEST_VERDICT("onload_zc_recv() retrieved OOB byte together "
                         "with normal data when SO_OOBINLINE was not set");
        }
    }
    else if (dbuf_recv.len == 1 &&
             *(char *)(dbuf_recv.ptr) == oob_byte)
    {
        /*
         * onload_zc_recv() may terminate after retrieving the single
         * OOB byte if SO_OOBINLINE is enabled and onload_zc_recv()
         * is hanging waiting for data.
         */
        if (!(oob_inline && unblock_zc))
        {
            TEST_VERDICT("onload_zc_recv() returned only OOB byte when "
                         "called without MSG_OOB flag");
        }
    }
    else
    {
        TEST_VERDICT("onload_zc_recv() returned unknown data");
    }

    TEST_STEP("Call @b onload_zc_recv() with @c MSG_OOB flag, check that "
              "it fails with @c EINVAL.");

    for (i = 0; i < MSGS_NUM; i++)
    {
        iovs[i].iov_len = iovs[i].iov_rlen = SOCKTS_MSG_STREAM_MAX;
    }

    /*
     * MSG_OOB is not supported in onload_zc_recv() after fixing bug
     * ON-11712.
     */
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_simple_zc_recv_gen_mmsg(pco_iut, iut_s, mmsgs, MSGS_NUM,
                                     NULL, RPC_MSG_OOB, NULL, os_inline);
    if (rc >= 0)
    {
        TEST_VERDICT("onload_zc_recv() succeeded with MSG_OOB flag");
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
    {
        RING_VERDICT("onload_zc_recv() called with MSG_OOB flag failed "
                     "with unexpected error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    te_dbuf_free(&dbuf1);
    te_dbuf_free(&dbuf2);
    te_dbuf_free(&dbuf_recv);

    TEST_END;
}
