/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 *
 * $Id$
 */

/** @page sendrecv-recvmmsg The recvmmsg() operations on the SOCK_DGRAM socket

 *
 * @objective Test on reliability of @b recvmmsg() operation on BSD
 *            compatible sockets.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param iut_addr      Network address on IUT
 * @param tst_addr      Network address on Tester
 * @param delay         Delay between sendings
 * @param data_size     Size of data to be send in each packet
 * @param pack_num      Number of packets to send
 * @param timeout       Timeout for @b recvmmsg() function
 * @param vlen          @p vlen parameter for @b recvmmsg()
 * @param waitforone    Whether to set @c MSG_WAITFORONE flag when
 *                      calling the function under test or not
 * @param use_zc        Whether to use @b onload_zc_recv() instead
 *                      of @b recvmmsg() or not
 *
 * @par Scenario:
 *
 * -# Allocate @p vlen number of following structures on @p IUT side:
 *    - @a msghdr;
 *    - @a scatter/gather array.
 * -# Create @p pco_iut socket of the @c SOCK_DGRAM type on the @p IUT side.
 * -# Create @p pco_tst socket of the @c SOCK_DGRAM type on the
 *    @p TESTER side.
 * -# @b bind() @p pco_iut socket to the local address/port.
 * -# @b bind() @p pco_tst socket to the local address/port.
 * -# Call @b recvmmsg() on the @p pco_iut socket with @b timeout and
 *    @p vlen.
 * -# Send @p pack_num packets of @p data_size from @p pco_tst to @p pco_iut
 *    with @p delay.
 * -# Check that @b recvmmsg() returned appropriate number of packets
 *    according to @p timeout and @p delay parameters.
 * -# Compare transmitted and received data.
 * -# Read all data from the socket on @p pco_iut.
 * -# Send @p pack_num packets of @p data_size from @p pco_tst to
 *    @p pco_iut.
 * -# Call @b recvmmsg() and check that it returned appropriate number of
 *    packets according to @p timeout and @p delay parameters.
 * -# Compare transmitted and received data.
 * -# Close created sockets;
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recvmmsg"

#include "sockapi-test.h"
#include "extensions_zc.h"

#define MIN_BUF_LEN 256
#define MAX_BUF_LEN 1024
#define MAX_IOV_LEN 16

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    struct rpc_mmsghdr mmsghdr[RCF_RPC_MAX_MSGHDR];
    rpc_msghdr        *msghdr;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    memset(mmsghdr, 0, sizeof(mmsghdr));

    struct tarpc_timespec     to;

    int delay;
    int data_size;
    int pack_num;
    int timeout;
    int vlen;
    int flags;

    te_bool waitforone;
    te_bool use_zc;

    ssize_t buf_len[RCF_RPC_MAX_MSGHDR];
    int     iov_len[RCF_RPC_MAX_MSGHDR];
    size_t  tmp;

    char        *buffers[RCF_RPC_MAX_MSGHDR];
    char         rx_buf[MAX_BUF_LEN];
    int          i;
    te_bool      readable = FALSE;
    int          get_pack = 0;
    int          rem_pack = 0;
    unsigned int tmp_pack = 0;
    te_bool      done = FALSE;
    te_bool      failed = FALSE;

    int          last_pkt_num;

    struct rpc_iovec tmp_v;

    int cb_flags[RCF_RPC_MAX_MSGHDR];

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(delay);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(pack_num);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_INT_PARAM(vlen);
    TEST_GET_BOOL_PARAM(waitforone);
    TEST_GET_BOOL_PARAM(use_zc);

    flags = (waitforone) ? RPC_MSG_WAITFORONE : 0;
    memset(cb_flags, 0, sizeof(cb_flags));
    memset(buffers, 0, sizeof(buffers));

    for (i = 0; i < pack_num; i++)
    {
        buffers[i] = te_make_buf_by_len(MAX_BUF_LEN);
        te_fill_buf(buffers[i], MAX_BUF_LEN);
    }

    /* Prepare mmsghdr */
    for (i = 0; i < vlen; i++)
    {
        msghdr = &mmsghdr[i].msg_hdr;

        msghdr->msg_namelen = sizeof(struct sockaddr_storage);
        CHECK_NOT_NULL(msghdr->msg_name =
                        te_make_buf_min(msghdr->msg_namelen, &tmp));
        msghdr->msg_rnamelen = tmp;

        if (use_zc)
        {
            iov_len[i] = 1;
            buf_len[i] = rand_range(data_size, MAX_BUF_LEN);
        }
        else
        {
            iov_len[i] = rand_range(1, MAX_IOV_LEN);
            buf_len[i] = rand_range(data_size, MAX_BUF_LEN);
        }
        msghdr->msg_iov = sockts_make_iovec(&iov_len[i], &buf_len[i]);
        msghdr->msg_iovlen = msghdr->msg_riovlen = iov_len[i];

        msghdr->msg_controllen = 0;
        msghdr->msg_control = NULL;
    }

    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM,
                        RPC_IPPROTO_UDP, iut_addr, tst_addr,
                        &iut_s, &tst_s, TRUE);

    to.tv_sec = timeout;
    to.tv_nsec = 0;

    if (!use_zc)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, vlen, flags, &to);
        TAPI_WAIT_NETWORK;

        for (i = 0; i < pack_num; i++)
        {
            RPC_WRITE(rc, pco_tst, tst_s, buffers[i], data_size);
            SLEEP(delay);
        }

        pco_iut->op = RCF_RPC_WAIT;
        get_pack = rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, vlen, flags, &to);

        if (waitforone && get_pack != 1)
            TEST_VERDICT("recvmmsg() get %d packets instead of 1 packets.",
                         get_pack);
        else if (!waitforone && get_pack != timeout / delay + 1)
            RING_VERDICT("recvmmsg() get %d packets instead of %d packets.",
                         get_pack, timeout / delay + 1);
        for (i = 0; i < get_pack; i++)
        {
            msghdr = &mmsghdr[i].msg_hdr;
            tmp_pack = MIN(buf_len[i], data_size);
            if (mmsghdr[i].msg_len != tmp_pack)
                TEST_VERDICT("msg_len for #%d message is %d but buffer "
                             "length is %d and message length is %d", i,
                             mmsghdr[i].msg_len, buf_len[i], data_size);
            tmp_v.iov_base = buffers[i];
            tmp_v.iov_len = tmp_v.iov_rlen = tmp_pack;
            if (rpc_iovec_cmp(tmp_pack, &tmp_v, 1, tmp_pack, msghdr->msg_iov,
                              msghdr->msg_iovlen) != 0)
                TEST_VERDICT("Data in #%s packet is incorrect", i);
        }

        RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
        while(readable)
        {
            rpc_read(pco_iut, iut_s, rx_buf, data_size);
            rem_pack++;
            RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
        }

        if (rem_pack != pack_num - get_pack)
            TEST_FAIL("There are %d remaining packets on the socket but %d "
                      "packets was sent and %d packets was recieved by "
                      "recvmmsg()", rem_pack, pack_num, get_pack);

        rem_pack = 0;
    }

    RPC_WRITE(rc, pco_tst, tst_s, buffers[0], data_size);
    RPC_GET_READABILITY(readable, pco_iut, iut_s, 1000);
    if (readable)
        rpc_read(pco_iut, iut_s, rx_buf, data_size);
    TAPI_WAIT_NETWORK;

    for (i = 0; i < pack_num; i++)
        RPC_WRITE(rc, pco_tst, tst_s, buffers[i], data_size);
    TAPI_WAIT_NETWORK;

    if (use_zc)
    {
        get_pack = rpc_simple_zc_recv_gen_mmsg(
                                          pco_iut, iut_s, mmsghdr, vlen,
                                          NULL, flags, cb_flags, TRUE);
    }
    else
    {
        get_pack = rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr,
                                    vlen, flags, &to);
    }

    if (get_pack != vlen)
        TEST_VERDICT("recvmmsg() get %d packets instead of %d packets.",
                     get_pack, vlen);
    for (i = 0; i < get_pack; i++)
    {
        msghdr = &mmsghdr[i].msg_hdr;
        tmp_pack = MIN(buf_len[i], data_size);
        if (mmsghdr[i].msg_len != tmp_pack)
            TEST_VERDICT("msg_len for #%d message is %d but buffer "
                         "length is %d and message length is %d", i,
                         mmsghdr[i].msg_len, buf_len[i], data_size);
        tmp_v.iov_base = buffers[i];
        tmp_v.iov_len = tmp_v.iov_rlen = tmp_pack;
        if (rpc_iovec_cmp(tmp_pack, &tmp_v, 1, tmp_pack, msghdr->msg_iov,
                          msghdr->msg_iovlen) != 0)
            TEST_VERDICT("Data in #%d packet is incorrect", i);
    }

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
    while(readable)
    {
        rpc_read(pco_iut, iut_s, rx_buf, data_size);
        rem_pack++;
        RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
    }

    if (rem_pack != pack_num - get_pack)
        TEST_FAIL("There are %d remaining packets on the socket but %d "
                  "packets were sent and %d packets were received by "
                  "recvmmsg-like function", rem_pack, pack_num,
                  get_pack);

    if (use_zc)
    {
        memset(cb_flags, 0, sizeof(cb_flags));
        for (i = 0; i < vlen - 1; i++)
            RPC_WRITE(rc, pco_tst, tst_s, buffers[i], data_size);
        TAPI_WAIT_NETWORK;

        pco_iut->op = RCF_RPC_CALL;
        get_pack = rpc_simple_zc_recv_gen_mmsg(
                                          pco_iut, iut_s, mmsghdr, vlen,
                                          NULL, flags, cb_flags, TRUE);
        TAPI_WAIT_NETWORK;
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
        if (!done)
        {
            RPC_WRITE(rc, pco_tst, tst_s, buffers[vlen - 1], data_size);
            RING_VERDICT("onload_zc_recv() function hangs.");
            failed = TRUE;
        }
        pco_iut->op = RCF_RPC_WAIT;
        get_pack = rpc_simple_zc_recv_gen_mmsg(
                                          pco_iut, iut_s, mmsghdr, vlen,
                                          NULL, flags, cb_flags, TRUE);
        last_pkt_num = done ? get_pack : vlen - 1;
        if (cb_flags[last_pkt_num - 1] != ONLOAD_ZC_END_OF_BURST)
            TEST_VERDICT("Last packet in te burst doesn't have "
                         "ONLOAD_ZC_END_OF_BURST flag.");
    }

    if (failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    for (i = 0; i < pack_num; i++)
        if (buffers[i] != NULL)
            free(buffers[i]);
    for (i = 0; i < vlen; i++)
    {
        msghdr = &mmsghdr[i].msg_hdr;
        free(msghdr->msg_name);
        sockts_free_iovecs(msghdr->msg_iov, iov_len[i]);
    }

    TEST_END;
}
