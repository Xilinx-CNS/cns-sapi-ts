/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-rcvtimeo_recvmmsg Usage of SO_RCVTIMEO socket with recvmmsg() function option
 *
 * @objective Check interaction of @c SO_RCVTIMEO option and @p timeout
 *            field in @b recvmmsg() function.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/rcvtimeo_recvmmsg"

#include "sockapi-test.h"

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

    int data_size;
    int timeout;
    int rcvtimeo;
    int vlen;

    ssize_t buf_len[RCF_RPC_MAX_MSGHDR];
    int     iov_len[RCF_RPC_MAX_MSGHDR];
    size_t  tmp;

    char         buffer[MAX_BUF_LEN];
    int          i;

    int          before_pack;
    int          during_pack;
    te_bool      after_pack;
    int          total_pack = 0;

    tarpc_timeval    opt_val;
    te_bool          operation_done = FALSE;
    uint64_t         expected;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_INT_PARAM(rcvtimeo);
    TEST_GET_INT_PARAM(vlen);
    TEST_GET_INT_PARAM(before_pack);
    TEST_GET_INT_PARAM(during_pack);
    TEST_GET_BOOL_PARAM(after_pack);

    /* Prepare mmsghdr */
    for (i = 0; i < vlen; i++)
    {
        msghdr = &mmsghdr[i].msg_hdr;

        msghdr->msg_namelen = sizeof(struct sockaddr_storage);
        CHECK_NOT_NULL(msghdr->msg_name =
                        te_make_buf_min(msghdr->msg_namelen, &tmp));
        msghdr->msg_rnamelen = tmp;

        iov_len[i] = rand_range(1, MAX_IOV_LEN);
        buf_len[i] = rand_range(MIN_BUF_LEN, MAX_BUF_LEN);
        msghdr->msg_iov = sockts_make_iovec(&iov_len[i], &buf_len[i]);
        msghdr->msg_iovlen = msghdr->msg_riovlen = iov_len[i];

        msghdr->msg_controllen = 0;
        msghdr->msg_control = NULL;

        /** Bug 57654: don't check msg_flags to avoid fails.
         * FIXME: sensible check should be added. */
        msghdr->msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;
    }

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_IPPROTO_UDP, TRUE, FALSE,
                                       iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_connect(pco_tst, tst_s, iut_addr);

    opt_val.tv_sec = rcvtimeo;
    opt_val.tv_usec = 0 ;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_RCVTIMEO, &opt_val);

    for (i = 0; i < before_pack; i++)
    {
        RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
        SLEEP(1);
    }
    total_pack = before_pack;

    to.tv_sec = timeout;
    to.tv_nsec = 0;

    pco_iut->timeout = pco_iut->def_timeout + TE_SEC2MS(timeout) +
                       TE_US2MS(rcvtimeo);
    pco_iut->op = RCF_RPC_CALL;
    rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, vlen, 0, &to);

    TAPI_WAIT_NETWORK;

    for (i = 0; i < during_pack; i++)
    {
        RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
        SLEEP(1);
    }
    total_pack += during_pack;

    SLEEP(timeout - during_pack + 1);

    rcf_rpc_server_is_op_done(pco_iut, &operation_done);

    if (operation_done)
    {
        pco_iut->op = RCF_RPC_WAIT;
        rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, vlen, 0, &to);
        expected = timeout * 1000000;
        CHECK_CALL_DURATION_INT(pco_iut->duration, TST_TIME_INACCURACY * 10,
                                TST_TIME_INACCURACY_MULTIPLIER,
                                expected, expected);
        RING_VERDICT("recvmmsg() has returned just after its timeout.");
    }
    else if (after_pack)
    {
        SLEEP(1);
        RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
        total_pack++;
        TAPI_WAIT_NETWORK;
        rcf_rpc_server_is_op_done(pco_iut, &operation_done);
        if (!operation_done)
            TEST_VERDICT("recvmmsg() still hangs after recieving "
                         "packet after timeout");
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, vlen, 0, &to);
    if (rc != total_pack)
        TEST_VERDICT("%d packet was sent but only %d was recieved.",
                     total_pack, rc);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    for (i = 0; i < vlen; i++)
    {
        msghdr = &mmsghdr[i].msg_hdr;
        free(msghdr->msg_name);
        sockts_free_iovecs(msghdr->msg_iov, iov_len[i]);
    }

    TEST_END;
}
