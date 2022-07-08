/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/**
 * @page level5-extension-msg_warm_zc_send onload_zc_send() with ONLOAD_MSG_WARM
 *
 * @objective Check that @c ONLOAD_MSG_WARM flag cannot be used
 *            with onload_zc_send() when more than MSS bytes or more than
 *            one IOV is passed to this function.
 *
 * @param sock_type     Socket type:
 *                      - tcp active
 *                      - tcp passive
 * @param big_packet    Whether to send more than MSS or not.
 * @param single_iov    Whether to send single IOV or not (cannot
 *                      be @c TRUE in the same time as @p big_packet
 *                      since @b onload_zc_send() does not allow
 *                      to send large buffer in the single IOV).
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/msg_warm_zc_send"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int   iut_s = -1;
    int   tst_s = -1;
    int   mss;

    rpc_iovec   *iovs = NULL;
    int          iov_cnt = 0;

    struct rpc_onload_zc_mmsg mmsg;

    int min_data_len;
    int max_data_len;

    sockts_socket_type    sock_type;
    te_bool               big_packet;
    te_bool               single_iov;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(big_packet);
    TEST_GET_BOOL_PARAM(single_iov);

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, &iut_s, &tst_s, NULL);

    TEST_STEP("Get MSS value for the connection.");
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);

    TEST_STEP("Construct parameters of @b onload_zc_send() according to "
              "@p single_iov and @p big_packet.");

    if (single_iov)
    {
        if (big_packet)
            TEST_FAIL("single_iov and big_packet cannot be both TRUE");

        min_data_len = 1;
        max_data_len = MIN(mss / 2, SOCKTS_ONLOAD_ZC_SEND_MAX_IOV_LEN);
        iov_cnt = 1;
    }
    else
    {
        if (big_packet)
        {
            min_data_len = MIN(mss / 2,
                               SOCKTS_ONLOAD_ZC_SEND_MAX_IOV_LEN / 2);
            max_data_len = SOCKTS_ONLOAD_ZC_SEND_MAX_IOV_LEN;
            iov_cnt = (mss + 1) / min_data_len;
            if ((mss + 1) % min_data_len != 0)
                iov_cnt++;
        }
        else
        {
            min_data_len = 1;
            max_data_len = MIN(mss / 2, SOCKTS_ONLOAD_ZC_SEND_MAX_IOV_LEN);
            iov_cnt = 2;
        }
    }

    rpc_alloc_iov(&iovs, iov_cnt, min_data_len, max_data_len);

    memset(&mmsg, 0, sizeof(mmsg));
    mmsg.msg.msg_iov = iovs;
    mmsg.msg.msg_iovlen = mmsg.msg.msg_riovlen = iov_cnt;
    mmsg.fd = iut_s;

    TEST_STEP("Call @b onload_zc_send(), check that it reports @c EINVAL "
              "unless @p single_iov is @c TRUE and @p big_packet is @c FALSE.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_simple_zc_send_gen(pco_iut, &mmsg, 1, RPC_MSG_WARM, -1, FALSE,
                                RPC_NULL, NULL);
    if (rc != 1)
    {
        TEST_VERDICT("onload_zc_send() returned unexpected result");
    }
    else
    {
        if (single_iov && !big_packet)
        {
            if (mmsg.rc < 0)
                TEST_VERDICT("onload_zc_send() unexpectedly reported "
                             "error %r", -mmsg.rc);
            else if (mmsg.rc != (int)rpc_iov_data_len(iovs, iov_cnt))
                TEST_VERDICT("onload_zc_send() reported unexpected "
                             "sent data length");
        }
        else
        {
            if (mmsg.rc >= 0)
                TEST_VERDICT("onload_zc_send() unexpectedly reported "
                             "success");
            else if (mmsg.rc != -RPC_EINVAL)
                TEST_VERDICT("onload_zc_send() reported %r error instead "
                             "of %r", -mmsg.rc, RPC_EINVAL);
        }
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    rpc_free_iov(iovs, iov_cnt);

    TEST_END;
}
