/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Onload extensions
 */

/**
 * @page level5-extension-msg_warm_fill_send_buf Using MSG_WARM while send buffer is not empty
 *
 * @objective Check that using of @c ONLOAD_MSG_WARM flag is harmless
 *            when send buffer is not empty.
 *
 * @param sock_type   Socket type:
 *                    - tcp active
 *                    - tcp passive
 * @param func        Testing send function:
 *                    - send
 *                    - sendto
 *                    - sendmsg
 *                    - onload_zc_send
 * @param full        Send buffer is full if @c TRUE.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/msg_warm_fill_send_buf"

#include "sockapi-test.h"
#include "te_dbuf.h"

/** Buffer length for ordinary data. */
#define PKT_LEN 1024

/** Buffer length for data sent with ONLOAD_MSG_WARM. */
#define WARM_PKT_LEN 512

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int   iut_s = -1;
    int   tst_s = -1;

    char buf[PKT_LEN];
    int  fail_cnt = 0;
    int  read_part = 0;

    te_dbuf iut_sent = TE_DBUF_INIT(0);
    te_dbuf tst_received = TE_DBUF_INIT(0);

    sockts_socket_type    sock_type;
    rpc_send_f            func;
    te_bool               full;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_SEND_FUNC(func);
    TEST_GET_BOOL_PARAM(full);

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Fill IUT send buffer completely or partly according to "
              "@p full.");

    fail_cnt = 0;

    while(TRUE)
    {
        te_fill_buf(buf, PKT_LEN);

        RPC_AWAIT_ERROR(pco_iut);
        pco_iut->silent = TRUE;
        rc = rpc_send(pco_iut, iut_s, buf, PKT_LEN, RPC_MSG_DONTWAIT);
        if (rc <= 0)
        {
            if (rc < 0 && RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                TEST_VERDICT("Wrong errno %r encountered "
                             "when trying to overfill send buffer",
                             RPC_ERRNO(pco_iut));
            else if (rc == 0)
                TEST_VERDICT("send() returned zero "
                             "when trying to overfill send buffer");

            fail_cnt++;
            if (fail_cnt > 1)
                break;
            TAPI_WAIT_NETWORK;
        }
        else
        {
            fail_cnt = 0;
            te_dbuf_append(&iut_sent, buf, rc);
        }
    }

    RING("%lu bytes were sent", (long unsigned int)iut_sent.len);

    if (!full)
        read_part = sockts_tcp_read_part_of_send_buf(pco_tst, tst_s,
                                                     iut_sent.len);

    TEST_STEP("Call @p func with @c MSG_WARM.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, buf, WARM_PKT_LEN, RPC_MSG_WARM);
    if (rc < 0)
        TEST_VERDICT("Tested function failed with ONLOAD_MSG_WARM, "
                     "errno %r", RPC_ERRNO(pco_iut));

    TEST_STEP("Try to send more data using function @p func "
              "(it should fail if @p full is @c TRUE and succeed otherwise).");
    te_fill_buf(buf, PKT_LEN);
    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, buf, PKT_LEN, RPC_MSG_DONTWAIT);
    if (full)
    {
        if (rc >= 0)
              TEST_VERDICT("Sending more data succeeded when send buffer "
                           "is overfilled");
        else if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
              TEST_VERDICT("Sending more data failed with unexpected "
                           "errno %r", RPC_ERRNO(pco_iut));
    }
    else
    {
        if (rc < 0)
              TEST_VERDICT("Sending more data failed with errno %r",
                           RPC_ERRNO(pco_iut));
        else if (rc == 0)
              TEST_VERDICT("Send function returned zero");

        te_dbuf_append(&iut_sent, buf, rc);
    }

    TEST_STEP("Read all data on Tester, check it for corruption.");
    while(TRUE)
    {
        RPC_AWAIT_ERROR(pco_tst);
        pco_tst->silent = TRUE;
        rc = rpc_recv(pco_tst, tst_s, buf, PKT_LEN, RPC_MSG_DONTWAIT);
        if (rc <= 0)
        {
            if (rc < 0 && RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                TEST_VERDICT("Wrong errno %r encountered "
                             "when trying to read data on Tester",
                             RPC_ERRNO(pco_iut));
            else if (rc == 0)
                TEST_VERDICT("recv() returned zero "
                             "when trying to read data on Tester");

            fail_cnt++;
            if (fail_cnt > 1)
                break;
            TAPI_WAIT_NETWORK;
        }
        else
        {
            fail_cnt = 0;
            te_dbuf_append(&tst_received, buf, rc);
        }
    }

    RING("%lu bytes were received", (long unsigned int)tst_received.len);

    if (tst_received.len + read_part != iut_sent.len)
    {
        TEST_VERDICT("Number of bytes received on Tester does not match the "
                     "number of bytes sent from IUT");
    }

    if (memcmp(iut_sent.ptr + read_part, tst_received.ptr,
               tst_received.len) != 0)
    {
        TEST_VERDICT("Data received on Tester does not "
                     "match data sent from IUT");
    }

    TEST_STEP("Send some data in both directions, read and check it.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:

    te_dbuf_free(&iut_sent);
    te_dbuf_free(&tst_received);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
