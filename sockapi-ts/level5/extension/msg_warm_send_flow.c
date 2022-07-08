/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/**
 * @page level5-extension-msg_warm_send_flow Send data flow and occasionally use ONLOAD_MSG_WARM
 *
 * @objective Check that using @c ONLOAD_MSG_WARM flag is harmless when
 *            it is done during data flow transmission.
 *
 * @param sock_type     Socket type:
 *                      - tcp active
 *                      - tcp passive
 * @param func          Testing send function:
 *                      - send
 *                      - sendto
 *                      - sendmsg
 *                      - onload_zc_send
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/msg_warm_send_flow"

#include "sockapi-test.h"

/** Number of iterations in the main loop. */
#define LOOP_ITERS 100

/** Maximum length of data passed to send function. */
#define MAX_PKT_LEN SOCKTS_ONLOAD_ZC_SEND_MAX_IOV_LEN

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int   iut_s = -1;
    int   tst_s = -1;

    int   i;
    int   send_len;
    int   recv_len;
    char  tx_buf[MAX_PKT_LEN];
    char  rx_buf[MAX_PKT_LEN];
    int   flags;

    sockts_socket_type    sock_type;
    rpc_send_f            func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_SEND_FUNC(func);

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("In a loop @c LOOP_ITERS times:");
    for (i = 0; i < LOOP_ITERS; i++)
    {
        send_len = rand_range(1, MAX_PKT_LEN);

        te_fill_buf(tx_buf, send_len);

        if (rand_range(0, 1) == 0)
            flags = 0;
        else
            flags = RPC_MSG_WARM;

        TEST_SUBSTEP("Call @p func, choosing random send buffer length, "
                     "and choosing randomly whether to use @c MSG_WARM flag.");

        RPC_AWAIT_ERROR(pco_iut);
        rc = func(pco_iut, iut_s, tx_buf, send_len, flags);
        if (rc < 0)
            TEST_VERDICT("%s(flags=%s) failed with errno %r",
                         rpc_send_func_name(func),
                         send_recv_flags_rpc2str(flags),
                         RPC_ERRNO(pco_iut));
        else if (rc != send_len)
            TEST_VERDICT("%s(flags=%s) return value differs from length of "
                         "data to send",
                         rpc_send_func_name(func),
                         send_recv_flags_rpc2str(flags));

        TEST_SUBSTEP("Read data on tester if @c MSG_WARM was not set, "
                     "check the data.");
        if (!(flags & RPC_MSG_WARM))
        {
            recv_len = 0;
            do {
                rc = rpc_recv(pco_tst, tst_s, rx_buf + recv_len,
                              MAX_PKT_LEN - recv_len, 0);
                recv_len += rc;
            } while (recv_len < send_len);

            if (recv_len != send_len ||
                memcmp(tx_buf, rx_buf, send_len) != 0)
                TEST_VERDICT("Received data differes from sent data");
        }
    }

    TEST_STEP("Call shutdown(WR) on IUT socket.");
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);

    TEST_STEP("Check that recv() on Tester returns @c 0.");
    rc = rpc_recv(pco_tst, tst_s, rx_buf, MAX_PKT_LEN, 0);
    if (rc != 0)
        TEST_VERDICT("After calling shutdown(WR) on IUT socket "
                     "recv() on Tester did not return zero");

    TEST_STEP("Close Tester socket.");
    RPC_CLOSE(pco_tst, tst_s);

    TEST_STEP("Check that recv() on IUT returns @c 0.");
    rc = rpc_recv(pco_iut, iut_s, rx_buf, MAX_PKT_LEN, 0);
    if (rc != 0)
        TEST_VERDICT("After calling close on Tester socket "
                     "recv() on IUT did not return zero");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
