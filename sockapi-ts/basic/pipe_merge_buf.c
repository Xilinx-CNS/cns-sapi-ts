/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-pipe_merge_buf Read data from the pipe using big buffer after several write calls
 *
 * @objective Check that data is correctly merged when @b read() with big
 *            buffer is called on the pipe with data written using several
 *            calls.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param write_num Number of @b write calls:
 *                  - 5
 * @param add_bytes Difference between buffer used for @b read() call and the
 *                  amount of data in the pipe:
 *                  - 0
 *                  - 512
 *
 * @par Scenario:
 *
 * -# Create @p pipefds pipe on pco_iut;
 * -# Create @p pco_child using @b fork();
 * -# Call @b write() @p write_num times with random number of bytes from
 *    @p pco_iut or @p pco_child the pipe.
 * -# Read data from the pipe according to @p add_bytes parameter.
 * -# Verify the data.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_merge_buf"

#include "sockapi-test.h"

#define MAX_WRITE_NUM 20
#define MIN_BUF_SIZE 1
#define MAX_BUF_SIZE 8192

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_child = NULL;
    int                 pipefds[2] = { -1, -1};
    int                 write_num;

    int8_t             *tx_buf[MAX_WRITE_NUM];
    int8_t             *rx_buf = NULL;
    size_t              buf_len[MAX_WRITE_NUM];
    size_t              total_bytes = 0;

    int                 add_bytes;

    int                 from_child;

    int i;
    int tmp = 0;

    rpc_send_f          send_f;
    rpc_recv_f          recv_f;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(write_num);
    TEST_GET_INT_PARAM(add_bytes);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_RECV_FUNC(recv_f);

    for (i = 0; i < write_num; i++)
    {
        tx_buf[i] = te_make_buf(MIN_BUF_SIZE, MAX_BUF_SIZE, &buf_len[i]);
        te_fill_buf(tx_buf[i], buf_len[i]);
        total_bytes += buf_len[i];
    }
    rx_buf = te_make_buf_by_len(total_bytes + add_bytes);

    rpc_pipe(pco_iut, pipefds);

    CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child));

    for (i = 0; i < write_num; i++)
    {
        from_child = rand_range(FALSE, TRUE);
        if ((rc = send_f((from_child) ? pco_child : pco_iut, pipefds[1],
                         tx_buf[i], buf_len[i], 0)) != (int)buf_len[i])
            TEST_FAIL("%s() sent %d bytes instead of %d",
                      rpc_send_func_name(send_f), rc, buf_len[i]);
    }

    from_child = rand_range(FALSE, TRUE);
    rc = recv_f((from_child) ? pco_child : pco_iut, pipefds[0],
                rx_buf, total_bytes + add_bytes, 0);
    if (rc != (int)total_bytes)
    {
        WARN("%d bytes were sent, %d bytes were recieved", total_bytes, rc);
        TEST_VERDICT("Incorrect number of bytes were recieved");
    }

    for (i = 0; i < write_num; i++)
    {
        if (memcmp(tx_buf[i], rx_buf + tmp, buf_len[i]) != 0)
            TEST_VERDICT("Incorrect data were recieved");
        tmp += buf_len[i];
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
    CLEANUP_RPC_CLOSE(pco_child, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_child, pipefds[1]);

    rcf_rpc_server_destroy(pco_child);

    TEST_END;
}
