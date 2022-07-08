/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-pipe_rw_rnd_len Read and write operations on pipe with randomly generated buffer lengths
 *
 * @objective Check that reading and writing different amounts of data
 *            from/to the pipe are handled correctly.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param iter_num  Number of @b write() + @b read() iterations:
 *                  - 20
 * @param writer_child  If @c TRUE write to the pipe from the child process.
 * @param reader_child  If @c TRUE read from the pipe from the child process.
 *
 * @par Scenario:
 *
 * -# Create @p pipefds pipe on pco_iut;
 * -# If @p writer_child or @p reader_child is @c TRUE create @p pco_child
 *    using @b fork();
 * -# If @p writer_child or @p reader_child is @c TRUE close unused ends of
 *    pipe according to @p writer_child or @p reader_child parameters;
 * -# Do the following iterations @p iter_num times:
 *      - Write randomly generated number of bytes to pipe according to
 *        @p writer_child;
 *      - Read randomly generated number of bytes from pipe according to
 *        @p reader_child parameter;
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_rw_rnd_len"

#include "sockapi-test.h"

#define MAX_LEN 50000

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_child = NULL;
    rcf_rpc_server     *writer = NULL;
    rcf_rpc_server     *reader = NULL;
    int                 pipefds[2] = { -1, -1 };
    int                 write_end;
    int                 read_end;

    uint8_t            *tx_buf = NULL;
    uint8_t            *rx_buf = NULL;

    int                 write_len;
    int                 read_len;
    te_bool             writer_child;
    te_bool             reader_child;

    uint64_t            bytes_in_pipe = 0;
    int                 iter_num;

    int                 i;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(iter_num);
    TEST_GET_BOOL_PARAM(writer_child);
    TEST_GET_BOOL_PARAM(reader_child);

    tx_buf = te_make_buf_by_len(MAX_LEN);
    rx_buf = te_make_buf_by_len(MAX_LEN);

    rpc_pipe(pco_iut, pipefds);
    write_end = pipefds[1];
    read_end = pipefds[0];

    if (writer_child || reader_child)
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child));

    writer = (writer_child) ? pco_child : pco_iut;
    if (reader == NULL)
        reader = (reader_child) ? pco_child : pco_iut;

    if (writer_child != reader_child)
    {
        RPC_CLOSE(writer, pipefds[0]);
        RPC_CLOSE(reader, pipefds[1]);
    }
    else if (writer_child)
    {
        RPC_CLOSE(pco_iut, pipefds[0]);
        RPC_CLOSE(pco_iut, pipefds[1]);
    }

    for (i = 0; i < iter_num; i++)
    {
        write_len = rand_range(1, (bytes_in_pipe + MAX_LEN / 3 > MAX_LEN) ?
                                    MAX_LEN - bytes_in_pipe:
                                    MAX_LEN / 3);
        RING("bytes_in_pipe = %d, MAX_LEN = %d, write_len = %d", bytes_in_pipe, MAX_LEN, write_len);
        rc = rpc_write(writer, write_end, tx_buf, write_len);
        if (rc != (int)write_len)
            TEST_FAIL("write() does not write all data on %d iteration",
                       i);
        bytes_in_pipe += write_len;
        read_len = rand_range(1, (bytes_in_pipe > MAX_LEN / 3) ?
                                    MAX_LEN / 3 : bytes_in_pipe);
        rc = rpc_read(reader, read_end, rx_buf, read_len);
        if (rc != (int)read_len)
            TEST_FAIL("Only part of data received on %d iteration", i);
        bytes_in_pipe -= read_len;
    }

    TEST_SUCCESS;

cleanup:
    if (writer_child == reader_child)
    {
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
    }
    else
    {
        CLEANUP_RPC_CLOSE(writer, pipefds[0]);
        CLEANUP_RPC_CLOSE(reader, pipefds[1]);
    }

    if (writer_child || reader_child)
    {
        CLEANUP_RPC_CLOSE(writer, write_end);
        CLEANUP_RPC_CLOSE(reader, read_end);
    }

    rcf_rpc_server_destroy(pco_child);

    TEST_END;
}
