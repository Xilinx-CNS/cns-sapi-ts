/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-pipe Reliability of pipe() operation
 *
 * @objective Test on reliability of the @b pipe() operations.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_iut_only
 * @param data_size             Size of data to be sent (if string is
 *                              started with '+', '-', '*' or '/' -
 *                              it is interpreted as an expression
 *                              with memory page size, i.e. "*2" is
 *                              page size * 2)
 * @param writer_child          If @c TRUE write to the pipe from the
 *                              child process
 * @param reader_child          If @c TRUE read from the pipe from the
 *                              child process
 * @param block_read            If @c TRUE call @b read() before @b write()
 * @param write_before_fork     Whether to write to the pipe before
 *                              @b fork() call or after it.
 *
 * @par Scenario:
 *
 * -# Create @p pipefds pipe on pco_iut;
 * -# Write data to pipe from @p pco_iut if @p write_before_fork;
 * -# If @p writer_child or @p reader_child is @c TRUE create @p pco_child
 *    using @b fork();
 * -# If @p writer_child or @p reader_child is @c TRUE close unused ends of
 *    pipe according to @p writer_child or @p reader_child parameters;
 * -# If @p block_read is @c TRUE call @b read() according to
 *    @p reader_child parameter;
 * -# Write data to pipe according to @p writer_child if
 *    !(@p write_before_fork);
 * -# Read data from pipe according tp @p reader_child parameter;
 * -# Verify data.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/pipe"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_child = NULL;
    rcf_rpc_server     *pco_aux = NULL;
    rcf_rpc_server     *writer = NULL;
    rcf_rpc_server     *reader = NULL;
    int                 pipefds[2] = { -1, -1 };
    int                 write_end;
    int                 read_end;

    void               *tx_buf = NULL;
    void               *rx_buf = NULL;

    const char         *data_size = NULL;
    long int            page_size = 0;
    int                 data_size_num;
    te_bool             writer_child;
    te_bool             reader_child;
    te_bool             block_read;
    te_bool             write_before_fork = FALSE;
    int                 len = 0;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(data_size);
    TEST_GET_BOOL_PARAM(writer_child);
    if (!writer_child)
        TEST_GET_BOOL_PARAM(write_before_fork);
    TEST_GET_BOOL_PARAM(reader_child);
    TEST_GET_BOOL_PARAM(block_read);
    RPC_AWAIT_IUT_ERROR(pco_iut);

    page_size = rpc_sysconf(pco_iut, RPC_SC_PAGESIZE);
    if (page_size < 0)
        TEST_VERDICT("Failed to get memory page size on IUT");

    if (data_size[0] == '+')
        data_size_num = page_size + strtol(data_size + 1, NULL, 10);
    else if (data_size[0] == '-')
        data_size_num = page_size - strtol(data_size + 1, NULL, 10);
    else if (data_size[0] == '*')
        data_size_num = page_size * strtol(data_size + 1, NULL, 10);
    else if (data_size[0] == '/')
        data_size_num = page_size / strtol(data_size + 1, NULL, 10);
    else
        data_size_num = strtol(data_size, NULL, 10);

    RING("Size of data to be sent is %ld", (long int)data_size_num);
 
    tx_buf = te_make_buf_by_len(data_size_num);
    rx_buf = te_make_buf_by_len(data_size_num);

    rpc_pipe(pco_iut, pipefds);
    write_end = pipefds[1];
    read_end = pipefds[0];

    if (write_before_fork)
    {
        rc = rpc_write(pco_iut, write_end, tx_buf, data_size_num);
        if (rc != (int)data_size_num)
            TEST_FAIL("RPC write() on IUT does not write all data");
    }

    if (writer_child || reader_child)
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child));

    if (block_read && writer_child == reader_child)
    {
        CHECK_RC(rcf_rpc_server_thread_create((writer_child) ? pco_child :
                                                               pco_iut,
                                              "child_thread", &pco_aux));
        reader = pco_aux;
    }
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

    if (block_read)
    {
        reader->op = RCF_RPC_CALL;
        rc = rpc_read(reader, read_end, rx_buf, data_size_num);

        TAPI_WAIT_NETWORK;

        writer->op = RCF_RPC_CALL;
        rpc_write(writer, write_end, tx_buf, data_size_num);

        reader->op = RCF_RPC_WAIT;
        len = rpc_read(reader, read_end, rx_buf, data_size_num);
        while (len < data_size_num &&
               (rc = rpc_read(reader, read_end, rx_buf + len,
                              data_size_num - len)) > 0)
            len += rc;

        if (len != data_size_num)
            TEST_FAIL("Only part of data received %d/%d bytes",
                      rc, data_size_num);

        writer->op = RCF_RPC_WAIT;
        RPC_WRITE(rc, writer, write_end, tx_buf, data_size_num);
    }
    else
    {
        if (!write_before_fork)
        {
            if (writer != reader)
                writer->op = RCF_RPC_CALL;
            rc = rpc_write(writer, write_end, tx_buf, data_size_num);
            if (writer == reader && rc != (int)data_size_num)
                TEST_FAIL("RPC write() on IUT does not write all data");
            else if (writer != reader && rc != 0)
                TEST_FAIL("RPC write() failed: %r", RPC_ERRNO(pco_iut));
        }

        while (len < data_size_num &&
               (rc = rpc_read(reader, read_end, rx_buf + len,
                              data_size_num - len)) > 0)
            len += rc;

        if (len != data_size_num)
            TEST_FAIL("Only part of data received %d/%d bytes",
                      rc, data_size_num);

        if (writer != reader && !write_before_fork)
        {
            writer->op = RCF_RPC_WAIT;
            RPC_WRITE(rc, writer, write_end, tx_buf, data_size_num);
        }
    }

    if (memcmp(tx_buf, rx_buf, data_size_num))
        TEST_FAIL("Invalid data received");

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

    if (pco_aux != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));
    rcf_rpc_server_destroy(pco_child);

    TEST_END;
}
