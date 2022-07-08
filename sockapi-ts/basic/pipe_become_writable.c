/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-pipe_become_writable Writability of the pipe after overfilling
 *
 * @objective Check that pipe become writable if read more then page size
 *            bytes from the pipe after its overfilling.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param data_size     Size of data to be sent:
 *                      - 512
 *                      - 1024
 *                      - 8192
 * @param writer_child   If @c TRUE write to the pipe from the child process.
 * @param reader_child   If @c TRUE read from the pipe from the child process.
 *
 * @par Scenario:
 *
 * -# Create @p pipefds pipe on pco_iut;
 * -# If @p writer_child or @p reader_child is @c TRUE create @p pco_child
 *    using @b fork();
 * -# If @p writer_child or @p reader_child is @c TRUE close unused ends of
 *    pipe according to @p writer_child or @p reader_child parameters;
 * -# Overfill pipe;
 * -# Read data from the pipe until pipe becomes writable.
 * -# Check the amount of data that was read.
 * -# Call @p send_f fucntion on the pipe end check that it returns correct
 *    number of sent bytes.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_become_writable"

#include "sockapi-test.h"

/** It's the bytes number which can be read from the Onload pipe, but the
 * second end of the pipe won't become readable. */
#define PIPE_NO_WRITABLE 1500

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_child = NULL;
    rcf_rpc_server     *writer = NULL;
    rcf_rpc_server     *reader = NULL;
    int                 pipefds[2] = { -1, -1};
    int                 write_end;
    int                 read_end;

    void               *tx_buf = NULL;
    void               *rx_buf = NULL;

    int                 data_size;
    te_bool             writer_child;
    te_bool             reader_child;
    te_bool             is_wrt = FALSE;
    int                 counter = 0;

    long int            page_size = 0;
    int                 max_tries;

    rpc_recv_f          recv_f;
    rpc_send_f          send_f;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(writer_child);
    TEST_GET_BOOL_PARAM(reader_child);
    TEST_GET_RECV_FUNC(recv_f);
    TEST_GET_SEND_FUNC(send_f);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    page_size = rpc_sysconf(pco_iut, RPC_SC_PAGESIZE);
    if (page_size < 0)
        TEST_VERDICT("Failed to get memory page size on IUT");

    max_tries = (page_size / data_size) + 1;
    rpc_pipe(pco_iut, pipefds);
    write_end = pipefds[1];
    read_end = pipefds[0];

    rx_buf = te_make_buf_by_len(data_size);
    tx_buf = te_make_buf_by_len(data_size * max_tries);

    if (writer_child || reader_child)
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child));

    writer = (writer_child) ? pco_child : pco_iut;
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

    rpc_overfill_fd(writer, write_end, NULL);

    while (!is_wrt && counter < max_tries)
    {
        recv_f(reader, read_end, rx_buf, data_size, 0);
        RPC_GET_WRITABILITY(is_wrt, writer, write_end, 1);
        counter++;
    }

    RING("%d bytes of data were read from the pipe.", data_size * counter);
    if (!is_wrt)
        TEST_VERDICT("Pipe didn't become writable then more then "
                     "size of page bytes were read from the pipe");
    else if (PIPE_NO_WRITABLE > data_size * counter)
        RING_VERDICT("Pipe became writable too early.");
    else if (page_size <= data_size * (counter - 1))
        TEST_VERDICT("Pipe became writable too late.");

    data_size = data_size * counter / 2;
    rc = send_f(writer, write_end, tx_buf, data_size, 0);
    if (rc != ((int)data_size))
    {
        WARN("%d bytes were sent, instead of %d", rc, data_size);
        TEST_VERDICT("Incorrect number of bytes were sent");
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
