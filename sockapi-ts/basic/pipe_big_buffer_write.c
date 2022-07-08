/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-pipe_big_buffer_write Write operation on the pipe with big buffer
 *
 * @objective Check that non-blocking @p write() operation on almost
 *            overfilled pipe buffer returns correct number of sent bytes.
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
 * @param reader_child   If @c TRUE read from the pipe from the child
 *                       process.
 * @param blocking_write Perform blocking or non-blocking @p read() call.
 * @param send_f        Tested write function (in couples with @p recv_f):
 *                      - write()
 *                      - writev()
 * @param recv_f        Tested read function:
 *                      - read()
 *                      - readv()
 * @param iovlen        Number of elements in vector for @b readv() function:
 *                      - 2
 *                      - 3
 *
 * @par Scenario:
 *
 * -# Create @p pipefds pipe on pco_iut;
 * -# If @p writer_child or @p reader_child is @c TRUE create @p pco_child
 *    using @b fork();
 * -# If @p writer_child or @p reader_child is @c TRUE close unused ends of
 *    pipe according to @p writer_child or @p reader_child parameters;
 * -# If @p blocking_write is @c FALSE call @b fcntl(@c O_NONBLOCK) on
 *    write end;
 * -# Overfill pipe;
 * -# Read data from the pipe until pipe becomes writable.
 * -# Write the amount of data greater then number of read bytes.
 * -# If @p blocking_write is @c TRUE read data from the pipe to unblock
 *    @p send_f function.
 * -# Check that @p write returns correct number of bytes.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_big_buffer_write"

#include "sockapi-test.h"

/* Minimum data size to read to make pipe writable */
#define MIN_DATA_READ 4096

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_child = NULL;
    rcf_rpc_server     *pco_aux = NULL;
    rcf_rpc_server     *writer = NULL;
    rcf_rpc_server     *reader = NULL;
    int                 pipefds[2] = { -1, -1};
    int                 write_end;
    int                 read_end;

    void               *tx_buf = NULL;
    void               *rx_buf = NULL;

    struct rpc_iovec   *tx_vector = NULL;
    int                 iovlen;
    int                 size1;
    int                 size2;
    int                 size3;

    int                 data_size;
    te_bool             writer_child;
    te_bool             reader_child;
    te_bool             blocking_write;
    te_bool             is_wrt = FALSE;
    int                 counter = 0;

    int                 max_tries;

    rpc_send_f          send_f;
    rpc_recv_f          recv_f;

    te_bool             operation_done;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(writer_child);
    TEST_GET_BOOL_PARAM(reader_child);
    TEST_GET_BOOL_PARAM(blocking_write);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_RECV_FUNC(recv_f);
    TEST_GET_INT_PARAM(iovlen);

    max_tries = (MIN_DATA_READ / data_size) + 2;
    rpc_pipe(pco_iut, pipefds);
    write_end = pipefds[1];
    read_end = pipefds[0];

    rx_buf = te_make_buf_by_len(data_size);
    if (send_f == rpc_send_func_write)
        tx_buf = te_make_buf_by_len(data_size * max_tries);
    else
    {
        CHECK_NOT_NULL(tx_vector =
                       calloc(iovlen, sizeof(struct rpc_iovec)));
        if (iovlen == 2)
        {
            size1 = rand_range(1, data_size * max_tries - 1);
            size2 = data_size * max_tries - size1;
            tx_vector[0].iov_base = te_make_buf_by_len(size1);
            tx_vector[0].iov_len = tx_vector[0].iov_rlen = size1;
            tx_vector[1].iov_base = te_make_buf_by_len(size2);
            tx_vector[1].iov_len = tx_vector[1].iov_rlen = size2;
        }
        if (iovlen == 3)
        {
            size1 = rand_range(1, data_size * max_tries - 2);
            size2 = rand_range(1, data_size * max_tries - size1 - 1);
            size3 = data_size * max_tries - size1 - size2;
            tx_vector[0].iov_base = te_make_buf_by_len(size1);
            tx_vector[0].iov_len = tx_vector[0].iov_rlen = size1;
            tx_vector[1].iov_base = te_make_buf_by_len(size2);
            tx_vector[1].iov_len = tx_vector[1].iov_rlen = size2;
            tx_vector[2].iov_base = te_make_buf_by_len(size3);
            tx_vector[2].iov_len = tx_vector[2].iov_rlen = size3;
        }
    }

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

    if (!blocking_write)
        rpc_fcntl(writer, write_end, RPC_F_SETFL, RPC_O_NONBLOCK);

    rpc_overfill_fd(writer, write_end, NULL);

    while (!is_wrt && counter < max_tries)
    {
        recv_f(reader, read_end, rx_buf, data_size, 0);
        RPC_GET_WRITABILITY(is_wrt, writer, write_end, 1);
        counter++;
    }

    if (counter == max_tries)
        TEST_FAIL("Failed to make pipe writable.");

    if (blocking_write && reader == writer)
        CHECK_RC(rcf_rpc_server_thread_create(reader, "child_thread",
                                              &pco_aux));

    writer->op = RCF_RPC_CALL;
    if (send_f == rpc_send_func_write)
        rc = rpc_write(writer, write_end, tx_buf,
                       data_size * max_tries);
    else
        rc = rpc_writev(writer, write_end, tx_vector, iovlen);

    if (blocking_write)
    {
        SLEEP(1);
        rcf_rpc_server_is_op_done(writer, &operation_done);
        if (operation_done)
            TEST_FAIL("%s() function doen't hang.",
                      rpc_send_func_name(send_f));

        while (!operation_done)
        {
            recv_f((reader == writer) ? pco_aux : reader, read_end, rx_buf,
                   data_size, 0);
            rcf_rpc_server_is_op_done(writer, &operation_done);
            counter++;
        }
    }

    writer->op = RCF_RPC_WAIT;
    if (send_f == rpc_send_func_write)
        rc = rpc_write(writer, write_end, tx_buf,
                       data_size * max_tries);
    else
        rc = rpc_writev(writer, write_end, tx_vector, iovlen);

    if (blocking_write)
    {
        if (counter < max_tries || counter > max_tries + 2)
            TEST_VERDICT("The data was read %d times although %s() tries "
                         "to write only data_size * %d bytes", counter,
                         rpc_send_func_name(send_f), max_tries);

        if (rc != (int)data_size * max_tries)
        {
            RING("%d bytes were sent, instead of %d",
                 rc, data_size * ((blocking_write) ? max_tries : counter));
            TEST_VERDICT("Incorrect number of bytes were sent");
        }
    }
    else if (rc > (int)data_size * counter ||
             rc < (int)data_size * counter / 2)
        TEST_VERDICT("Incorrect number of bytes were sent");

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
