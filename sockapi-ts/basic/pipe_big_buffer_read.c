/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-pipe_big_buffer_read Read operation on the pipe with big buffer
 *
 * @objective Check that @p read() operation on pipe with buffer bigger
 *            than available data works correctly.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param data_size     Size of data to be sent:
 *                      - 512
 *                      - 1024
 *                      - 8192
 * @param writer_child  If @c TRUE write to the pipe from the child process.
 * @param reader_child  If @c TRUE read from the pipe from the child process.
 * @param blocking_read Perform blocking or non-blocking @p read() call.
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
 * -# If @p recv_f is @c readv() make read vector according to @p iovlen
 *    and with total buffer size more then @p data_size;
 * -# If @p writer_child or @p reader_child is @c TRUE create @p pco_child
 *    using @b fork();
 * -# If @p writer_child or @p reader_child is @c TRUE close unused ends of
 *    pipe according to @p writer_child or @p reader_child parameters;
 * -# If @p blocking_read is @c FALSE call @b fcntl(@c O_NONBLOCK) on read
 *    end;
 * -# Write data to pipe according to @p writer_child;
 * -# Read data from pipe according to @p reader_child parameter using
 *    buffer greater than available data;
 * -# Check that @p recv_f returns the number of data bytes that was
 *    available in the pipe;
 * -# Verify data.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_big_buffer_read"

#include "sockapi-test.h"

#define ADD_SIZE 100
#define MAX_IOV_LEN 16

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_child = NULL;
    rcf_rpc_server     *writer = NULL;
    rcf_rpc_server     *reader = NULL;
    int                 pipefds[2] = { -1, -1};
    int                 write_end = -1;
    int                 read_end = -1;

    uint8_t            *tx_buf = NULL;
    uint8_t            *rx_buf = NULL;
    uint8_t            *check_buf = NULL;
    uint8_t            *tmp_buf = NULL;

    struct rpc_iovec   *rx_vector = NULL;
    int                 iovlen;
    int                 size1;
    int                 size2;
    int                 size3;
    int                 count = 0;

    int                 data_size;
    te_bool             writer_child;
    te_bool             reader_child;
    te_bool             blocking_read;

    rpc_send_f          send_f;
    rpc_recv_f          recv_f;

    int i;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(writer_child);
    TEST_GET_BOOL_PARAM(reader_child);
    TEST_GET_BOOL_PARAM(blocking_read);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_RECV_FUNC(recv_f);
    TEST_GET_INT_PARAM(iovlen);

    rpc_pipe(pco_iut, pipefds);
    write_end = pipefds[1];
    read_end = pipefds[0];

    tx_buf = te_make_buf_by_len(data_size);
    te_fill_buf(tx_buf, data_size);
    check_buf = te_make_buf_by_len(data_size + ADD_SIZE);
    tmp_buf = te_make_buf_by_len(data_size + ADD_SIZE);
    if (recv_f == rpc_recv_func_read)
    {
        rx_buf = te_make_buf_by_len(data_size + ADD_SIZE);
        memcpy(check_buf, rx_buf, data_size + ADD_SIZE);
    }
    else
    {
        CHECK_NOT_NULL(rx_vector =
                       calloc(iovlen, sizeof(struct rpc_iovec)));
        if (iovlen == 2)
        {
            size1 = rand_range(1, data_size + ADD_SIZE - 1);
            size2 = data_size + ADD_SIZE - size1;
            rx_vector[0].iov_base = te_make_buf_by_len(size1);
            rx_vector[0].iov_len = rx_vector[0].iov_rlen = size1;
            rx_vector[1].iov_base = te_make_buf_by_len(size2);
            rx_vector[1].iov_len = rx_vector[1].iov_rlen = size2;
            memcpy(check_buf, rx_vector[0].iov_base, size1);
            memcpy(check_buf + size1, rx_vector[1].iov_base, size2);
        }
        if (iovlen == 3)
        {
            size1 = rand_range(1, data_size + ADD_SIZE - 2);
            size2 = rand_range(1, data_size + ADD_SIZE - size1 - 1);
            size3 = data_size + ADD_SIZE - size1 - size2;
            rx_vector[0].iov_base = te_make_buf_by_len(size1);
            rx_vector[0].iov_len = rx_vector[0].iov_rlen = size1;
            rx_vector[1].iov_base = te_make_buf_by_len(size2);
            rx_vector[1].iov_len = rx_vector[1].iov_rlen = size2;
            rx_vector[2].iov_base = te_make_buf_by_len(size3);
            rx_vector[2].iov_len = rx_vector[2].iov_rlen = size3;
            memcpy(check_buf, rx_vector[0].iov_base, size1);
            memcpy(check_buf + size1, rx_vector[1].iov_base, size2);
            memcpy(check_buf + size1 + size2, rx_vector[2].iov_base, size3);
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

    if (!blocking_read)
        rpc_fcntl(reader, read_end, RPC_F_SETFL, RPC_O_NONBLOCK);

    if ((rc = send_f(writer, write_end, tx_buf, data_size, 0)) != data_size)
        TEST_FAIL("%s() returned %d bytes instead of %d", rc, data_size);

    if (recv_f == rpc_recv_func_read)
        rc = rpc_read(reader, read_end, rx_buf, data_size + ADD_SIZE);
    else
        rc = rpc_readv(reader, read_end, rx_vector, iovlen);

    if (rc != (int)data_size)
    {
        ERROR("%d bytes were sent, %d bytes were recieved", data_size, rc);
        TEST_VERDICT("Incorrect number of bytes were recieved");
    }

    if (recv_f == rpc_recv_func_readv)
    {
        for (i = 0; i < iovlen; i++)
        {
             memcpy(tmp_buf + count, rx_vector[i].iov_base,
                    rx_vector[i].iov_len);
             count += rx_vector[i].iov_rlen;
        }
    }
    else
        memcpy(tmp_buf, rx_buf, data_size + ADD_SIZE);

    if (memcmp(tx_buf, tmp_buf, data_size) != 0)
        TEST_VERDICT("Incorrect data were recieved");

    if (memcmp(check_buf + data_size, tmp_buf + data_size, ADD_SIZE)
        != 0)
        TEST_VERDICT("The rest of recieve buffer was modified");

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
