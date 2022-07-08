/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-pipe_writev_readv Writev/readv operations on pipe
 *
 * @objective Check that @b writev()/ @b readv() operations correctly work
 *            with pipe.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param data_size Size of data to be sent (if string is started with
 *                  '+', '-', '*' or '/' - it is interpreted as an expression
 *                  with memory page size, i.e. "*2" is page size * 2):
 *                  - 1: one byte
 *                  - *1: @c PAGE_SIZE
 *                  - +1: @c PAGE_SIZE + 1
 *                  - *16: 16 * @c PAGE_SIZE
 * @param writer_child  If @c TRUE write to the pipe from the child process.
 * @param reader_child  If @c TRUE read from the pipe from the child process.
 * @param block_read    If @c TRUE call @b readv() before @b writev().
 * @param half_empty    If @c TRUE half of iovec buffers should bhave length
 *                      @c 0.
 * @param write_before_fork     Whether to write to the pipe before
 *                              @b fork() call or after it.
 * @param kill_after_write      Whether to @b kill() writing process after
 *                              @b writev() call.
 *
 * @par Scenario:
 *
 * -# Create @p pipefds pipe on pco_iut;
 * -# Write data to pipe using @p writev() function from @p pco_iut
 *    if @p write_before_fork;
 * -# If @p writer_child or @p reader_child is @c TRUE create @p pco_child
 *    using @b fork();
 * -# If @p writer_child or @p reader_child is @c TRUE close unused ends of
 *    pipe according to @p writer_child or @p reader_child parameters;
 * -# If @p block_read is @c TRUE call @b readv() according to
 *    @p reader_child parameter;
 * -# Write data to pipe using @p writev() function according to
 *    @p writer_child if !(@p write_before_fork);
 * -# Read data from pipe according tp @p reader_child parameter;
 * -# Verify data.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_writev_readv"

#include "sockapi-test.h"

#define MAX_IOV_LEN 16

/**
 * Copy vector @a src to tail of vector @a dst  with offset
 * 
 * @param dst       Destination I/O vector
 * @param src       Source I/O vector
 * @param iovcnt    Number of buffers in vector @a dst
 * @param offt      Offset in bytes from start of vector @a dst
 * 
 * @return Updated offset or @c -1 in case of failure
 */
static int
test_copy_iovec_offt(rpc_iovec *dst, rpc_iovec *src, size_t iovcnt,
                     size_t offt, size_t len)
{
    size_t i;
    size_t start;
    size_t tail = offt;

    for (i = 0; i < iovcnt; i++)
    {
        if (tail > dst[i].iov_len || dst[i].iov_len == 0)
            tail -= dst[i].iov_len;
        else
            break;
    }

    if (iovcnt == i)
    {
        ERROR("Wrong iovec offset, fix test please");
        return -1;
    }

    offt += len;

    if (src[0].iov_len < len)
    {
        memcpy(dst[i].iov_base + tail, src[0].iov_base, src[0].iov_len);
        len -= src[0].iov_len;
    }
    else
    {
        memcpy(dst[i].iov_base + tail, src[0].iov_base, len);
        return offt;
    }

    for (start = i++; i < iovcnt; i++)
    {
        if (dst[i].iov_len < len)
        {
            memcpy(dst[i].iov_base, src[i-start].iov_base, dst[i].iov_len);
            len -= dst[i].iov_len;
        }
        else
        {
            memcpy(dst[i].iov_base, src[i-start].iov_base, len);
            break;
        }
    }

    return offt;
}

/**
 * Make copy of vector tail from offset
 * 
 * @param iov       I/O vector
 * @param iovcnt    Number of buffers in vector
 * @param offt      Offset in bytes
 * @param o_iovcnt  Location for number of buffers in new vector
 * 
 * @return Pointer to copy
 */
static rpc_iovec *
test_make_iovec_offt(rpc_iovec *iov, size_t iovcnt, size_t offt,
                     size_t *o_iovcnt)
{
    rpc_iovec  *vect;
    size_t      i;
    size_t      si;

    for (i = 0; i < iovcnt; i++)
    {
        if (offt > iov[i].iov_len || iov[i].iov_len == 0)
            offt -= iov[i].iov_len;
        else
            break;
    }

    if ((*o_iovcnt = iovcnt - i) == 0)
        TEST_FAIL("Wrong offset, fix test please");

    vect = calloc(*o_iovcnt, sizeof(*vect));
    vect[0].iov_base = malloc(iov[i].iov_len - offt);
    vect[0].iov_len = vect[0].iov_rlen = iov[i].iov_len - offt;
    i++;

    for (si = 1; i < iovcnt; i++, si++)
    {
        vect[si].iov_base = malloc(iov[i].iov_len);
        vect[si].iov_len = vect[si].iov_rlen = iov[i].iov_len;
    }

    return vect;
}

/**
 * Read data using readv() call in loop until data exhausted
 * 
 * @param rpcs          RPC server
 * @param fd            File descriptor to read data
 * @param iov           I/O vector fo data
 * @param iovcnt        Number of buffers in the vector
 * @param total_lenght  Total length of data which should be received
 */
static void
test_readv_loop(rcf_rpc_server *rpcs, int fd, struct rpc_iovec *iov,
                size_t iovcnt, int total_lenght)
{
    struct rpc_iovec   *tmp_vector = NULL;
    int                 res;
    int                 offt = 0;
    size_t              tmp_iov_cnt;

    if ((offt = rpc_readv(rpcs, fd, iov, iovcnt)) == total_lenght)
        return;

    tmp_vector = test_make_iovec_offt(iov, iovcnt, offt, &tmp_iov_cnt);
    while (offt < total_lenght &&
           (res = rpc_readv(rpcs, fd, tmp_vector, tmp_iov_cnt)) > 0)
    {
        if ((offt = test_copy_iovec_offt(iov, tmp_vector, iovcnt, offt,
                                         res)) < 0)
        {
            sockts_free_iovecs(tmp_vector, iovcnt);
            TEST_FAIL("Couldn't copy iov, test problem");
        }

        if (offt >= total_lenght)
            break;

        sockts_free_iovecs(tmp_vector, tmp_iov_cnt);
        tmp_vector = test_make_iovec_offt(iov, iovcnt, offt, &tmp_iov_cnt);
    }
    sockts_free_iovecs(tmp_vector, tmp_iov_cnt);

    if (offt != total_lenght)
        TEST_FAIL("Only part of data received");
}

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

    int                 iov_len_write;
    int                 iov_len_read;
    struct rpc_iovec   *tx_vector = NULL;
    struct rpc_iovec   *rx_vector = NULL;

    long int            page_size = 0;
    const char         *data_size = NULL;
    ssize_t             data_size_num;
    pid_t               iut_pid;
    te_bool             writer_child;
    te_bool             reader_child;
    te_bool             block_read;
    te_bool             half_empty;
    te_bool             write_before_fork;
    te_bool             kill_after_write;
    te_bool             was_killed = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(data_size);
    TEST_GET_BOOL_PARAM(writer_child);
    TEST_GET_BOOL_PARAM(reader_child);
    TEST_GET_BOOL_PARAM(block_read);
    TEST_GET_BOOL_PARAM(half_empty);
    TEST_GET_BOOL_PARAM(write_before_fork);
    TEST_GET_BOOL_PARAM(kill_after_write);

    if (kill_after_write && (writer_child || !reader_child))
        TEST_FAIL("Incorrect test parameters");

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
        
    iov_len_read = rand_range(1, MAX_IOV_LEN);
    iov_len_write = rand_range(1, MAX_IOV_LEN);
    iut_pid = rpc_getpid(pco_iut);
    
    if (half_empty)
    {
        tx_vector = sockts_make_iovec_gen(&iov_len_write, &data_size_num,
                                          iov_len_write / 2);
        rx_vector = sockts_make_iovec_gen(&iov_len_read, &data_size_num,
                                          iov_len_read / 2);
    }
    else
    {
        tx_vector = sockts_make_iovec(&iov_len_write, &data_size_num);
        rx_vector = sockts_make_iovec(&iov_len_read, &data_size_num);
    }

    rpc_pipe(pco_iut, pipefds);
    write_end = pipefds[1];
    read_end = pipefds[0];

    if (write_before_fork)
    {
        rc = rpc_writev(pco_iut, write_end, tx_vector, iov_len_write);
        if (rc != (int)data_size_num)
            TEST_FAIL("RPC writev() on IUT does not write all data");
    }

    if (writer_child || reader_child)
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "child_proc", &pco_child));

    if (write_before_fork && kill_after_write)
    {
        rpc_kill(pco_child, iut_pid, RPC_SIGKILL);
        was_killed = TRUE;
    }

    if (block_read && (writer_child == reader_child ||
                       kill_after_write))
    {
        CHECK_RC(rcf_rpc_server_thread_create(reader_child ? pco_child :
                                                             pco_iut,
                                              "child_thread", &pco_aux));
        reader = pco_aux;
    }
    writer = (writer_child) ? pco_child : pco_iut;
    if (reader == NULL)
        reader = (reader_child) ? pco_child : pco_iut;

    if (writer_child != reader_child)
    {
        if (!was_killed)
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
        rc = rpc_readv(reader, read_end, rx_vector, iov_len_read);

        if (kill_after_write)
        {
            rc = rpc_writev(writer, write_end, tx_vector, iov_len_write);
            if (rc != (int)data_size_num)
                TEST_FAIL("RPC writev() on IUT does not write all data");
            rpc_kill(pco_child, iut_pid, RPC_SIGKILL);
            was_killed = TRUE;
        }
        else
        {
            writer->op = RCF_RPC_CALL;
            rpc_writev(writer, write_end, tx_vector, iov_len_write);
        }

        reader->op = RCF_RPC_WAIT;
        test_readv_loop(reader, read_end, rx_vector, iov_len_read,
                        data_size_num);
        if (!kill_after_write)
        {
            writer->op = RCF_RPC_WAIT;
            rc = rpc_writev(writer, write_end, tx_vector, iov_len_write);
            if (rc != (int)data_size_num)
                TEST_FAIL("RPC writev() on IUT does not write all data");
        }
    }
    else
    {
        if (!write_before_fork)
        {
            if (!kill_after_write && writer != reader)
            {
                writer->op = RCF_RPC_CALL;
                rpc_writev(writer, write_end, tx_vector, iov_len_write);
            }
            else
            {
                rc = rpc_writev(writer, write_end, tx_vector, iov_len_write);
                if (rc != (int)data_size_num)
                    TEST_FAIL("RPC writev() on IUT does not write all data");
            }

            if (kill_after_write)
            {
                rpc_kill(pco_child, iut_pid, RPC_SIGKILL);
                was_killed = TRUE;
            }
        }

        test_readv_loop(reader, read_end, rx_vector, iov_len_read,
                        data_size_num);

        if (!write_before_fork && !kill_after_write && writer != reader)
        {
            writer->op = RCF_RPC_WAIT;
            rc = rpc_writev(writer, write_end, tx_vector, iov_len_write);
            if (rc != (int)data_size_num)
                TEST_FAIL("RPC writev() on IUT does not write all data");
        }
    }

    if (rpc_iovec_cmp(data_size_num, tx_vector, iov_len_write,
                      data_size_num, rx_vector, iov_len_read) != 0)
        TEST_VERDICT("Recieved data is not the same as sent one");

    TEST_SUCCESS;

cleanup:

    if (writer_child != reader_child)
    {
        if (!was_killed)
            CLEANUP_RPC_CLOSE(writer, pipefds[0]);
        CLEANUP_RPC_CLOSE(reader, pipefds[1]);
    }
    else if (writer_child)
    {
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
    }

    if (writer_child || reader_child)
    {
        if (!was_killed)
            CLEANUP_RPC_CLOSE(writer, write_end);
        CLEANUP_RPC_CLOSE(reader, read_end);
    }

    if (was_killed)
    {
        rcf_rpc_server_finished(pco_iut);
        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }

    if (pco_aux != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));
    rcf_rpc_server_destroy(pco_child);

    sockts_free_iovecs(tx_vector, iov_len_write);
    sockts_free_iovecs(rx_vector, iov_len_read);

    TEST_END;
}
