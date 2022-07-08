/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/**
 * @page sendrecv-largebuff_via_splice test splice() with large buffer size
 *
 * @objective Check sending/receiving large amount of data via a socket
 *            with splice().
 *
 * @param buff_size          Buffer size:
 *      - 0x00020000
 * @param splice_from_socket If @c TRUE, splice from socket, else splice to
 *                           socket:
 *      - TRUE
 *      - FALSE
 * @param f_more_flag        If @c TRUE, we use F_MORE flag in splice call:
 *      - TRUE
 *      - FALSE
 *
 * @par Scenario:
 *
 * @author Anton Protasov <Anton.Protasov@oktetlabs.ru>
 */

#define TE_TEST_NAME "sendrecv/largebuff_via_splice"

#include "sockapi-test.h"

/* Max loop counter, show verdict if equal */
#define LOOP_COUNT 16

/**
 * Splice data and read
 *
 * @param pco_iut           IUT server
 * @param read_srv          Read server
 * @param fd_in             Input desriptor
 * @param fd_out            Output desriptor
 * @param fd_read           Read desriptor
 * @param rx_buff           Receive buffer
 * @param buff_size         Sended buffer size
 *
 * @return Total bytes send.
 */
static size_t
splice_read_data(rcf_rpc_server *pco_iut, rcf_rpc_server *read_srv,
                 int fd_in, int fd_out, int fd_read,
                 char *rx_buff, size_t buff_size, uint32_t flags)
{

    size_t  total_bytes_sent = 0;
    size_t  total_bytes = 0;
    ssize_t  bytes_sent = 0;
    int     rc;
    int     loop_count = 0;

    while (total_bytes_sent < buff_size)
    {
        RPC_AWAIT_ERROR(pco_iut);
        bytes_sent = rpc_splice(
                         pco_iut, fd_in, NULL,
                         fd_out, NULL,
                         buff_size - total_bytes_sent,
                         flags | RPC_SPLICE_F_NONBLOCK);
        if (bytes_sent < 0)
        {
            /*
             * If splice() is blocked, read half of sent data
             * from the descriptor to free some space.
             */
            if (RPC_ERRNO(pco_iut) == RPC_EAGAIN)
            {
                rc = rpc_read(read_srv, fd_read, rx_buff + total_bytes,
                              (total_bytes_sent - total_bytes) / 2);
                total_bytes += rc;
                continue;
            }
            else
            {
                TEST_VERDICT("splice() failed with errno %r",
                             RPC_ERRNO(pco_iut));
            }
        }
        total_bytes_sent += bytes_sent;
        loop_count++;
        if (loop_count == LOOP_COUNT)
            TEST_VERDICT("Too many calls of splice() were required");
    }
    do {
        rc = rpc_read(read_srv, fd_read, rx_buff + total_bytes,
                      total_bytes_sent - total_bytes);
        total_bytes += rc;
    } while (total_bytes < total_bytes_sent);
    return total_bytes;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    int                         iut_s = -1;
    int                         tst_s = -1;
    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;
    const struct if_nameindex  *iut_if = NULL;

    te_bool                     splice_from_socket;
    te_bool                     f_more_flag;
    size_t                      buff_size;
    char                       *tx_buff;
    char                       *rx_buff;
    cfg_handle                  ef_pipe_size_h = CFG_HANDLE_INVALID;
    char                        pipe_size[50];
    char                       *old_pipe_size = NULL;
    int                         fds[2] = { -1, -1 };
    size_t                      total_bytes = 0;
    int                         fd_in = -1;
    int                         fd_out = -1;
    int                         fd_read = -1;
    rcf_rpc_server             *read_srv = NULL;
    uint32_t                    flags;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(splice_from_socket);
    TEST_GET_BOOL_PARAM(f_more_flag);
    TEST_GET_INT_PARAM(buff_size);

    TE_SPRINTF(pipe_size, "%ld", buff_size);

    ef_pipe_size_h = sockts_set_env_gen(pco_iut, "EF_PIPE_SIZE",
                                        pipe_size, &old_pipe_size,
                                        TRUE);

    TEST_STEP("Create large buffer with size @p buff_size");
    tx_buff = te_make_buf_by_len(buff_size);
    rx_buff = te_make_buf_by_len(buff_size);

    TEST_STEP("Create two TCP sockets");
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    rpc_pipe(pco_iut, fds);
    rc = rpc_fcntl(pco_iut, fds[0], RPC_F_SETPIPE_SZ, buff_size);
    rc = rpc_fcntl(pco_iut, fds[0], RPC_F_GETPIPE_SZ);
    if ((int)buff_size != rc)
    {
        if ((int)buff_size > rc)
        {
            if ((int)buff_size < 1.5 * rc)
                WARN("Amount of data in the pipe is a "
                     "little bit bigger then pipe size");
            if ((int)buff_size >= 1.5 * rc)
                TEST_VERDICT("Amount of data in the pipe is much "
                             "bigger then pipe size");
        }
        else
        {
            if ((int)buff_size > 0.8 * rc)
                WARN("Amount of data in the pipe is a "
                     "little bit smaller then pipe size");
            if ((int)buff_size < 0.8 * rc)
                TEST_VERDICT("Amount of data in the pipe is much "
                             "smaller then pipe size");
        }
    }

    if (f_more_flag)
        flags = RPC_SPLICE_F_MORE;
    else
        flags = 0;

    if (splice_from_socket)
    {
        TEST_STEP("If @p splice_from_socket = TRUE: Send buff "
                  "with @p buff_size from socket via splice");

        RPC_WRITE(rc, pco_tst, tst_s, tx_buff, buff_size);
        fd_in = iut_s;
        fd_out = fds[1];
        fd_read = fds[0];
        read_srv = pco_iut;
    }
    else
    {
        TEST_STEP("If @p splice_from_socket = FALSE: Send buff "
                  "with @p buff_size to socket via splice");

        RPC_WRITE(rc, pco_iut, fds[1], tx_buff, buff_size);
        fd_in = fds[0];
        fd_out = iut_s;
        fd_read = tst_s;
        read_srv = pco_tst;
    }

    TAPI_WAIT_NETWORK;
    total_bytes = splice_read_data(pco_iut, read_srv, fd_in, fd_out,
                                   fd_read, rx_buff, buff_size, flags);

    TEST_STEP("Check buff");
    if (total_bytes < buff_size)
        TEST_VERDICT("Only part of data received");
    if (total_bytes > buff_size || memcmp(tx_buff, rx_buff, total_bytes))
        TEST_VERDICT("Invalid data received");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, fds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, fds[1]);

    CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_pipe_size_h,
                                            old_pipe_size, TRUE));

    free(tx_buff);
    free(rx_buff);

    TEST_END;
}
