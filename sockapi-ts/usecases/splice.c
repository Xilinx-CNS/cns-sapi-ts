/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-splice The splice() operation on BSD compatible sockets
 *
 * @objective Test on reliability of @b splice() operation
 *            on BSD compatible sockets.
 *
 * @type use case
 *
 * @param env                   Private set of environments which iterates
 *                              various combinations of spliced connections:
 *                              Onload accelerated, non-accelerated, loopback,
 *                              using or not SFC interface.
 * @param splice_before_data    Whether to call splice before sending data
 *                              from peer socket or not.
 * @param set_move              Whether to call splice with @c SPLICE_F_MOVE
 *                              flag or not.
 * @param set_nonblock          Whether to call splice with
 *                              @c SPLICE_F_NONBLOCK flag or not.
 * @param extra_pipes           Number of extra pipes to which test passes the
 *                              data via splice. I.e. we send data to the
 *                              write end of the first pipe, then read it from
 *                              read end and send to the second pipe. \n
                                Values:
 *                              - 0
 *                              - 5
 * @param overfill_pipe         Whether test should overfill first pipe or not.
 * @param acc_pipe              Whether pipe in test should be accelerated or
 *                              not.
 * @param diff_stacks           Whether test should use many stacks or not.
 * @param pipe_size             Create extra pipes according to this variable.
 *                              It could be reduce, increase, large or certain
 *                              value. \n
                                Values:
 *                              - unchanged
 *                              - reduce: the size of next pipe should be lesser then previous;
 *                              - increase: bigger then previous;
 *                              - large: 1024 * 1024;
 *                              - 4096
 *                              - 8192
 * @param use_fcntl             Whether set pipe size using fcntl or not.
 * @param sock_type             Socket type.
 *                              Value:
 *                              - @c SOCK_STREAM
 *                              - @c SOCK_DGRAM
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/splice"

#include "sockapi-test.h"
#include "extensions.h"

#define MAX_PIPES 10

#define CHECK_DATA(_buf, _buf_len, _got_buf, _got_buf_len) \
do {                                             \
    if (_got_buf_len != _buf_len)                \
        TEST_FAIL("Only part of data received"); \
    if (memcmp(_buf, _got_buf, _buf_len))        \
            TEST_FAIL("Invalid data received");  \
} while(0);

#define MAX_BUFF_SIZE 10240

#define SET_PIPE_SIZE(_pco, _pipe_fd, _size) \
do {                                                            \
    int old_size;                                               \
    if (strcmp(_size, "unchanged") != 0 && use_fcntl)           \
    {                                                           \
        old_size = rpc_fcntl(_pco, _pipe_fd, RPC_F_GETPIPE_SZ); \
        if (strcmp(_size, "reduce") == 0)                       \
            old_size /= 2;                                      \
        else if (strcmp(_size, "increase") == 0)                \
            old_size *= 2;                                      \
        else if (strcmp(_size, "large") == 0)                   \
            old_size = 1024 * 1024;                             \
        else                                                    \
            TEST_FAIL("Incorrect pipe size");                   \
        rpc_fcntl(_pco, _pipe_fd, RPC_F_SETPIPE_SZ, old_size);  \
    }                                                           \
} while(0);

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_aux = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    int             tst_s1 = -1;
    int             tst_s2 = -1;
    int             iut_s1 = -1;
    int             iut_s2 = -1;
    void           *tx_buf = NULL;
    size_t          tx_buf_len;
    void           *rx_buf = NULL;
    size_t          rx_buf_len;
    uint64_t        total_bytes;
    unsigned char   buffer[MAX_BUFF_SIZE];

    const struct sockaddr  *iut_addr1;
    const struct sockaddr  *iut_addr2;
    const struct sockaddr  *tst1_addr;
    const struct sockaddr  *tst2_addr;

    int             extra_pipes = 0;
    te_bool         check_after_splice = FALSE;
    te_bool         splice_before_data = FALSE;
    te_bool         overfill_pipe = FALSE;
    int             fds[MAX_PIPES][2];
    te_bool         set_move = FALSE;
    te_bool         set_nonblock = FALSE;
    int             flags = 0;
    te_bool         acc_pipe = TRUE;
    te_bool         diff_stacks = FALSE;
    te_bool         use_fcntl = FALSE;
    const char     *pipe_size;
    char           *old_pipe_size = NULL;
    cfg_handle     ef_pipe_size_h = CFG_HANDLE_INVALID;

    rpc_socket_type sock_type;

    int i;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_INT_PARAM(extra_pipes);
    TEST_GET_BOOL_PARAM(check_after_splice);
    TEST_GET_BOOL_PARAM(splice_before_data);
    TEST_GET_BOOL_PARAM(overfill_pipe);
    TEST_GET_BOOL_PARAM(set_move);
    TEST_GET_BOOL_PARAM(set_nonblock);
    TEST_GET_BOOL_PARAM(acc_pipe);
    TEST_GET_BOOL_PARAM(diff_stacks);
    TEST_GET_BOOL_PARAM(use_fcntl);
    TEST_GET_STRING_PARAM(pipe_size);
    TEST_GET_SOCK_TYPE(sock_type);

    if (strcmp(pipe_size, "unchanged") != 0 && !use_fcntl)
        ef_pipe_size_h = sockts_set_env_gen(pco_iut, "EF_PIPE_SIZE",
                                            pipe_size, &old_pipe_size,
                                            acc_pipe);

    TEST_STEP("Disable pipe acceleration on @p pco_iut according to "
              "@p acc_pipe parameter");
    if (!acc_pipe)
        CHECK_RC(tapi_sh_env_set(pco_iut, "EF_PIPE", "0", TRUE, TRUE));

    if (overfill_pipe)
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "iut_thread",
                                              &pco_aux));

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);
    flags = set_move ? RPC_SPLICE_F_MOVE : 0;
    if (set_nonblock)
        flags |= RPC_SPLICE_F_NONBLOCK;

    TEST_STEP("Generate connection between @p pco_iut and @p pco_tst1: @p iut_s1 "
              "and @p tst_s1 sockets according to @p sock_type");
    GEN_CONNECTION(pco_tst1, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst1_addr, iut_addr1, &tst_s1, &iut_s1);
    TEST_STEP("Change stack according to @p diff_stacks parameter");
    if (diff_stacks)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, "test1");
    TEST_STEP("Generate connection between @p pco_iut and @p pco_tst2: @p iut_s2 "
              "and @p tst_s2 sockets according to @p sock_type");
    GEN_CONNECTION(pco_tst2, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst2_addr, iut_addr2, &tst_s2, &iut_s2);
    for (i = 0; i < extra_pipes + 1; i++)
        fds[i][0] = fds[i][1] = -1;
    if (diff_stacks)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, "test2");
    TEST_STEP("Create a number of pipes according to @p extra_pipes parameter");
    for (i = 0; i < extra_pipes + 1; i++)
    {
        rpc_pipe(pco_iut, fds[i]);
        SET_PIPE_SIZE(pco_iut, fds[i][0], pipe_size);
    }

    TEST_STEP("Overfill pipe according to @p overfill_pipe parameter");
    if (overfill_pipe)
        rpc_overfill_fd(pco_iut, fds[0][1], &total_bytes);

    TEST_STEP("Call @b splice() with @p iut_s1 socket and with write end of the "
              "first pipe");
    if (splice_before_data)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_splice(pco_iut, iut_s1, NULL,
                   fds[0][1], NULL, tx_buf_len, flags);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Send some data from @p pco_tst1 to @p pco_iut");
    RPC_SEND(rc, pco_tst1, tst_s1, tx_buf, tx_buf_len, 0);

    TEST_STEP("Send the data from one pipe to the next one @p extra_pipes times");
    for (i = 0; i < extra_pipes + 1; i++)
    {
        if (i == 0 && overfill_pipe)
        {
            if (!splice_before_data)
            {
                pco_iut->op = RCF_RPC_CALL;
                rpc_splice(pco_iut, iut_s1, NULL,
                           fds[0][1], NULL, tx_buf_len, flags);
                TAPI_WAIT_NETWORK;
            }
            if (set_nonblock)
            {
                RPC_AWAIT_IUT_ERROR(pco_iut);
                pco_iut->op = RCF_RPC_WAIT;
                rc = rpc_splice(pco_iut, iut_s1, NULL,
                                fds[0][1], NULL, tx_buf_len, flags);
                if (rc != -1)
                    TEST_VERDICT("splice() with SPLICE_F_NONBLOCK flags "
                                 "returned %d on overfilled pipe", rc);
                CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                                "splice() with SPLICE_F_NONBLOCK flags "
                                "returned -1");
            }
            do {
                rc = rpc_read(pco_aux, fds[0][0],
                              buffer,
                              (total_bytes > MAX_BUFF_SIZE) ?
                                MAX_BUFF_SIZE : total_bytes);
                total_bytes -= rc;
            } while (total_bytes != 0);
        }
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_splice(pco_iut, (i == 0) ? iut_s1 : fds[i - 1][0], NULL,
                        fds[i][1], NULL, tx_buf_len, flags);
        if (rc < 0)
        {
            TEST_VERDICT("Correct splice() call with first IUT socket "
                         "unexpectedly failed with errno %r",
                         RPC_ERRNO(pco_iut));
        }
    }

    TEST_STEP("Read all data from the last pipe and check that it is correct "
              "if @p check_after_splice is @c TRUE");
    if (check_after_splice)
    {
        rc = rpc_read(pco_iut, fds[extra_pipes][0], rx_buf, rx_buf_len);
        CHECK_DATA(tx_buf, rc, rx_buf, (int)tx_buf_len);

        TEST_SUCCESS;
    }

    TEST_STEP("Call @b splice() with @p iut_s2 socket and with read end of the "
              "last pipe pipe");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_splice(pco_iut, fds[extra_pipes][0], NULL,
                    iut_s2, NULL, tx_buf_len, flags);
    if (rc < 0)
    {
        TEST_VERDICT("Correct splice() call with second IUT socket "
                     "unexpectedly failed with errno %r",
                     RPC_ERRNO(pco_iut));
    }
    TEST_STEP("Read all data from @p tst_s2 socket and check that it is correct "
              "if @p check_after_splice is @c TRUE");
    rc = rpc_recv(pco_tst2, tst_s2, rx_buf, rx_buf_len, 0);
    CHECK_DATA(tx_buf, rc, rx_buf, (int)tx_buf_len);

    TEST_SUCCESS;

cleanup:
    /* Closing order matters: avoid TIME_WAIT on IUT side */
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    for (i = 0; i < extra_pipes + 1; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, fds[i][0]);
        CLEANUP_RPC_CLOSE(pco_iut, fds[i][1]);
    }
    free(tx_buf);
    free(rx_buf);

    if (pco_aux)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));

    CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_pipe_size_h,
                                            old_pipe_size, acc_pipe));
    if (!acc_pipe)
        CHECK_RC(tapi_sh_env_set(pco_iut, "EF_PIPE", "1", TRUE, TRUE));

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
