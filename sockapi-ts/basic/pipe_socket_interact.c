/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page basic-pipe_socket_interact Opening and closing sockets and pipes
 *
 * @objective Check that creating and closing sockets and pipes do not
 *            cause any crashes.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 * @param open_pipe1    Pipes number to create at the first step.
 * @param open_sock1    Sockets number to create at the first step.
 * @param open_pipe2    Pipes number to create at the second step.
 * @param close_sock    Sockets number to close after creation.
 * @param close_pipe    Pipes number to close after sockets closing.
 * @param open_sock2    Sockets number to create at the third step.
 * @param open_pipe3    Pipes number to create at the third step.
 *
 * @par Scenario:
 *
 * -# Create @p open_pipe1 number of pipes;
 * -# Create @p open_sock1 number of sockets of randomly chosen type;
 * -# Create @p open_pipe2 number of pipes;
 * -# Overfill buffers in all created pipes;
 * -# Set non-blocking mode on all created sockets;
 * -# Close @p close_sock number of sockets;
 * -# Close @p close_pipe number od pipes;
 * -# Create @p open_sock2 number of sockets;
 * -# Create @p open_pipe3 number of pipes;
 * -# Overfill buffers in all new pipes;
 * -# Set non-blocking mode on all new sockets;
 * -# Read data from all pipes.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/pipe_socket_interact"

#include "sockapi-test.h"

#define MAX_PIPES_SOCK 30
#define GARBAGE_STRING "BEEFBEEFBEEFBEEF"
#define MAX_BUF_LEN 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    int                 pipefds[MAX_PIPES_SOCK][2];
    int                 sock[MAX_PIPES_SOCK];
    int                 buf[MAX_BUF_LEN];

    int         open_pipe1;
    int         open_sock1;
    int         open_pipe2;

    int         close_pipe;
    int         close_sock;

    int         open_sock2;
    int         open_pipe3;

    int i;
    int j;

    rpc_send_f          send_f;
    rpc_recv_f          recv_f;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(open_pipe1);
    TEST_GET_INT_PARAM(open_pipe2);
    TEST_GET_INT_PARAM(open_pipe3);
    TEST_GET_INT_PARAM(close_pipe);
    TEST_GET_INT_PARAM(open_sock1);
    TEST_GET_INT_PARAM(open_sock2);
    TEST_GET_INT_PARAM(close_sock);
    TEST_GET_SEND_FUNC(send_f);
    TEST_GET_RECV_FUNC(recv_f);

    for (i = 0; i < MAX_PIPES_SOCK; i++)
    {
        pipefds[i][0] = -1;
        pipefds[i][1] = -1;
        sock[i] = -1;
    }

    for (i = 0; i < open_pipe1; i++)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_pipe(pco_iut, pipefds[i]);
        if (rc < 0)
            TEST_VERDICT("Creation of pipe number %d failed: %s",
                         i, errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    
    for (i = 0; i < open_sock1; i++)
    {
        sock[i] =
            rpc_socket(pco_iut, RPC_PF_INET,
                       (rand_range(0, 1) == 0) ? RPC_SOCK_STREAM :
                                                 RPC_SOCK_DGRAM,
                       RPC_PROTO_DEF);
    }

    for (i = open_pipe1; i < open_pipe2 + open_pipe1; i++)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_pipe(pco_iut, pipefds[i]);
        if (rc < 0)
            TEST_VERDICT("Creation of pipe number %d failed: %s",
                         i, errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    for (i = 0; i < open_pipe2 + open_pipe1; i++)
        rpc_overfill_fd(pco_iut, pipefds[i][1], NULL);

    for (i = 0; i < open_sock1; i++)
        rpc_fcntl(pco_iut, sock[i], RPC_F_SETFL, RPC_O_NONBLOCK);

    for (i = 0; i < close_sock; i++)
    {
        for (j = rand_range(0, open_sock1); sock[j] == -1;
             j = rand_range(0, open_sock1));
        RPC_CLOSE(pco_iut, sock[j]);
    }

    for (i = 0; i < close_pipe; i++)
    {
        for (j = rand_range(0, open_pipe1 + open_pipe2);
             pipefds[j][0] == -1;
             j = rand_range(0, open_pipe1 + open_pipe2));

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_close(pco_iut, pipefds[j][0]);
        pipefds[j][0] = -1;
        if (rc < 0)
            TEST_VERDICT("Closing of read end of pipe number %d "
                         "failed: %s",
                         j, errno_rpc2str(RPC_ERRNO(pco_iut)));
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_close(pco_iut, pipefds[j][1]);
        pipefds[j][1] = -1;
        if (rc < 0)
            TEST_VERDICT("Closing of write end of pipe number %d "
                         "failed: %s",
                         j, errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    for (i = open_sock1; i < open_sock1 + open_sock2; i++)
    {
        sock[i] =
            rpc_socket(pco_iut, RPC_PF_INET,
                       (rand_range(0, 1) == 0) ? RPC_SOCK_STREAM :
                                                 RPC_SOCK_DGRAM,
                       RPC_PROTO_DEF);
    }

    for (i = open_pipe2 + open_pipe1; i < open_pipe3 + open_pipe2 +
                                          open_pipe1; i++)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_pipe(pco_iut, pipefds[i]);
        if (rc < 0)
            TEST_VERDICT("Creation of pipe number %d failed: %s",
                         i, errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    for (i = open_pipe2 + open_pipe1; i < open_pipe3 + open_pipe2 +
                                          open_pipe1; i++)
        rpc_overfill_fd(pco_iut, pipefds[i][1], NULL);

    for (i = open_sock1; i < open_sock2 + open_sock1; i++)
        rpc_fcntl(pco_iut, sock[i], RPC_F_SETFL, RPC_O_NONBLOCK);

    for (i = 0; i < open_pipe3 + open_pipe2 + open_pipe1; i++)
    {
        if (pipefds[i][0] == -1)
            continue;
        rpc_fcntl(pco_iut, pipefds[i][0], RPC_F_SETFL, RPC_O_NONBLOCK);
        do {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = recv_f(pco_iut, pipefds[i][0], buf, MAX_BUF_LEN, 0);
        } while (rc > 0);
        if (rc != -1)
            TEST_FAIL("Non-blocking %s() returns %d instead of -1",
                      rpc_recv_func_name(recv_f), rc);
        else
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                            "Non-blocking %s() fails, but",
                            rpc_recv_func_name(recv_f));
    }

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < open_pipe3 + open_pipe2 + open_pipe1; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[i][0]);
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[i][1]);
    }
    for (i = 0; i < open_sock2 + open_sock1; i++)
        CLEANUP_RPC_CLOSE(pco_iut, sock[i]);

    TEST_END;
}
