/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/**
 * @page basic-pipe_via_af_unix Pass a pipe FD between proccesses via AF_UNIX socket and read/write data using it.
 *
 * @objective Check that the read/write functions work with pipe FD
 *            received from another process via AF_UNIX
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_iut_only
 * @param is_read   If @c TRUE read from the pipe from the child process
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "basic/pipe_via_af_unix"

#include "sockapi-test.h"

#define BUFFER_SIZE 256

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    te_bool is_read;

    int iut2_fd = -1;
    int pipefds[2] = { -1, -1 };
    int write_end;
    int read_end;

    char tx_buf[BUFFER_SIZE];
    char rx_buf[BUFFER_SIZE];

    rcf_rpc_server *pco_sndr = NULL;
    rcf_rpc_server *pco_rcvr = NULL;
    int rcvr_fd;
    int sndr_fd;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(is_read);

    te_fill_buf(tx_buf, BUFFER_SIZE);

    TEST_STEP("Create a new @p pco_iut2 process on IUT");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut2", &pco_iut2));

    TEST_STEP("On @p pco_iut create a pipe");
    rpc_pipe(pco_iut, pipefds);
    write_end = pipefds[1];
    read_end = pipefds[0];

    TEST_STEP("Pass read or write end of the pipe from @p pco_iut to "
              "@p pco_iut2, depending on @p is_read parameter");
    iut2_fd = sockts_share_socket_2proc(pco_iut, pco_iut2,
                                        (is_read) ? read_end : write_end);

    TEST_STEP("Write some data to the write end of the pipe. If @p is_read is "
              "@c FALSE, do it on @p pco_iut2");
    if (is_read)
    {
        pco_rcvr = pco_iut2;
        pco_sndr = pco_iut;
        rcvr_fd = iut2_fd;
        sndr_fd = write_end;
    }
    else
    {
        pco_rcvr = pco_iut;
        pco_sndr = pco_iut2;
        rcvr_fd = read_end;
        sndr_fd = iut2_fd;
    }

    rpc_write(pco_sndr, sndr_fd, tx_buf, BUFFER_SIZE);
    TEST_STEP("Read data from the read end of pipe. If @p is_read is @c TRUE, "
              "do it on @p pco_iut2.");
    rc = rpc_read(pco_rcvr, rcvr_fd, rx_buf, BUFFER_SIZE);

    TEST_STEP("Check that data was received correctly");
    SOCKTS_CHECK_RECV(pco_rcvr, tx_buf, rx_buf, BUFFER_SIZE, rc);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, write_end);
    CLEANUP_RPC_CLOSE(pco_iut, read_end);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_fd);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut2));

    TEST_END;
}
