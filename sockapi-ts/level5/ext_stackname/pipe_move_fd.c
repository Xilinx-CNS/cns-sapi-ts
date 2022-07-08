/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-pipe_move_fd Call @b onload_move_fd() on a pipe fd
 *
 * @objective Check that if we call @b onload_move_fd() on a pipe fd,
 *            it fails and pipe still works OK.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param read_end             Whether we should to call
 *                             @b onload_move_fd() on a read or a write
 *                             end of pipe
 * @param system_fd            Whether we should to call
 *                             @b onload_move_fd() on an Onload pipe fd
 *                             or system one
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/pipe_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME "foo"
#define DATA_SIZE 256

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_child = NULL;
    te_bool                 read_end = FALSE;
    te_bool                 system_fd = FALSE;

    int                     pipe_fds[2] = { -1, -1};
    int                     read_fd;
    int                     write_fd;

    char                    write_buf[DATA_SIZE];
    char                    read_buf[DATA_SIZE];

    te_bool                 test_failed = FALSE;
    te_bool                 restore_stack_name = FALSE;
    char                   *init_stack_name;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(read_end);
    TEST_GET_BOOL_PARAM(system_fd);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Create a pipe with read or write end (depending on @p read_end) "
              "opened in @p pco_iut and another in @p pco_iut_child obtained with "
              "@b fork().");
    if (system_fd)
        pco_iut->use_libc_once = TRUE;
    rpc_pipe(pco_iut, pipe_fds);
    read_fd = pipe_fds[0];
    write_fd = pipe_fds[1];

    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_child",
                                 &pco_iut_child));
    if (read_end)
    {
        rpc_close(pco_iut, write_fd);
        rpc_close(pco_iut_child, read_fd);
    }
    else
    {
        rpc_close(pco_iut, read_fd);
        rpc_close(pco_iut_child, write_fd);
    }

    TEST_STEP("Send some data through the pipe.");
    te_fill_buf(write_buf, DATA_SIZE);
    rpc_write(read_end ? pco_iut_child : pco_iut,
              write_fd, write_buf, DATA_SIZE);

    TEST_STEP("Try to move a pipe end (selected according to @p read_end) "
              "to a new stack; check that it fails.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                         FALSE, NULL);

    restore_stack_name = TRUE;

    if (!tapi_rpc_onload_move_fd_check(
                            pco_iut, read_end ? read_fd : write_fd,
                            TAPI_MOVE_FD_FAILURE_EXPECTED, STACK_NAME,
                            "Calling onload_move_fd() on a pipe fd"))
        test_failed = TRUE;

    TEST_STEP("Check that data sent can be succesfully read from a pipe.");
    if (rpc_read(read_end ? pco_iut : pco_iut_child,
                 read_fd, read_buf, DATA_SIZE) != DATA_SIZE ||
        memcmp(read_buf, write_buf, DATA_SIZE) != 0)
        TEST_VERDICT("Data sent through pipe was corrupted");

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;
cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, read_end ? read_fd : write_fd);
    CLEANUP_RPC_CLOSE(pco_iut_child, read_end ? write_fd : read_fd);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_child));

    TEST_END;
}
