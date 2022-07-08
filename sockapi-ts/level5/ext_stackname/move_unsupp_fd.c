/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-move_unsupp_fd Call @b onload_move_fd() on an unsupported fd
 *
 * @objective Check that calling @b onload_move_fd() fails when called on
 *            device fd or file fd
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param fd_type              Type of fd to be tested (file, /dev/null,
 *                             etc)
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/move_unsupp_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#define STACK_NAME "foo"

typedef enum {
    FD_UNKNOWN = 0,
    FD_DEV_NULL,
    FD_DEV_ZERO,
    FD_STDIN,
    FD_STDOUT,
    FD_STDERR,
    FD_TMPFILE, 
} fd_type;

#define FD_TYPE \
    { "dev_null", FD_DEV_NULL }, \
    { "dev_zero", FD_DEV_ZERO }, \
    { "stdin", FD_STDIN }, \
    { "stdout", FD_STDOUT }, \
    { "stderr", FD_STDERR }, \
    { "tmpfile", FD_TMPFILE }

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             fd_type = FD_UNKNOWN;
    int             fd;
    int             rc2;
    char            tmp_file_name[100];
    te_bool         test_failed = FALSE;
    te_bool         restore_stack_name = FALSE;
    char           *init_stack_name;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ENUM_PARAM(fd_type, FD_TYPE);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Create a fd of type specified by @p fd_type.");
    switch (fd_type)
    {
        case FD_DEV_NULL:
            fd = rpc_open(pco_iut, "/dev/null",
                          RPC_O_WRONLY, 0);
            break;

        case FD_DEV_ZERO:
            fd = rpc_open(pco_iut, "/dev/zero",
                          RPC_O_RDONLY, 0);
            break;

        case FD_STDIN:
            fd = RPC_STDIN_FILENO;
            break;

        case FD_STDOUT:
            fd = RPC_STDOUT_FILENO;
            break;

        case FD_STDERR:
            fd = RPC_STDERR_FILENO;
            break;

        case FD_TMPFILE:
            snprintf(tmp_file_name, sizeof(tmp_file_name), 
                     "/tmp/te_tmp_file_%d_%d", 
                     rpc_getpid(pco_iut), rand_range(0, 100000));
            fd = rpc_open(pco_iut, tmp_file_name,
                          RPC_O_RDWR | RPC_O_CREAT, RPC_S_IRWXU);
            break;

        default:
            TEST_VERDICT("Unknown fd type");
    }

    TEST_STEP("Try to move the created fd to a new stack; check that it fails.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                         FALSE, NULL);

    restore_stack_name = TRUE;

    if (!tapi_rpc_onload_move_fd_check(
                                  pco_iut, fd,
                                  TAPI_MOVE_FD_FAILURE_EXPECTED, STACK_NAME,
                                  "Calling onload_move_fd() on an "
                                  "unsupported fd type"))
        test_failed = TRUE;

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    if (fd_type == FD_TMPFILE)
    {
        CLEANUP_CHECK_RC(rcf_ta_call(pco_iut->ta, 0, "ta_rtn_unlink",
                                     &rc2, 1, FALSE, RCF_STRING,
                                     tmp_file_name));
        if (rc2 != 0)
        {
            ERROR("Failed to unlink '%s'", tmp_file_name);
            result = EXIT_FAILURE;
        }
    }

    CLEANUP_RPC_CLOSE(pco_iut, fd);

    if (fd_type == FD_STDIN || fd_type == FD_STDOUT || fd_type == FD_STDERR)
        rcf_rpc_server_restart(pco_iut);

    TEST_END;
}
