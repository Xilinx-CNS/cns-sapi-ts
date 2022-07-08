/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-fcntl_getfl_pipe fcntl(F_GETFL) conformance for pipe
 *
 * @objective Check that @b fcntl(F_GETFL) returns correct flags for pipe
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 *
 * @par Test sequence:
 * -# Create pipe on @p pco_iut.
 * -# Call @b fcntl(F_GETFL). Check the flags it returns.
 * -# Send some data through the pipe.
 * -# Chack the flags again.
 * -# Issue verdicts.
 * -# Close pipe.
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#include "sockapi-test.h"
#include "fcntl_getfl_lib.h"

#define TE_TEST_NAME  "fcntl/fcntl_getfl"

int
main(int argc, char *argv[])
{

    rcf_rpc_server        *pco_iut = NULL;

    int                    pipefd[2];

    TEST_START;

    TEST_GET_PCO(pco_iut);

    rpc_pipe(pco_iut, pipefd);

    FCNTL_GETFL_TEST_FLAGS(pco_iut, pipefd[1], RPC_O_WRONLY);
    FCNTL_GETFL_TEST_FLAGS(pco_iut, pipefd[0], 0);
    rpc_write(pco_iut, pipefd[1], "1", sizeof("1"));
    FCNTL_GETFL_TEST_FLAGS(pco_iut, pipefd[1], RPC_O_WRONLY);
    FCNTL_GETFL_TEST_FLAGS(pco_iut, pipefd[0], 0);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, pipefd[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefd[1]);

    TEST_END;
}
