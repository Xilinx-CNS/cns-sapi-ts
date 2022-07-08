/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "performance/epilogue"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut;
    rcf_rpc_server *pco_tst;

    te_string   cmd = (te_string)TE_STRING_INIT;
    tarpc_pid_t pid;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    CHECK_RC(te_string_append(&cmd, "pkill -f netserver"));

    if ((pid = rpc_te_shell_cmd(pco_tst, cmd.ptr, -1, NULL, NULL, NULL)) < 0)
        ERROR("Failed to kill netserver: %s", cmd);


    TEST_SUCCESS;

cleanup:
    te_string_free(&cmd);
    TEST_END;

}
