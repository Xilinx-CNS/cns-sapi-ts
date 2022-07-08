/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "basic/vfork_epilogue"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    cfg_handle      handle;

    TEST_START;

    TEST_GET_PCO(pco_iut);

    CHECK_RC(cfg_find_fmt(&handle, "/agent:%s/env:EF_VFORK_MODE", 
                          pco_iut->ta));
    CHECK_RC(cfg_del_instance(handle, 1));

    rcf_rpc_server_restart(pco_iut);

    TEST_SUCCESS;
cleanup:
    TEST_END;
}
