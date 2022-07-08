/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "basic/vfork_prologue"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             vfork_mode;
    cfg_handle      handle;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(vfork_mode);

    CHECK_RC(cfg_add_instance_fmt(&handle, 
                                  CFG_VAL(STRING,
                                          (vfork_mode == 0) ? "0" :
                                            (vfork_mode == 1) ? "1": "2"),
                                  "/agent:%s/env:EF_VFORK_MODE",
                                  pco_iut->ta));

    /* EF_VFORK_MODE is library-only setting.
     * Restart RPC server - re-init the library. */
    rcf_rpc_server_restart(pco_iut);

    TEST_SUCCESS;
cleanup:
    TEST_END;
}
