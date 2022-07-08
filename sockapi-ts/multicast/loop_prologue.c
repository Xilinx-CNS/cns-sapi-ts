/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 * Multicast send
 * 
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *
 * $Id$
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "multicast/loop_prologue"

#include "sockapi-test.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    te_bool         force_loop;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(force_loop);

    CHECK_RC(tapi_sh_env_save_set(pco_iut, "EF_FORCE_SEND_MULTICAST", NULL,
                                  NULL, force_loop ? "1" : "0", FALSE));

    sockts_recreate_onload_stack(pco_iut);
    rcf_rpc_server_restart(pco_iut);

    if (tapi_onload_run())
    {
        /* Fix to scalable filters testing */
        sockts_kill_zombie_stacks(pco_iut);
        SLEEP(5);
    }

    TEST_SUCCESS;
cleanup:
    TEST_END;
}
