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
#define TE_TEST_NAME    "multicast/loop_epilogue"

#include "sockapi-test.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);

    tapi_no_reuse_pco_disable_once();

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
