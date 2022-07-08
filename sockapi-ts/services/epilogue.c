/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 *
 * $Id$
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "services/epilogue"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "services.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);

    CHECK_RC(tapi_sh_env_set(pco_iut, "EF_PIPE", "1", TRUE, TRUE));

#ifdef VIA_CS
    cfg_del_instance_fmt(FALSE, "/agent:%s/env:LD_PRELOAD", pco_iut->ta);
#else
    rcf_ta_set_var(pco_iut->ta, 0, "LD_PRELOAD", RCF_STRING, "");
#endif    
    
    rcf_rpc_server_restart(pco_iut);
    
    TEST_SUCCESS;

cleanup:

    TEST_END;
}

