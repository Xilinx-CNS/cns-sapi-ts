/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 * UDP tests
 * 
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 *
 * $Id$
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "udp/epilogue"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    
    
    rc = cfg_del_instance_fmt(FALSE, "/agent:%s/env:EF_UDP_NETMASK", 
                              pco_iut->ta);

    if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_ENOENT)
        TEST_FAIL("Failed to delete EF_UDP_NETMASK");

    if (rcf_rpc_server_restart(pco_iut) != 0)
        TEST_FAIL("Failed to restart pco_iut");
    
    TEST_SUCCESS;

cleanup:

    TEST_END;
}

