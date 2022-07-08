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
#define TE_TEST_NAME    "udp/prologue"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    
    tapi_env_net   *net1 = NULL;
    tapi_env_net   *net2 = NULL;

    te_bool disable_tunnelling;

    cfg_handle handle;

    uint32_t mask;
    uint32_t ef_udp_netmask;
    char    *ef_udp_netmask_str = NULL;

    char buf[INET_ADDRSTRLEN] = {0,};

    TEST_START;

    TEST_GET_NET(net1);
    TEST_GET_NET(net2);

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    
    TEST_GET_BOOL_PARAM(disable_tunnelling);

    if (net1->ip4pfx != net2->ip4pfx)
        TEST_FAIL("Nets attached to IUT have different prefixes, exit");
    mask = htonl(PREFIX2MASK(net1->ip4pfx));
    ef_udp_netmask = (disable_tunnelling == TRUE) ? 0xffffffff :  mask;
    if ((ef_udp_netmask_str = 
         (char *)inet_ntop(AF_INET, &ef_udp_netmask, buf, INET_ADDRSTRLEN)) == NULL)
        TEST_FAIL("Failed to convert EF_UDP_NETMASK to string");

    /* IUT */
    if (cfg_find_fmt(&handle, "/agent:%s/env:EF_UDP_NETMASK", 
                     pco_iut->ta) != 0)
        rc = cfg_add_instance_fmt(&handle, CVT_STRING, 
                                  ef_udp_netmask_str,
                                  "/agent:%s/env:EF_UDP_NETMASK", 
                                  pco_iut->ta);
    else
        rc = cfg_set_instance(handle, CVT_STRING, ef_udp_netmask_str);
  
    /* Tester 1 */
    if (cfg_find_fmt(&handle, "/agent:%s/env:EF_UDP_NETMASK", 
                     pco_tst1->ta) != 0)
        rc = cfg_add_instance_fmt(&handle, CVT_STRING, 
                                  ef_udp_netmask_str,
                                  "/agent:%s/env:EF_UDP_NETMASK", 
                                  pco_tst1->ta);
    else
        rc = cfg_set_instance(handle, CVT_STRING, ef_udp_netmask_str);
 
    /* Tester 2 */
    if (cfg_find_fmt(&handle, "/agent:%s/env:EF_UDP_NETMASK", 
                     pco_tst2->ta) != 0)
        rc = cfg_add_instance_fmt(&handle, CVT_STRING, 
                                  ef_udp_netmask_str,
                                  "/agent:%s/env:EF_UDP_NETMASK", 
                                  pco_tst2->ta);
    else
        rc = cfg_set_instance(handle, CVT_STRING, ef_udp_netmask_str);
    
    if (rc != 0)
        TEST_FAIL("Failed to set EF_UDP_NETMASK");

    if (rcf_rpc_server_restart(pco_iut) != 0)
        TEST_FAIL("Failed to restart pco_iut");
    
    if (rcf_rpc_server_restart(pco_tst1) != 0)
        TEST_FAIL("Failed to restart pco_tst1");
    
    if (rcf_rpc_server_restart(pco_tst2) != 0)
        TEST_FAIL("Failed to restart pco_tst2");
    
    TEST_SUCCESS;

cleanup:
    TEST_END;
}

