/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP package prologue
 */

/** @page arp-prologue Prologue for ARP package tests
 *
 * @objective Configure test hosts for ARP package.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_gw
 *
 * @par Scenario:
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "arp/prologue"

#include "sockapi-test.h"

#if HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "tapi_cfg.h"
#include "tapi_cfg_net.h"
#include "logger_ten.h"
#include "tapi_test.h"


/**
 * Delete all static ARP entries set by prologue.
 *
 * @retval EXIT_SUCCESS     success
 * @retval EXIT_FAILURE     failure
 */
int
main(int argc, char *argv[])
{
    unsigned int    i, j, k;
    cfg_val_type    val_type;

    cfg_nets_t      nets;

    cfg_oid        *oid = NULL;

    int             use_static_arp_def;
    int             use_static_arp;

    TEST_START;

    /* Get default value for 'use_static_arp' */
    val_type = CVT_INTEGER;
    rc = cfg_get_instance_fmt(&val_type, &use_static_arp_def,
                              "/local:/use_static_arp:");
    if (rc != 0)
    {
        use_static_arp_def = 0;
        WARN("Failed to get /local:/use_static_arp: default value, "
             "set to %d", use_static_arp_def);
    }

    /* Get available networks configuration */
    rc = tapi_cfg_net_get_nets(&nets);
    if (rc != 0)
    {
        TEST_FAIL("Failed to get networks from Configurator: %X", rc);
    }

    for (i = 0; i < nets.n_nets; ++i)
    {
        cfg_net_t  *net = nets.nets + i;

        /* Delete ARP entires previously being set by root prologue */
        for (j = 0; j < net->n_nodes; ++j)
        {
            char               *node_oid = NULL;
            char               *if_oid = NULL;
            unsigned int        ip4_addrs_num;
            cfg_handle         *ip4_addrs;
            struct sockaddr    *ip4_addr = NULL;
            
            /* Get IPv4 address assigned to the node */
            rc = cfg_get_oid_str(net->nodes[j].handle, &node_oid);
            if (rc != 0)
            {
                ERROR("Failed to string OID by handle: %X", rc);
                break;
            }

            /* Get IPv4 addresses of the node */
            rc = cfg_find_pattern_fmt(&ip4_addrs_num, &ip4_addrs,
                                      "%s/ip4_address:*", node_oid);
            if (rc != 0)
            {
                ERROR("Failed to find IPv4 addresses assigned to node "
                      "'%s': %X", node_oid, rc);
                free(node_oid);
                break;
            }
            if (ip4_addrs_num == 0)
            {
                ERROR("No IPv4 addresses are assigned to node '%s'",
                      node_oid);
                free(node_oid);
                rc = TE_EENV;
                break;
            }
            val_type = CVT_ADDRESS;
            rc = cfg_get_instance(ip4_addrs[0], &val_type, &ip4_addr);
            free(node_oid);
            if (rc != 0)
            {
                ERROR("Failed to get node IPv4 address: %X", rc);
                break;
            }
            /* Delete ARP entries */
            for (k = 0; k < net->n_nodes; ++k)
            {
                if (j == k)
                    continue;

                /* Get network node OID and agent name in it */
                val_type = CVT_STRING;
                rc = cfg_get_instance(net->nodes[k].handle, &val_type,
                                      &if_oid);
                if (rc != 0)
                {
                    ERROR("Failed to string OID by handle: %X", rc);
                    break;
                }
                oid = cfg_convert_oid_str(if_oid);
                if (oid == NULL)
                {
                    ERROR("Failed to convert OID from string '%s' to "
                          "struct", if_oid);
                    free(if_oid);
                    break;
                }
                free(if_oid);

                /* Should we use static ARP for this TA? */
                val_type = CVT_INTEGER;
                rc = cfg_get_instance_fmt(&val_type, &use_static_arp,
                                          "/local:%s/use_static_arp:",
                                          CFG_OID_GET_INST_NAME(oid, 1));
                if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
                {
                    use_static_arp = use_static_arp_def;
                    rc = 0;
                }
                else if (rc != 0)
                {
                    ERROR("Failed to get /local:%s/use_static_arp: "
                          "value: %X", CFG_OID_GET_INST_NAME(oid, 1),
                          rc);
                    break;
                }
                if (!use_static_arp)
                {
                    cfg_free_oid(oid);
                    continue;
                }

                /* Delete ARP entry */
                rc = tapi_cfg_del_neigh_entry(CFG_OID_GET_INST_NAME(oid, 1),
                                              CFG_OID_GET_INST_NAME(oid, 2),
                                              ip4_addr);
                if (TE_RC_GET_ERROR(rc) == TE_ENOENT || 
                    TE_RC_GET_ERROR(rc) == TE_EFAULT)
                {
                    WARN("static ARP entry to be deleted does not exist - continue");
                    rc = 0;
                }
                else if (rc != 0)
                {
                    ERROR("Failed to delete ARP entry to TA '%s': %X",
                          CFG_OID_GET_INST_NAME(oid, 1), rc);
                    cfg_free_oid(oid);
                    break;
                }
                cfg_free_oid(oid);
            }
            free(ip4_addr);
            if (rc != 0)
                break;
        }
        if (rc != 0)
            break;
    }
    tapi_cfg_net_free_nets(&nets);
    if (rc != 0)
    {
        TEST_FAIL("Failed to prepare testing networks");
    }
    else
    {
        TEST_SUCCESS;
    }

cleanup:

    TEST_END;
}
