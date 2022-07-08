/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief ARP Test Suite
 *
 * Handover test instances creation
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 *
 * $Id$
 */

/** User name of ARP send/receive library */
#define TE_LGR_USER     "Handover test instances"

#include "derived_instances.h"

/* See description in derived_instances.h */
derived_test_instance *
create_instances(const char *method, const char *command,
                 rcf_rpc_server *rpcs, int s, int *num,
                 rpc_socket_domain domain, rpc_socket_type sock_type)
{
    derived_test_instance *result = NULL;
    int                    rc = 0;
    int                    child_s = -1;    
    
    if (strcmp(command, "execve") == 0)
    {
        if ((rc = rcf_rpc_server_exec(rpcs)) != 0)
        {
            ERROR("exec processing failed, rc %X", rc);
            return NULL;
        }
        if ((result = calloc(1, sizeof(derived_test_instance))) == NULL)
        {
            ERROR("No resources for you, poor fish");
            return NULL; 
        }
        *num = 1;
        result[0].rpcs = rpcs;
        result[0].s = s;
    }
    else if (strcmp(command, "fork") == 0)
    {
        rcf_rpc_server *child_rpcs = NULL;
       
        rpc_create_child_process_socket(method, rpcs, s, domain,
                                        sock_type, &child_rpcs, &child_s);
        if ((result = calloc(2, sizeof(derived_test_instance))) == NULL)
        {
            ERROR("No resources for you, poor fish");
            return NULL; 
        }
        *num = 2;
        result[0].rpcs = rpcs;
        result[0].s = s;
        result[1].rpcs = child_rpcs;
        result[1].s = child_s;
    }
    else if (strcmp(command, "dup") == 0)
    {
        int ds;

        if ((ds = rpc_dup(rpcs, s)) == -1)
        {
           ERROR("dup processing failed, rc %X", rc);
           return NULL;
       }
       if ((result = calloc(2, sizeof(derived_test_instance))) == NULL)
       {
           ERROR("No resources for you, poor fish");
           return NULL; 
       }
       *num = 2;
       result[0].rpcs = rpcs;
       result[0].s = s;
       result[1].rpcs = rpcs;
       result[1].s = ds;
    }
    return result;
}
