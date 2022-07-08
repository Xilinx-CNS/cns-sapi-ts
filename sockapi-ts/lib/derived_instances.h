/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* @fine
  @brief ARP Test Suite
 *
 * Handover test instances creation
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_INSTANCES_H__
#define __TS_INSTANCES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "sockapi-test.h"

/**
 * Pair: RPC server with a socket on it
 */
typedef struct derived_test_instance { 
    rcf_rpc_server *rpcs;   /**< RPC server */
    int             s;      /**< socket on RPC server */
} derived_test_instance;   


/**
 * Create a douple of a given socket. 
 * if command is 'execve' call execve() on rpc server,
 * if command is 'fork' call fork() on rpc server,
 * if command is 'dup' call dup() on socket.
 *
 * @param method    method of socket duplication
 * @param command   execve, fork, or dup
 * @param rpcs      rpcs server
 * @param s         socket on rpcs
 * @param num       number of pairs (rpc server, socket),
 *                  obtained by command performance
 * @param domain    socket domain
 * @param sock_type socket type
 *
 * @return List of pairs (rpcs server, socket),
 *         obtained by command performance,
 *         or NULL
 */ 
extern derived_test_instance *create_instances(const char *method,
                                               const char *command,
                                               rcf_rpc_server *rpcs,
                                               int s, int *num,
                                               rpc_socket_domain domain,
                                               rpc_socket_type sock_type);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif
