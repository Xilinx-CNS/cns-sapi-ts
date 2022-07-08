/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-socket_close The socket()/close() functions
 *
 * @objective Test on possibility of communication endpoint creation.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_iut_only
 * @param domain    Communications domain:
 *                      - PF_INET
 *                      - PF_INET6
 * @param type      Type of socket:
 *                      - SOCK_STREAM
 *                      - SOCK_DGRAM
 * @param protocol  A particular protocol to be used with the socket:
 *                      - IPPROTO_TCP
 *                      - IPPROTO_UDP
 *                      - PROTO_DEF
 *
 * @par Scenario:
 * -# Create socket with parameters @p domain, @p type, @p proto.
 * -# Close created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/socket_close"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rpc_socket_type     type;
    rpc_socket_proto    proto;
    int                 s;
    rpc_socket_domain   domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(type);
    TEST_GET_PROTOCOL(proto);
    TEST_GET_DOMAIN(domain);
        
    s = rpc_socket(pco_iut, domain, type, proto);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, s);
    TEST_END;
}
