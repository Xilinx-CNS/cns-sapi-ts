/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-fork_bound fork() with bound socket
 *
 * @objective Check that bound socket is inherited to the both processes
 *            during @b fork call and @b close() socket in one process remains
 *            it alive in another.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Private testing environment set similar to
 *              @ref arg_types_env_iut_ucast and
 *              @ref arg_types_env_iut_ucast_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param act_child If @c TRUE child acts after @b fork(), parent tracks;
 *                  else parent acts after @b fork(), child tracks.
 * @param method    Determines what exactly to do creating new process:
 *                  - inherit: means just calling @b fork().
 *
 * @par Scenario:
 *
 * -# Create socket @p sock on @p pco_iut of @p sock_type type. 
 * -# @b bind() it with wildcard address and zero port.
 * -# Split @p iut_child from @p pco_iut with 
 *    @ref lib-create_child_process_socket.
 * -# Perform #sockts_get_socket_state routine for @p sock on @p pco_iut.
 * -# Perform #sockts_get_socket_state routine for @p sock_child on 
 *    @p iut_child.
 * -# Check that obtained state of sockets from both processes 
 *    is @c STATE_BOUND. 
 * -# @b close() socket on @p actor.
 * -# Perform #sockts_get_socket_state routine for socket on 
 *    @p actor.
 * -# Check that obtained state of socket on @p actor is @c STATE_CLOSED. 
 * -# Perform #sockts_get_socket_state routine for socket on @p tracker.
 * -# Check that obtained state of socket on @p tracker is @c STATE_BOUND. 
 * -# @b close() @p sock on @b pco_iut.
 * -# Destroy process @b iut_child.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/fork_bound"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *iut_child = NULL;
    rcf_rpc_server         *pco_iut1 = NULL;
    int                     iut1_s = -1;
    int                     sock = -1;
    int                     sock_child = -1; 
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *iut1_addr;
    const char             *method;
    
    rpc_socket_type         sock_type; 
    te_bool                 act_child;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut1, iut1_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(act_child);
    TEST_GET_STRING_PARAM(method);

    if (sock_type == RPC_SOCK_DGRAM)
    {    
        rcf_rpc_server_create(pco_iut->ta, "pco_iut1", &pco_iut1);

        iut1_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut_addr), 
                            sock_type, RPC_PROTO_DEF);
        rpc_bind(pco_iut1, iut1_s, iut1_addr);
        rpc_connect(pco_iut1, iut1_s, iut_addr);
    }
    
    sock = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                      sock_type, RPC_PROTO_DEF); 
    rpc_bind(pco_iut, sock, iut_addr);
    

    CHECK_SOCKET_STATE(pco_iut, sock, pco_iut1, iut1_s, STATE_BOUND);

    rpc_create_child_process_socket(method, pco_iut, sock, 
                                    rpc_socket_domain_by_addr(iut_addr), 
                                    sock_type, &iut_child, &sock_child);

    /* Try to check socket state implicitly */
    RPC_AWAIT_IUT_ERROR(iut_child);
    if (rpc_bind(iut_child, sock_child, iut_addr) != -1)
        TEST_FAIL("Child socket is successfully bound second time");
    
    CHECK_SOCKET_STATE(pco_iut, sock, pco_iut1, iut1_s, STATE_BOUND);
    CHECK_SOCKET_STATE(iut_child, sock_child, pco_iut1, iut1_s, STATE_BOUND);
    
    if (act_child)
    {    
        rpc_closesocket(iut_child, sock_child); 
        CHECK_SOCKET_STATE(iut_child, sock_child, 
                           pco_iut1, iut1_s, STATE_CLOSED); 
        CHECK_SOCKET_STATE(pco_iut, sock, pco_iut1, iut1_s, STATE_BOUND);
        
        sock_child = -1;
    }
    else
    {
        rpc_closesocket(pco_iut, sock); 
        CHECK_SOCKET_STATE(pco_iut, sock, pco_iut1, iut1_s, STATE_CLOSED); 
        CHECK_SOCKET_STATE(iut_child, sock_child, 
                           pco_iut1, iut1_s, STATE_BOUND);
        sock = -1;                           
    }
    
    TEST_SUCCESS;

cleanup:
    
    CLEANUP_RPC_CLOSE(pco_iut, sock);
    if (iut_child == pco_iut)
        CLEANUP_RPC_CLOSE(pco_iut, sock_child);

    TEST_END;
}
