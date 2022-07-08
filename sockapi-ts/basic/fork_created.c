/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-fork_created fork() with just created socket
 *
 * @objective Check that created socket is inherited to the both 
 *            processes during @b fork() call and legal state
 *            transitions in one process are detected in another.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_ucast
 *              - @ref arg_types_env_iut_ucast_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param act_child If @c TRUE child acts after @b fork(), parent tracks;
 *                  else parent acts after @b fork(), child tracks.
 *
 * @par Scenario:
 *
 * -# Create socket @p sock on @p pco_iut of desired type.
 * -# Split process @p iut_child from @p pco_iut with @b fork().
 * -# Perform #sockts_get_socket_state routine for @p sock on @p pco_iut.
 * -# Perform #sockts_get_socket_state routine for @p sock on @p iut_child.
 * -# Check that obtained state of @p sock is @c STATE_CLEAR. 
 * -# @b bind() sock on @p actor to wildcard IP address and zero port.
 * -# Perform #sockts_get_socket_state routine for @p sock on @p actor.
 * -# Perform #sockts_get_socket_state routine for @p sock on @p tracker.
 * -# Check that obtained state of @p sock is @c STATE_BOUND on both 
 *    PCOs.
 * -# @b close() @p sock on @p tracker.
 * -# Perform #sockts_get_socket_state routine for @p sock on @p tracker. 
 * -# Check that obtained state of @p sock is @c STATE_CLOSED. 
 * -# Perform #sockts_get_socket_state routine for @p sock on @p actor.
 * -# Check that obtained state of @p sock is @c STATE_BOUND. 
 * -# @b close() @p sock on @b actor.
 * -# Destroy process @b iut_child.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/fork_created"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *iut_child = NULL;
    int                     sock  = -1;
    int                     sock_child = -1;
    const char             *method;

    const struct sockaddr  *iut_addr;

    rpc_socket_type         sock_type; 
    te_bool                 act_child;
    rcf_rpc_server         *actor = NULL;
    rcf_rpc_server         *tracker = NULL;
    int                     actor_sock, tracker_sock;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(act_child);
    TEST_GET_STRING_PARAM(method);

    sock = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                      sock_type, RPC_PROTO_DEF); 

    rpc_create_child_process_socket(method, pco_iut, sock, 
                                    rpc_socket_domain_by_addr(iut_addr), 
                                    SOCK_DGRAM, &iut_child, &sock_child);

    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(pco_iut, sock, 
                                          NULL, -1, STATE_CLEAR);

    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(iut_child, sock_child, 
                                          NULL, -1, STATE_CLEAR);

    if (act_child)
    {
        actor = iut_child;
        tracker = pco_iut;
        actor_sock = sock_child;
        tracker_sock = sock;
    }
    else
    {
        actor = pco_iut;
        tracker = iut_child;
        actor_sock = sock;
        tracker_sock = sock_child;
    }

    rpc_bind(actor, actor_sock, iut_addr);

    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(actor, actor_sock, 
                                          NULL, -1, STATE_BOUND);

    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(tracker, tracker_sock, 
                                          NULL, -1, STATE_BOUND);

    rpc_closesocket(tracker, tracker_sock);
    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(tracker, tracker_sock, 
                                          NULL, -1, STATE_CLOSED);
    /*
     * Set the @p tracker_sock to -1 after checking of the socket
     * state to make sure that the @p tracker_sock will not close
     * for the second time during cleanup
     */
    tracker_sock = -1;

    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(actor, actor_sock, 
                                          NULL, -1, STATE_BOUND);

    TEST_SUCCESS;

cleanup:
    /*
     * It will suffice to close only @p actor_sock and
     * @p tracker_sock sockets, as these sockets are aliases
     * for open @p sock and @p sock_child sockets
     */
    CLEANUP_RPC_CLOSE(actor, actor_sock);
    CLEANUP_RPC_CLOSE(tracker, tracker_sock);

    TEST_END;
}
