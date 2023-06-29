/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-fork_listening fork() with listening sockets
 *
 * @objective Check that TCP listening server socket is inherited to the
 *            both processes during @ref lib-create_child_process_socket
 *            call and connection establishing operations works correctly.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param act_child If @c TRUE child acts after @b fork(), parent tracks;
 *                  else parent acts after @b fork(), child tracks.
 * @param method    Determines what exactly to do creating new process:
 *                  - inherit: means just calling @b fork().
 * @param wildcard  Bind socket to wildcard address instead of unicast
 *                  if @c TRUE.
 *
 * @par Scenario:
 *
 * -# Create socket stream @p sock_iut on @p pco_iut.
 * -# @b bind() @p sock_iut to @p pco_iut socket address.  
 * -# Call @b listen() for @p sock_iut.
 * -# Split @p iut_child from @p pco_iut with 
 *    @ref lib-create_child_process_socket.
 * -# Perform #sockts_get_socket_state routine for @p iut_child, @p sock_child.
 * -# Perform #sockts_get_socket_state routine for @p pco_iut, @p sock_iut.
 * -# Check that obtained state of sockets is @c STATE_LISTENING 
 *    in both processes. 
 * -# Create socket @p sock_tst on @p pco_tst.
 * -# @b connect() socket @p sock_tst to the socket address of @p pco_iut. 
 * -# Check that sockets on @p pco_iut and @p iut_child are readable.
 * -# Call @b accept() on actor's socket to get @p sock_acc socket.  
 * -# Check that sockets on @p pco_iut and @p iut_child are readable.
 * -# @b close() @p sock_acc and @p sock_tst sockets.  
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b close() socket on @p tracker.
 * -# Perform #sockts_get_socket_state routine for socket on @p actor.
 * -# Check that obtained state is @c STATE_LISTENING. 
 * -# Create socket @p sock_tst on @p pco_tst.
 * -# @b connect() socket @p sock_tst to the socket address of @p pco_iut. 
 * -# Check that socket on @p actor is readable.
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Close all sockets.
 * -# Destroy process @b iut_child.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/fork_listening"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    rcf_rpc_server         *iut_child = NULL;
    const char             *method;
    int                     sock_iut = -1;
    int                     sock_tst = -1;
    int                     sock_acc = -1;
    int                     sock_child = -1;

    const struct sockaddr  *iut_addr;
    te_bool                 wildcard;

    struct sockaddr_storage acc_addr;
    socklen_t               acc_addrlen; 

    te_bool                 act_child;
    rcf_rpc_server        **actor = NULL;
    rcf_rpc_server        **tracker = NULL;
    int                     act_sock;
    int                     track_sock;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(act_child);
    TEST_GET_STRING_PARAM(method);
    TEST_GET_BOOL_PARAM(wildcard);
    
    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    sock_iut = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                          RPC_SOCK_STREAM, RPC_PROTO_DEF); 

    if (wildcard)
    {
        struct sockaddr_storage addr;
        
        memset(&addr, 0, sizeof(addr));
        addr.ss_family = iut_addr->sa_family;
        te_sockaddr_set_port(SA(&addr), te_sockaddr_get_port(iut_addr));
        rpc_bind(pco_iut, sock_iut, SA(&addr));
    }
    else
    {
        rpc_bind(pco_iut, sock_iut, iut_addr);
    }

    rpc_listen(pco_iut, sock_iut, SOCKTS_BACKLOG_DEF);

    rpc_create_child_process_socket(method, pco_iut, sock_iut, 
                                    rpc_socket_domain_by_addr(iut_addr), 
                                    RPC_SOCK_STREAM, &iut_child, &sock_child);

    if (act_child)
    {
        actor = &iut_child;
        tracker = &pco_iut;
        act_sock = sock_child;
        track_sock = sock_iut;
    }
    else
    {
        actor = &pco_iut;
        tracker = &iut_child;
        act_sock = sock_iut;
        track_sock = sock_child;
    }

    CHECK_SOCKET_STATE(pco_iut, sock_iut, NULL, -1, STATE_LISTENING);
    CHECK_SOCKET_STATE(iut_child, sock_child, NULL, -1, STATE_LISTENING); 

    sock_tst = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr), 
                          RPC_SOCK_STREAM, RPC_PROTO_DEF); 

    rpc_connect(pco_tst, sock_tst, iut_addr);
    TAPI_WAIT_NETWORK;

    RPC_CHECK_READABILITY(pco_iut, sock_iut, TRUE); 
    RPC_CHECK_READABILITY(iut_child, sock_child, TRUE);

    acc_addrlen = sizeof(acc_addr);
    sock_acc = rpc_accept(*actor, act_sock, SA(&acc_addr), &acc_addrlen); 
    TAPI_WAIT_NETWORK;
        
    RPC_CHECK_READABILITY(*actor, act_sock, FALSE); 
    RPC_CHECK_READABILITY(*tracker, track_sock, FALSE);

    RPC_CLOSE(*actor, sock_acc);
    RPC_CLOSE(pco_tst, sock_tst); 

    RPC_CLOSE(*tracker, track_sock);
        
    CHECK_SOCKET_STATE(*actor, act_sock, NULL, -1, STATE_LISTENING);
        
    sock_tst = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr), 
                          RPC_SOCK_STREAM, RPC_PROTO_DEF); 

    rpc_connect(pco_tst, sock_tst, iut_addr);
    TAPI_WAIT_NETWORK;

    RPC_CHECK_READABILITY(*actor, act_sock, TRUE); 
        
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, sock_tst); 
    if (actor == NULL)
    {
        CLEANUP_RPC_CLOSE(pco_iut, sock_iut);
    }
    else
    {
        assert(actor != NULL);
        assert(tracker != NULL);
        CLEANUP_RPC_CLOSE(*actor, sock_acc);
        CLEANUP_RPC_CLOSE(*actor, act_sock);
        CLEANUP_RPC_CLOSE(*tracker, track_sock);
    }

    free(tx_buf);
    free(rx_buf);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
