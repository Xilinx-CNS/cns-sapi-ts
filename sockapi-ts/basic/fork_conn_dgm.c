/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-fork_conn_dgm fork() with connected datagram sockets
 *
 * @objective Check that socket is inherited to the both processes during
 *            @b fork call, that data received and transmitted correctly and
 *            legal state transitions in one process are detected in another.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_tst
 *              - @ref arg_types_env_peer2peer_lo
 * @param act_child If @c TRUE child acts after @b fork(), parent tracks;
 *                  else parent acts after @b fork(), child tracks.
 * @param method    Determines what exactly to do creating new process:
 *                  - inherit: means just calling @b fork().
 *
 * @par Scenario:
 *
 * -# Create socket @p sock_iut on @p pco_iut of @c SOCK_DGRAM type. 
 * -# @b bind() @p sock_iut with zeros address and port, get auto-bound
 *      port of @p sock_iut. 
 * -# Create socket @p sock_tst on @p pco_tst of @c SOCK_DGRAM type. 
 * -# @b connect() @p sock_tst to the socket address of @p pco_iut.
 * -# @b connect() @p sock_iut to the socket address of @p pco_tst.
 * -# Perform #sockts_get_socket_state routine for @p pco_iut, @p sock_iut.
 * -# Check that obtained state of @p sock_iut is @c STATE_CONNECTED. 
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Split @p iut_child from @p pco_iut with 
 *    @ref lib-create_child_process_socket.
 * -# Perform #sockts_get_socket_state routine for @p pco_iut, @p sock_iut.
 * -# Perform #sockts_get_socket_state routine for @p iut_child, @p sock_child.
 * -# Check that obtained state of sockets is @c STATE_CONNECTED in
 *    both processes. 
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() data from @p sock_iut on @p pco_iut.   
 * -# Catch sent data by @b recv() on @p sock_tst. 
 * -# @b send() data from @p sock_child on @p iut_child.   
 * -# Catch sent data by @b recv() on @p sock_tst. 
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() data from @p sock_tst.
 * -# Check that @p sock_iut is readable on @p pco_iut and @p sock_child - on  
 *    @p iut_child.
 * -# Catch sent data by @b recv() on @p sock_iut on @p pco_iut. 
 * -# Check that @p sock_child is not readable on @p iut_child.
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() data from @p sock_tst.
 * -# Check that @p sock_iut is readable on @p pco_iut and @p sock_child - on 
 *  @p iut_child.
 * -# Catch sent data by @b recv() on @p sock_child on @p iut_child. 
 * -# Check that @p sock_iut is not readable on @p pco_iut.
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b close() socket on @p actor.
 * -# Perform #sockts_get_socket_state routine for socket on @p actor.
 * -# Check that obtained state is @c STATE_CLOSED. 
 * -# Perform #sockts_get_socket_state routine for socket on @p tracker.
 * -# Check that obtained state is @c STATE_CONNECTED. 
 * -# @b send() data from @p sock_tst.
 * -# Catch sent data by @b recv() on socket on @p tracker. 
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b close() all sockets.
 * -# Destroy process @b iut_child.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/fork_conn_dgm"

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
    int                     sock_child = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    te_bool                 act_child;
    rcf_rpc_server        **actor = NULL;
    rcf_rpc_server        **tracker = NULL;
    int                     act_sock;
    int                     track_sock;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(act_child);
    TEST_GET_STRING_PARAM(method);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);


    sock_iut = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF); 

    sock_tst = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF); 

    rpc_bind(pco_iut, sock_iut, iut_addr);

    rpc_bind(pco_tst, sock_tst, tst_addr);

    rpc_connect(pco_iut, sock_iut, tst_addr);

    rpc_connect(pco_tst, sock_tst, iut_addr);

    CHECK_SOCKET_STATE(pco_iut, sock_iut, pco_tst, sock_tst, STATE_CONNECTED);

    rpc_create_child_process_socket(method, pco_iut, sock_iut, 
                                    rpc_socket_domain_by_addr(iut_addr), 
                                    SOCK_DGRAM, &iut_child, &sock_child);

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
    
    CHECK_SOCKET_STATE(pco_iut, sock_iut, pco_tst, sock_tst, STATE_CONNECTED);

    CHECK_SOCKET_STATE(iut_child, sock_child, pco_tst, sock_tst, 
                       STATE_CONNECTED);

    RPC_SEND(rc, pco_iut, sock_iut, tx_buf, buf_len, 0);

    rc = rpc_recv(pco_tst, sock_tst, rx_buf, buf_len, 0); 

    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("sock_tst received bytes differ then was sent from pco_iut"); 
    }


    RPC_SEND(rc, iut_child, sock_child, tx_buf, buf_len, 0);

    rc = rpc_recv(pco_tst, sock_tst, rx_buf, buf_len, 0); 
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("sock_tst received bytes differ then was sent from iut_child"); 
    }

    RPC_SEND(rc, pco_tst, sock_tst, tx_buf, buf_len, 0);
    TAPI_WAIT_NETWORK;

    RPC_CHECK_READABILITY(pco_iut, sock_iut, TRUE); 
    RPC_CHECK_READABILITY(iut_child, sock_child, TRUE);

    rc = rpc_recv(pco_iut, sock_iut, rx_buf, buf_len, 0); 
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("sock_iut received on pco_iut differ length then was sent"); 
    }

    RPC_CHECK_READABILITY(iut_child, sock_child, FALSE);

    RPC_SEND(rc, pco_tst, sock_tst, tx_buf, buf_len, 0);
    TAPI_WAIT_NETWORK;

    RPC_CHECK_READABILITY(pco_iut, sock_iut, TRUE); 
    RPC_CHECK_READABILITY(iut_child, sock_child, TRUE);

    rc = rpc_recv(iut_child, sock_child, rx_buf, buf_len, 0); 
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("sock_iut received on iut_child differ length then was sent"); 
    }

    RPC_CHECK_READABILITY(pco_iut, sock_iut, FALSE);

    rpc_closesocket(*actor, act_sock); 
    CHECK_SOCKET_STATE(*actor, act_sock, pco_tst, sock_tst, 
                       STATE_CLOSED); 
    CHECK_SOCKET_STATE(*tracker, track_sock, pco_tst, sock_tst, 
                       STATE_CONNECTED);
    RPC_SEND(rc, pco_tst, sock_tst, tx_buf, buf_len, 0);
    rc = rpc_recv(*tracker, track_sock, rx_buf, buf_len, 0);    
   
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("sock_iut received on pco_iut differ length then was sent"); 
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, sock_tst); 

    if (iut_child != pco_iut)
        rcf_rpc_server_restart(iut_child);
        
    rcf_rpc_server_restart(pco_iut);

    TEST_END;
}
