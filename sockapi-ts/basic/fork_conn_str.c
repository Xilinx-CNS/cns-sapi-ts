/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-fork_conn_str fork() with connected stream sockets
 *
 * @objective Check that socket is inherited by child process
 *            during @b fork call and traffic transmission
 *            in both directions.
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
 * -# Create socket @p sock_iut on @p pco_iut of @c SOCK_STREAM type. 
 * -# @b bind() @p sock_iut to @p pco_iut socket address.
 * -# Create socket @p sock_tst on @p pco_tst of @c SOCK_STREAM type.
 * -# @b bind() @p sock_tst to @p pco_tst socket address. 
 * -# Call @b listen() for @p sock_tst.
 * -# @b connect() @p sock to the @p sock_tst.
 * -# Call @b accept() on @p sock_tst to get @p sock_acc socket.  
 * -# Perform #sockts_get_socket_state routine for @p pco_iut, @p sock_iut.
 * -# Check that obtained state of @p sock_iut is @c STATE_CONNECTED. 
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# split @p iut_child from @p pco_iut with @b fork();
 * -# Perform #sockts_get_socket_state routine for @p iut_child, @p sock_iut.
 * -# Perform #sockts_get_socket_state routine for @p pco_iut, @p sock_iut.
 * -# Check that obtained state of @p sock_iut is @c STATE_CONNECTED 
 *    in both processes. 
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() data from @p sock_iut on @p pco_iut.   
 * -# Catch sent data by @b recv() on @p sock_acc. 
 * -# @b send() data from @p sock_iut on @p iut_child.   
 * -# Catch sent data by @b recv() on @p sock_acc. 
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() data from @p sock_acc.
 * -# Check that @p sock_iut is readable on @p pco_iut and @p iut_child.
 * -# Catch sent data by @b recv() on @p sock_iut on @p pco_iut. 
 * -# Check that @p sock_iut is not readable on @p iut_child.
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() data from @p sock_acc.
 * -# Check that @p sock_iut is readable on @p pco_iut and @p iut_child.
 * -# Catch sent data by @b recv() on @p sock_iut on @p iut_child. 
 * -# Check that @p sock_iut is not readable on @p pco_iut.
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b close() @p sock_iut on @p actor.
 * -# Perform #sockts_get_socket_state routine for @p actor, @p sock_iut.
 * -# Check that obtained state of @p sock_iut is @c STATE_CLOSED. 
 * -# Perform #sockts_get_socket_state routine for @p tracker, @p sock_iut.
 * -# Check that obtained state of @p sock_iut is @c STATE_CONNECTED. 
 * -# @b send() data from @p sock_acc.
 * -# Catch sent data by @b recv() on @p sock_iut on @p tracker. 
 * -# @b send() data from @p sock_iut.
 * -# Catch sent data by @b recv() on @p sock_acc on @p tracker. 
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b close() all sockets.
 * -# Destroy process @b iut_child;
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/fork_conn_str"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;
    rpc_socket_domain       domain;
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    rcf_rpc_server         *iut_child = NULL;
    int                     sock_iut = -1;
    int                     sock_tst = -1;
    int                     sock_acc = -1;
    int                     child_s = -1;
    int                     sock_act, sock_track;
    const char             *method;
    
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    struct sockaddr_storage acc_addr;
    socklen_t               acc_addrlen; 

    te_bool                 act_child;
    rcf_rpc_server        **actor = NULL;
    rcf_rpc_server        **tracker = NULL;

    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    domain = rpc_socket_domain_by_addr(iut_addr);
    TEST_GET_BOOL_PARAM(act_child);
    TEST_GET_STRING_PARAM(method);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_stream(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    sock_iut = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    sock_tst = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, sock_iut, iut_addr);

    rpc_bind(pco_tst, sock_tst, tst_addr);

    rpc_listen(pco_tst, sock_tst, SOCKTS_BACKLOG_DEF);

    rpc_connect(pco_iut, sock_iut, tst_addr);

    acc_addrlen = sizeof(acc_addr);
    sock_acc = rpc_accept(pco_tst, sock_tst, SA(&acc_addr), &acc_addrlen); 

    CHECK_SOCKET_STATE(pco_iut, sock_iut, pco_tst, sock_acc,
                       STATE_CONNECTED);

    rpc_create_child_process_socket(method, pco_iut, sock_iut, domain,
                                    RPC_SOCK_STREAM, &iut_child, &child_s);

    if (act_child)
    {
        actor = &iut_child;
        tracker = &pco_iut;
        sock_act = child_s;
        sock_track = sock_iut;
    }
    else
    {
        actor = &pco_iut;
        tracker = &iut_child;
        sock_act = sock_iut;
        sock_track = child_s;
    }

    CHECK_SOCKET_STATE(pco_iut, sock_iut, pco_tst, sock_acc,
                       STATE_CONNECTED);

    CHECK_SOCKET_STATE(iut_child, child_s, pco_tst, sock_acc,
                       STATE_CONNECTED);

    RPC_SEND(rc, pco_iut, sock_iut, tx_buf, buf_len, 0);
    rc = rpc_recv(pco_tst, sock_acc, rx_buf, buf_len, 0); 
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("sock_acc received differ length then was sent from"
                  " pco_iut"); 
    }

    RPC_SEND(rc, iut_child, child_s, tx_buf, buf_len, 0);
    rc = rpc_recv(pco_tst, sock_acc, rx_buf, buf_len, 0); 
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("sock_acc received differ length then was sent "
                  "from iut_child"); 
    }


    RPC_SEND(rc, pco_tst, sock_acc, tx_buf, buf_len, 0);
    TAPI_WAIT_NETWORK;
    RPC_CHECK_READABILITY(pco_iut, sock_iut, TRUE); 
    RPC_CHECK_READABILITY(iut_child, child_s, TRUE);
    rc = rpc_recv(pco_iut, sock_iut, rx_buf, buf_len, 0); 
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("sock_iut received on pco_iut differ length then was"
                  " sent"); 
    }
    RPC_CHECK_READABILITY(iut_child, child_s, FALSE);


    RPC_SEND(rc, pco_tst, sock_acc, tx_buf, buf_len, 0);
    TAPI_WAIT_NETWORK;
    RPC_CHECK_READABILITY(pco_iut, sock_iut, TRUE); 
    RPC_CHECK_READABILITY(iut_child, child_s, TRUE);
    rc = rpc_recv(iut_child, child_s, rx_buf, buf_len, 0); 
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("sock_iut received on iut_child differ length then "
                  "was sent"); 
    }
    RPC_CHECK_READABILITY(pco_iut, sock_iut, FALSE);

    rpc_closesocket(*actor, sock_act); 

    CHECK_SOCKET_STATE(*actor, sock_act, pco_tst, sock_acc, STATE_CLOSED); 

    CHECK_SOCKET_STATE(*tracker, sock_track, pco_tst, sock_acc,
                       STATE_CONNECTED);

    RPC_SEND(rc, pco_tst, sock_acc, tx_buf, buf_len, 0);
    rc = rpc_recv(*tracker, sock_track, rx_buf, buf_len, 0); 
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("Socket %d received on pco_iut differ length then was"
                  " sent", sock_iut); 
    }

    buf_len = rpc_send(*tracker, sock_track, rx_buf, buf_len, 0); 
    rc = rpc_recv(pco_tst, sock_acc, tx_buf, buf_len, 0);
    if ((unsigned)rc != buf_len)
    {
        TEST_FAIL("Socket %d received different length than was sent from"
                  " IUT", sock_acc);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, sock_tst); 
    CLEANUP_RPC_CLOSE(pco_tst, sock_acc); 

    if (iut_child != pco_iut)
        rcf_rpc_server_restart(iut_child);

    rcf_rpc_server_restart(pco_iut);

    TEST_END;
}
