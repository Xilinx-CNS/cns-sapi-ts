/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Handover tests
 */

/** @page basic-derived_connect connect() after exec(), fork() or @b dup()
 *
 * @objective Check that @b connect() and other connection establishing
 *            operations works correctly on sockets instances, obtained
 *            by @b exec(), @b fork(), @b dup().
 *
 * @type conformance
 *
 * @param env   Private testing environment set:
 *              - @ref arg_types_env_peer2peer_tst
 *              - @ref arg_types_env_peer2peer_tst_ipv6
 *              - similar to @ref arg_types_env_peer2peer_lo with
 *              IPv4/IPv6 addresses issued for testing.
 * @param command     Command to get another socket instance:
 *                    - execve()
 *                    - fork()
 *                    - dup()
 * @param double_acts @c TRUE if connection establishing operations
 *                    are performing on doubled socket, @c FALSE if
 *                    they are performing on original instance.
 * @param method      Determines what exactly to do creating the new process:
 *                    - inherit: only for @p command @c fork(), means just
 *                    calling @b fork();
 *                    - unspecified
 * @param sock_type   Socket type:
 *                    - SOCK_STREAM
 *                    - SOCK_DGRAM
 *
 * @par Test sequence:
 * -# Create @p sock_type socket @p iut_s on @p pco_iut;
 * -# Create @p double of @p iut_s via @p command;
 * -# If @p double_acts is TRUE then let @p actor to be
 *    @p double, and @p tracker to be @p iut_s,
 *    otherwise let @p actor to be @p iut_s, 
 *    and @p tracker to be @p double;
 *       - Note! Actually, @p actor and @p tracker are pairs
 *       (socket, process possessing the socket), and
 *       all further operations related to sockets
 *       are performed in that process context.
 *       Below it is related as sockets process;
 *       Note, that @p actor and @p tracker are the same
 *       in case of @b execve command;
 * -# Create @p sock_type socket @p tst_s on @p pco_tst;
 * -# Set @c SO_REUSEADDR option on @p tst_s;
 * -# Bind @p tst_s to @p tst_addr;
 * -# If @p sock_type is @c SOCK_STREAM then
 *    call @b listen() on @p tst_s;
 * -# Call @b connect() on @p actor towards @p tst_addr;
 * -# If @p sock_type is @c SOCK_STREAM then
 *    call @b accept() on @p tst_s and obtain @p acc_s socket 
 *    as result of the call;
 * -# Check that @p actor is in connected state;
 * -# If @p command is @b execve, then change process image
 *    by calling @b execve;
 * -# Check that @p tracker is in connected state;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b send() on @p actor;
 * -# If @p sock_type is @c SOCK_STREAM then
 *     -# Call @p recv() on @p acc_s;
 *     -# Call @p send() on @p acc_s with the same buffer;
 * -# If @p sock_type is @c SOCK_DGRAM then    
 *     -# Call @p recvfrom() on @p acc_s;
 *     -# Call @p sendto() on @p acc_s with the same buffer
 *        to @p peer address which is obtained 
 *        from previous call @b recvfrom();
 * -# Check that @p actor is readable;       
 * -# If @p command is @b execve, then change process image
 *    by calling @b execve;
 * -# Check that @p tracker is readable;   
 * -# Call @b recv() on @p actor, check that data received 
 *    is the same as one were sent;
 * -# Check that @p actor is not readable;       
 * -# If @p command is @b execve, then change process image
 *    by calling @b execve;
 * -# Check that @p tracker is not readable;   
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p command is not @b execve, then
 *     -# Close @p tracker, not changing socket descriptor;
 *     -# Check that @p tracker is in closed state;
 *     -# Check that @p actor is in connected state;
 *     -# If @p sock_type is @c SOCK_STREAM then
 *        call @b send() on @p tst_s;
 *     -# If @p sock_type is @c SOCK_DGRAM then   
 *        call @b sendto() on @p tst_s towards @p peer address; 
 *     -# Check that @p actor is readable;
 *    \n @htmlonly &nbsp; @endhtmlonly
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "basic/derived_connect"

#include <errno.h>
#include <pthread.h>

#include "sockapi-test.h"
#include "rcf_api.h"
#include "tapi_cfg_base.h"
#include "rcf_rpc.h"
#include "tapi_rpc_unistd.h"

#include "derived_instances.h" 

    
int
main(int argc, char *argv[])
{
    rpc_socket_domain   domain;
    rcf_rpc_server     *pco_iut = NULL;
    int                 iut_s = -1;  
    int                 acc_s = -1;       

    rcf_rpc_server     *pco_tst = NULL;
    int                 tst_s = -1;


    const struct sockaddr  *tst_addr = NULL;
    
    const struct sockaddr_storage peer;
    socklen_t                     peer_len = sizeof(peer);

    const char             *command = NULL;
    rpc_socket_type         sock_type;
    te_bool                 double_acts;
    const char             *method;

    derived_test_instance  *instances = NULL;
    derived_test_instance  *actor = NULL;
    derived_test_instance  *tracker = NULL;
    int                     inst_num = 0;
    
    int                     opt_val = 1;

    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  tx_buflen;
    size_t                  rx_buflen;
    size_t                  got_data;

    TEST_START;
  
    TEST_GET_SOCK_TYPE(sock_type);
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    
    TEST_GET_ADDR(pco_tst, tst_addr);
    domain = rpc_socket_domain_by_addr(tst_addr);

    TEST_GET_STRING_PARAM(command);
    TEST_GET_BOOL_PARAM(double_acts);
    TEST_GET_STRING_PARAM(method);
    

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
   
    if ((instances = create_instances(method, command, pco_iut, iut_s,
                                      &inst_num, domain,
                                      sock_type)) == NULL)
        TEST_FAIL("Cannot create test instnaces");

    if (double_acts == TRUE)
    {
        tracker = instances;
        actor = instances + inst_num - 1;
    }
    else
    {
        actor = instances;
        tracker = instances + inst_num - 1;
    }

    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(actor->rpcs, actor->s, 
                                          NULL, -1, STATE_CLEAR);

    if (strcmp(command, "execve") == 0)
    {
        CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
    }

    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(tracker->rpcs, tracker->s, 
                                          NULL, -1, STATE_CLEAR);

    tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
 
    /* Bind */
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_REUSEADDR, &opt_val);
    rpc_bind(pco_tst, tst_s, tst_addr);

    /* Listen */
    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    /* Connect */
    rpc_connect(actor->rpcs, actor->s, tst_addr);
    if (sock_type == RPC_SOCK_STREAM)
    {
        acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
        rpc_close(pco_tst, tst_s);
        tst_s = acc_s;
        acc_s = -1;
    }
    else
    {
        rpc_getsockname(actor->rpcs, actor->s, SA(&peer), &peer_len);
        rpc_connect(pco_tst, tst_s, SA(&peer));
    }
    
    /* Try to check socket state implicitly */
    if (sock_type == RPC_SOCK_STREAM)
    {
        RPC_AWAIT_IUT_ERROR(tracker->rpcs);
        if (rpc_connect(tracker->rpcs, tracker->s, tst_addr) != -1)
        {                    
            TEST_VERDICT("Child socket is successfully connected second time");
        }
        if (RPC_ERRNO(tracker->rpcs) != RPC_EISCONN)
            TEST_VERDICT("Incorrect error is returned by second connect()");
    }

    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(actor->rpcs, actor->s, 
                                          pco_tst, tst_s, STATE_CONNECTED);
                                          
    if (strcmp(command, "execve") == 0)
    {
        CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
    }
    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(tracker->rpcs, tracker->s, 
                                          pco_tst, tst_s, STATE_CONNECTED);

    /* Send data */
    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&tx_buflen)));
    rx_buflen = tx_buflen;
    rx_buf = te_make_buf_by_len(rx_buflen);
    rpc_send(actor->rpcs, actor->s, tx_buf, tx_buflen, 0);
    rpc_recv(pco_tst, tst_s, rx_buf, rx_buflen, 0);
    rpc_send(pco_tst, tst_s, tx_buf, tx_buflen, 0);
    TAPI_WAIT_NETWORK;
        
    RPC_CHECK_READABILITY(actor->rpcs, actor->s, TRUE);
    if (strcmp(command, "execve") == 0)
    {
        CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
    }
    RPC_CHECK_READABILITY(tracker->rpcs, tracker->s, TRUE);

    got_data = rpc_recv(actor->rpcs, actor->s, rx_buf, rx_buflen, 0);
    if (got_data != tx_buflen || memcmp(rx_buf, tx_buf, tx_buflen) != 0)
        TEST_FAIL("Received buffer differs from sent one");

    RPC_CHECK_READABILITY(actor->rpcs, actor->s, FALSE);
    if (strcmp(command, "execve") == 0)
    {
        CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
    }
    RPC_CHECK_READABILITY(tracker->rpcs, tracker->s, FALSE);

    /* Close one descriptor */
    if (strcmp(command, "execve") != 0)
    {
        rpc_closesocket(tracker->rpcs, tracker->s);

        CHECK_SOCKET_STATE_AND_RETURN_VERDICT(tracker->rpcs, tracker->s, 
                                              pco_tst, tst_s, STATE_CLOSED);
        CHECK_SOCKET_STATE_AND_RETURN_VERDICT(actor->rpcs, actor->s, pco_tst, 
                                              tst_s, STATE_CONNECTED);
        rpc_send(pco_tst, tst_s, tx_buf, tx_buflen, 0);
        TAPI_WAIT_NETWORK;
 
        RPC_CHECK_READABILITY(actor->rpcs, actor->s, TRUE);
    }    

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    if (actor != NULL)
        CLEANUP_RPC_CLOSE(actor->rpcs, actor->s);
    else
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
