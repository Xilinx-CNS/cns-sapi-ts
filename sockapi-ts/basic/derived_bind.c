/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-derived_bind bind() after exec(), fork() or @b dup()
 *
 * @objective Check that @b bind() and other connection establishing
 *            operations work correctly on sockets instances, obtained
 *            by @b exec(), @b fork(),  @b dup().
 *
 * @type conformance
 *
 * @param env   Private testing environment set:
 *              - @ref arg_types_env_peer2peer_tst;
 *              - @ref arg_types_env_peer2peer_tst_ipv6;
 *              - similar to @ref arg_types_env_peer2peer_lo with
 *              IPv4 or IPv6 addresses issued for testing, it is not
 *              iterated with @p use_wildcard = @c TRUE.
 * @param command       Command to get another socket instance:
 *                      - execve()
 *                      - fork()
 *                      - dup()
 * @param double_acts   @c TRUE if connection establishing operations
 *                      are performing on doubled socket, @c FALSE if
 *                      they are performing on original instance.
 * @param use_wildcard  Use @c INADDR_ANY to bind if @c TRUE.
 * @param method    Determines what exactly to do creating the new process:
 *                  - inherit: only for @p command @c fork(), means just
 *                  calling @b fork();
 *                  - unspecified
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Test sequence:
 *
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
 * -# Set @c SO_REUSEADDR option on @p actor;
 * -# Bind @p actor to @p iut_addr;
 * -# Check that @p actor is in bound state;
 * -# If @p command is @b execve, then change process image
 *    by calling @b execve;
 * -# Check that @p tracker is in bound state;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p sock_type is @c SOCK_STREAM then
 *     -# Call @b listen() on @p actor;
 *     -# Check that @p actor is in listening state;
 *     -# If @p command is @b execve, then change process image
 *        by calling @b execve;
 *     -# Check that @p tracker is in listening state;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p sock_type socket @p tst_s on @p pco_tst;
 * -# Call @b connect() on @p tst_s towards @p iut_addr;
 * -# If @p sock_type is @c SOCK_DGRAM then
 *     -# Call @b send() on @p tst_s;
 * -# Check that @p actor is readable;
 * -# If @p command is @b execve, then change process image
 *    by calling @b execve;
 * -# Check that @p tracker is readable;   
 * -# If @p sock_type is @c SOCK_STREAM then
 *     -# Call @b accept() on @p actor. Let @p acc_s be result
 *        of the call;
 * -# If @p sock_type is @c SOCK_DGRAM then 
 *     -# Call @b recvfrom() on @p actor;
 * -# Check that @p actor is not readable;
 * -# If @p command is @b execve, then change process image
 *    by calling @b execve;
 * -# Check that @p tracker is not readable;
 * -# Close @p tst_s;
 * -# If @p sock_type is @c SOCK_STREAM then close @p acc_s;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p command is not @b execve, then
 *     -# Close @p tracker, not changing socket descriptor;
 *     -# Create @p sock_type socket @p tst_s on @p pco_tst;
 *     -# Call @b connect() on @p tst_s towards @p iut_addr;
 *     -# If @p sock_type is @c SOCK_DGRAM then
 *        call @b send() on @p tst_s;
 *     -# Check that @p actor is readable;
 *    \n @htmlonly &nbsp; @endhtmlonly
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "basic/derived_bind"

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

    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst_aux = NULL;
    int             tst_s = -1;
    
    const char             *method;

    const struct sockaddr  *iut_addr = NULL;
    struct sockaddr_storage wildcard_addr;
    struct sockaddr_storage peer;
    socklen_t               peer_len = sizeof(struct sockaddr_storage);

    const char             *command = NULL;
    rpc_socket_type         sock_type;
    te_bool                 double_acts;
 
    derived_test_instance  *instances = NULL;
    derived_test_instance  *actor = NULL;
    derived_test_instance  *tracker = NULL;
    int                     inst_num = 0;
    
    int                     opt_val = 1;

    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  tx_buflen;
    size_t                  rx_buflen;
    
    int tst_s_aux = -1;
    int acc_s_aux = -1;

    te_bool                 use_wildcard = FALSE;
    

    /* Preambule */
    TEST_START;
  
    TEST_GET_SOCK_TYPE(sock_type);    
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_GET_STRING_PARAM(command);
    TEST_GET_BOOL_PARAM(double_acts);
    TEST_GET_BOOL_PARAM(use_wildcard);
    TEST_GET_STRING_PARAM(method);

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
                       
    if (sock_type == RPC_SOCK_DGRAM)
    {
        tst_s_aux = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s_aux, iut_addr);
        pco_tst_aux = pco_tst;
    }
    
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

    rpc_setsockopt(actor->rpcs, actor->s, RPC_SO_REUSEADDR, &opt_val);

    /* Bind */
    memcpy(&wildcard_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));
    rpc_bind(actor->rpcs, actor->s,
             use_wildcard ? SA(&wildcard_addr) : iut_addr);

    /* Try to check socket state implicitly */
    RPC_AWAIT_IUT_ERROR(tracker->rpcs);
    if (rpc_bind(tracker->rpcs, tracker->s,
                 use_wildcard ? SA(&wildcard_addr) : iut_addr) != -1)
    {
        TEST_VERDICT("Child socket is successfully bound second time");
    }
    if (RPC_ERRNO(tracker->rpcs) != RPC_EINVAL)
    {
        TEST_VERDICT("Incorrect error is returned by second bind()");
    }
    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(actor->rpcs, actor->s, 
                                          pco_tst_aux, tst_s_aux, STATE_BOUND);
    if (strcmp(command, "execve") == 0)
    {
        CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
    }
    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(tracker->rpcs, tracker->s, 
                                          pco_tst_aux, tst_s_aux, STATE_BOUND);
    
    /* Listen */
    if (sock_type == RPC_SOCK_STREAM)
    {    
        rpc_listen(actor->rpcs, actor->s, SOCKTS_BACKLOG_DEF);

        CHECK_SOCKET_STATE_AND_RETURN_VERDICT(actor->rpcs, actor->s, 
                                              pco_tst_aux, tst_s_aux, 
                                              STATE_LISTENING);
        if (strcmp(command, "execve") == 0)
        {
            CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
        }
        {
            struct sockaddr_storage peer_addr;
            socklen_t               peer_addrlen = 
                                    sizeof(struct sockaddr_storage);

            /* Try to check socket state implicitly */
            tst_s_aux = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);

            rpc_connect(pco_tst, tst_s_aux, iut_addr);
            RPC_AWAIT_IUT_ERROR(tracker->rpcs);
            if ((acc_s_aux = rpc_accept(tracker->rpcs, tracker->s, 
                                        (struct sockaddr *)&peer_addr, 
                                        &peer_addrlen)) == -1)
            {
                TEST_VERDICT("Socket is expected to be listening but "
                             "accept() returns -1 with %s",
                             errno_rpc2str(RPC_ERRNO(tracker->rpcs)));
            }
            rpc_close(pco_tst, tst_s_aux);
            tst_s_aux = -1;
        }
        CHECK_SOCKET_STATE_AND_RETURN_VERDICT(tracker->rpcs, tracker->s,  
                                              pco_tst_aux, tst_s_aux, 
                                              STATE_LISTENING);
    }    

    tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
    /* Connect/send */
    rpc_connect(pco_tst, tst_s, iut_addr);
    if (sock_type == RPC_SOCK_DGRAM)
    {
        CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&tx_buflen)));
        rx_buflen = tx_buflen;
        rx_buf = te_make_buf_by_len(rx_buflen);
        rpc_send(pco_tst, tst_s, tx_buf, tx_buflen, 0);
    }
    TAPI_WAIT_NETWORK;

    RPC_CHECK_READABILITY(actor->rpcs, actor->s, TRUE);
    if (strcmp(command, "execve") == 0)
    {
        CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
    }
    RPC_CHECK_READABILITY(tracker->rpcs, tracker->s, TRUE);
    
    /* Accept/receive */
    if (sock_type == RPC_SOCK_STREAM)
        acc_s = rpc_accept(actor->rpcs, actor->s, NULL, NULL);
    else
        rpc_recvfrom(actor->rpcs, actor->s, rx_buf, rx_buflen, 0, 
                     (struct sockaddr *)&peer, &peer_len);
        
        
    RPC_CHECK_READABILITY(actor->rpcs, actor->s, FALSE);
    if (strcmp(command, "execve") == 0)
    {
        CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
    }
    RPC_CHECK_READABILITY(tracker->rpcs, tracker->s, FALSE);

    /* Close connection */
    if (sock_type == RPC_SOCK_STREAM)
        RPC_CLOSE(actor->rpcs, acc_s);
    RPC_CLOSE(pco_tst, tst_s);

    /* Close one descriptor */
    if (strcmp(command, "execve") != 0)
    {
        rpc_close(tracker->rpcs, tracker->s);
        tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s, iut_addr);
        if (sock_type == RPC_SOCK_DGRAM)
            rpc_send(pco_tst, tst_s, tx_buf, tx_buflen, 0);
        TAPI_WAIT_NETWORK;
        RPC_CHECK_READABILITY(actor->rpcs, actor->s, TRUE);
    }    

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_aux);
    if (actor != NULL)
    {
        CLEANUP_RPC_CLOSE(actor->rpcs, acc_s);
        CLEANUP_RPC_CLOSE(actor->rpcs, actor->s);
    }
    else
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (tracker != NULL)
        CLEANUP_RPC_CLOSE(tracker->rpcs, acc_s_aux);

    TEST_END;
}
