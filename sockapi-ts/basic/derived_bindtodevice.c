/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-derived_bindtodevice bindtodevice() after exec(), fork() or @b dup()
 *
 * @objective Check that @b bindtodevice() and further connection
 *            establishing operations works correctly on sockets
 *            instances, obtained by @b exec(), @b fork(), @b dup().
 *
 * @type conformance
 *
 * @param env   Private testing environment set (each environment is iterated
 *              with IPv4/IPv6 addresses):
 *              - similar to @ref arg_types_env_peer2peer_tst,
 *              bind IUT to IP address on non-SFC interface,
 *              bind-to-device on the same interface;
 *              - similar to @ref arg_types_env_peer2peer_tst,
 *              bind IUT to @c INADDR_ANY,
 *              bind-to-device to non-SFC interface;
 *              - similar to @ref arg_types_env_two_nets_iut_first,
 *              bind IUT to IP address on non-SFC interface, but
 *              bind-to-device to SFC interface;
 *              - similar to @ref arg_types_env_two_nets_iut_first,
 *              bind IUT to @c INADDR_ANY, but bind-to-device to SFC
 *              interface;
 *              - similar to @ref arg_types_env_peer2peer,
 *              bind IUT to IP address on SFC interface,
 *              bind-to-device on the same interface;
 *              - similar to @ref arg_types_env_peer2peer,
 *              bind IUT to @c INADDR_ANY, bind-to-device on SFC interface;
 *              - similar to @ref arg_types_env_two_nets_iut_first,
 *              bind IUT to IP address on SFC interface, but
 *              bind-to-device to non-SFC interface;
 *              - similar to @ref arg_types_env_two_nets_iut_first,
 *              bind IUT to @c INADDR_ANY, but bind-to-device to non-SFC
 *              interface;
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
 * @param use_wildcard  Bind IUT socket to wildcard address if @c TRUE. Set in
 *                      depencende on @p env to determine in test if the
 *                      bound address is wildcard.
 * @param listen_state  If @c TRUE then bind-to-device is performed on
 *                      listening socket, else set it on clear socket.
 *
 * @note If there is configuration with two nets between iut node
 *       and tester node which are physically different, interfaces to bind
 *       to always reside on the same net.
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
 * -# If @p listen_state is @c FALSE then bind @p actor
 *    to @p iut_dev_to_bind;
 * -# Check that @p actor is in clear state;
 * -# If @p command is @b execve, then change process image
 *    by calling @b execve;
 * -# Check that @p tracker is in clear state;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Bind @p actor to @p addr_to_bind;
 * -# Check that @p actor is in bound state;
 * -# If @p command is @b execve, then change process image
 *    by calling @b execve;
 * -# Check that @p tracker is in bound state;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p sock_type is @c SOCK_STREAM then
 *     -# Call @b listen() on @p actor;
 *     -# If @p listen_state is @c FALSE then bind @p actor
 *        to @p iut_dev_to_bind;
 *     -# Check that @p actor is in listening state;
 *     -# If @p command is @b execve, then change process image
 *        by calling @b execve;
 *     -# Check that @p tracker is in listening state;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p sock_type socket @p tst_s on @p pco_tst;
 * -# If @p gateway parameter is given then add route on tester node
 *    to @p addr_to_connect via @p gateway;
 * -# Call @b connect() on @p tst_s towards @p addr_to_connect;
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
 *     -# Call @b connect() on @p tst_s towards @p addr_to_connect;
 *     -# If @p sock_type is @c SOCK_DGRAM then
 *        call @b send() on @p tst_s;
 *     -# Check that @p actor is readable;
 *    \n @htmlonly &nbsp; @endhtmlonly
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "basic/derived_bindtodevice"

#include <errno.h>
#include <pthread.h>

#include "sockapi-test.h"
#include "rcf_api.h"
#include "tapi_cfg.h"
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
    int             tst_s = -1;

    const struct if_nameindex *iut_dev_to_bind = NULL;
    const struct if_nameindex *tester_dev_to_bind = NULL;

    const struct sockaddr  *addr_to_bind;
    struct sockaddr_storage wildcard_addr;
    struct sockaddr_storage peer;
    socklen_t               peer_len = sizeof(struct sockaddr_storage);
    
    const struct sockaddr  *addr_to_connect = NULL;

    const struct sockaddr  *gateway = NULL;
    socklen_t               gateway_len;

    const char             *command = NULL;
    rpc_socket_type         sock_type;
    te_bool                 double_acts;
    te_bool                 listen_state;
    const char             *method;

    derived_test_instance  *instances = NULL;
    derived_test_instance  *actor = NULL;
    derived_test_instance  *tracker = NULL;
    int                     inst_num = 0;

    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  tx_buflen;
    size_t                  rx_buflen;

    cfg_handle              rt_handle = CFG_HANDLE_INVALID;
    tapi_env_net           *net_to_connect = NULL;

    te_bool                 use_wildcard = FALSE;

    /* Preambule */
    TEST_START;
  
    TEST_GET_SOCK_TYPE(sock_type);    
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_IF(iut_dev_to_bind);
    TEST_GET_IF(tester_dev_to_bind);

    TEST_GET_ADDR(pco_iut, addr_to_bind);
    domain = rpc_socket_domain_by_addr(addr_to_bind);
    TEST_GET_ADDR_NO_PORT(addr_to_connect);

    gateway = tapi_env_get_addr(&env, "gateway", &gateway_len);

    TEST_GET_STRING_PARAM(command);
    TEST_GET_BOOL_PARAM(double_acts);
    TEST_GET_STRING_PARAM(method);
    TEST_GET_BOOL_PARAM(listen_state);
    TEST_GET_BOOL_PARAM(use_wildcard);
    
    if (gateway != NULL)
    {
        TEST_GET_NET(net_to_connect);
    }

    if (listen_state && sock_type == RPC_SOCK_DGRAM)
        TEST_FAIL("Wrong test parameters, "
                  "udp socket cannot be in listen state");

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

    if (!listen_state)
    {
        /* Bind to device */
        rpc_bind_to_device(actor->rpcs, actor->s,
                           iut_dev_to_bind->if_name);
    }    
    CHECK_SOCKET_STATE(actor->rpcs, actor->s, NULL, -1, STATE_CLEAR);
    if (strcmp(command, "execve") == 0)
    {
        CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
    }
    CHECK_SOCKET_STATE(tracker->rpcs, tracker->s, NULL, -1, STATE_CLEAR);

    memcpy(&wildcard_addr, addr_to_bind,
           te_sockaddr_get_size(addr_to_bind));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));
    rpc_bind(actor->rpcs, actor->s,
             use_wildcard ? SA(&wildcard_addr) : addr_to_bind);
    te_sockaddr_set_port(SA(addr_to_connect), te_sockaddr_get_port(addr_to_bind));
    
    CHECK_SOCKET_STATE(actor->rpcs, actor->s, NULL, -1, STATE_BOUND);
    if (strcmp(command, "execve") == 0)
    {
        CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
    }
    CHECK_SOCKET_STATE(tracker->rpcs, tracker->s, NULL, -1, STATE_BOUND);

    /* Listen */
    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(actor->rpcs, actor->s, SOCKTS_BACKLOG_DEF);

        if (listen_state)
            rpc_bind_to_device(actor->rpcs, actor->s,
                               iut_dev_to_bind->if_name);

        CHECK_SOCKET_STATE(actor->rpcs, actor->s, NULL, -1, STATE_LISTENING);
        if (strcmp(command, "execve") == 0)
        {
            CHECK_RC(rcf_rpc_server_exec(actor->rpcs));
        }
        CHECK_SOCKET_STATE(tracker->rpcs, tracker->s, NULL, -1,
                           STATE_LISTENING);
    }        

    /* Connect/send */
    tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);

    rpc_bind_to_device(pco_tst, tst_s,
                       tester_dev_to_bind->if_name);

    if (gateway != NULL)
    {
        CHECK_RC(tapi_cfg_add_route(pco_tst->ta,
                                    addr_to_connect->sa_family,
                                    te_sockaddr_get_netaddr(addr_to_connect),
                                    te_netaddr_get_size(
                                        addr_to_connect->sa_family) << 3,
                                    te_sockaddr_get_netaddr(gateway),
                                    tester_dev_to_bind->if_name, NULL,
                                    0, 0, 0, 0, 0, 0, &rt_handle));

        CFG_WAIT_CHANGES;
    }

    rpc_connect(pco_tst, tst_s, addr_to_connect);
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
        rpc_connect(pco_tst, tst_s, addr_to_connect);
        if (sock_type == RPC_SOCK_DGRAM)
            rpc_send(pco_tst, tst_s, tx_buf, tx_buflen, 0);
        TAPI_WAIT_NETWORK;
        RPC_CHECK_READABILITY(actor->rpcs, actor->s, TRUE);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (actor != NULL)
    {
        CLEANUP_RPC_CLOSE(actor->rpcs, acc_s);
        CLEANUP_RPC_CLOSE(actor->rpcs, actor->s);
        if (command != NULL && strcmp(command, "fork") == 0)
            CLEANUP_CHECK_RC(rcf_rpc_server_destroy((instances + 1)->rpcs));
        free(instances);
    }
    else
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_CHECK_RC(tapi_cfg_del_route(&rt_handle));

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
