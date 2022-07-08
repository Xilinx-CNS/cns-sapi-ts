/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-close_listen_pending Close listening socket with pending connections
 *
 * @objective Check that listening socket with pending connections
 *            can be successfully closed.
 *
 * @type Conformance, compatibility
 *
 * @param env       Private set of environment which iterates
 *                  @ref arg_types_env_peer2peer and
 *                  @ref arg_types_env_peer2peer_ipv6 like
 *                  and two kinds of loopback envs (with IPv4/IPv6 addresses).
 * @param accept    Determines host where from connection requests are
 *                  performed (see @p env YACC code):
 *                  - none
 *                  - clnt1
 *                  - clnt2
 *@param send_data  Send data from client sockets if @c TRUE.
 *
 * @par Scenario:
 *
 * -# Create socket @p srv_s on @p pco_srvr of the @c SOCK_STREAM type.
 * -# @b bind() @p srv_s with parameters: wildcard IP address and zero port.
 * -# Call @b listen() on @p srv_s with @a backlog greater than one.
 * -# Perform routine #sockts_get_socket_state on @p srv_s.
 * -# Check that obtained state of @p srv_s is the @c STATE_LISTENING.
 * -# Create accepted connection according to @p accept parameter.
 * -# Create socket @p clnt1_s on @p pco_clnt1 of the @c SOCK_STREAM type.
 * -# @b connect() @p clnt1_s to the @p srv_s.
 * -# Create socket @p clnt2_s on @p pco_clnt2 of the @c SOCK_STREAM type.
 * -# @b connect() @p clnt2_s to the @p srv_s.
 * -# @b close() @p srv_s.
 * -# Perform routine #sockts_get_socket_state on @p srv_s.
 * -# Check that obtained state of @p srv_s is the @c STATE_CLOSED.
 * -# Call @b recv() on @p clnt1_s.
 * -# Check that @b recv() above immediately returns -1 and 
 *    @c ECONNRESET @b errno.
 * -# Call @b recv() on @p clnt2_s.
 * -# Check that @b recv() above immediately returns -1 and
 *    @c ECONNRESET @b errno.
 * -# @b close() all sockets.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/close_listen_pending"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_srvr;
    rcf_rpc_server         *pco_clnt0;
    rcf_rpc_server         *pco_clnt1;
    rcf_rpc_server         *pco_clnt2;

    const struct sockaddr  *srv_addr;
    const struct sockaddr  *clnt1_addr;
    const struct sockaddr  *clnt2_addr;

    int                     srv_s = -1;
    int                     acc_s = -1;
    int                     clnt0_s = -1;
    int                     clnt1_s = -1;
    int                     clnt2_s = -1;
    
    struct sockaddr_storage wild_addr;
    socklen_t               wild_addrlen;

    struct sockaddr_storage listen_addr;

    void                   *tx_buf = NULL;
    size_t                  tx_buf_len;
    char                    buf[10] = { 0, };

    const char             *accept;
    te_bool                 acc;    /* Whether to make accepted connection
                                       or not */
    te_bool                 send_data = FALSE;
    rpc_socket_domain       domain;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_srvr);
    TEST_GET_PCO(pco_clnt1);
    TEST_GET_PCO(pco_clnt2);
    TEST_GET_ADDR(pco_srvr, srv_addr);
    TEST_GET_ADDR(pco_clnt1, clnt1_addr);
    TEST_GET_ADDR(pco_clnt2, clnt2_addr);
    TEST_GET_STRING_PARAM(accept);
    TEST_GET_BOOL_PARAM(send_data);

    if (send_data)
        tx_buf = sockts_make_buf_stream(&tx_buf_len);

    if (strcmp(accept, "none") == 0)
    {
        acc = FALSE;
    }
    else if (strcmp(accept, "clnt1") == 0)
    {
        acc = TRUE;
        pco_clnt0 = pco_clnt1;
    }
    else if (strcmp(accept, "clnt2") == 0)
    {
        acc = TRUE;
        pco_clnt0 = pco_clnt2;
    }
    else
    {
        TEST_FAIL("Unexpected accept parameter value, %s", accept);
    }

    domain = rpc_socket_domain_by_addr(srv_addr);

    memset(&wild_addr, 0, sizeof(wild_addr));
    SA(&wild_addr)->sa_family = srv_addr->sa_family;

    srv_s = rpc_socket(pco_srvr, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_srvr, srv_s, SA(&wild_addr));

    rpc_listen(pco_srvr, srv_s, 2);

    wild_addrlen = sizeof(wild_addr);
    rpc_getsockname(pco_srvr, srv_s, SA(&wild_addr), &wild_addrlen);
    listen_addr = wild_addr;
    te_sockaddr_set_netaddr(SA(&listen_addr),
                            te_sockaddr_get_netaddr(srv_addr));

    CHECK_SOCKET_STATE(pco_srvr, srv_s, NULL, -1, STATE_LISTENING);

    if (acc)
    {
        clnt0_s = rpc_socket(pco_clnt0,
                             domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_clnt0, clnt0_s, SA(&listen_addr));
        TAPI_WAIT_NETWORK;
        acc_s = rpc_accept(pco_srvr, srv_s, NULL, NULL);
    }

    clnt1_s = rpc_socket(pco_clnt1, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_clnt1, clnt1_s, clnt1_addr);
    rpc_connect(pco_clnt1, clnt1_s, SA(&listen_addr));
    if (send_data)
        RPC_SEND(rc, pco_clnt1, clnt1_s, tx_buf, tx_buf_len, 0);

    clnt2_s = rpc_socket(pco_clnt2, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_clnt2, clnt2_s, clnt2_addr);
    rpc_connect(pco_clnt2, clnt2_s, SA(&listen_addr));
    if (send_data)
        RPC_SEND(rc, pco_clnt2, clnt2_s, tx_buf, tx_buf_len, 0);

    TAPI_WAIT_NETWORK;
    {
        int srv_s_copy = srv_s; 
        
        rpc_closesocket(pco_srvr, srv_s);
        srv_s = -1;
        CHECK_SOCKET_STATE(pco_srvr, srv_s_copy, NULL, -1, STATE_CLOSED);
    }

    RPC_AWAIT_IUT_ERROR(pco_clnt1);
    rc = rpc_recv(pco_clnt1, clnt1_s, buf, sizeof(buf), 0);
    if (rc != -1)
    {
        TEST_FAIL("Reading from the first connected socket when server "
                  "closes listening socket before accept returns %d "
                  "instead of -1", rc);
    }
    CHECK_RPC_ERRNO(pco_clnt1, RPC_ECONNRESET,
                    "Reading from the first connected socket when server "
                    "closes listening socket before accept returns -1, "
                    "but");

    RPC_AWAIT_IUT_ERROR(pco_clnt2);
    rc = rpc_recv(pco_clnt2, clnt2_s, buf, sizeof(buf), 0);
    if (rc != -1)
    {
        TEST_FAIL("Reading from the second connected socket when server "
                  "closes listening socket before accept returns %d "
                  "instead of -1", rc);
    }
    CHECK_RPC_ERRNO(pco_clnt2, RPC_ECONNRESET,
                    "Reading from the second connected socket when server "
                    "closes listening socket before accept returns -1, "
                    "but");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_clnt1, clnt1_s);
    CLEANUP_RPC_CLOSE(pco_clnt2, clnt2_s);
    CLEANUP_RPC_CLOSE(pco_clnt0, clnt0_s);
    CLEANUP_RPC_CLOSE(pco_srvr, acc_s);

    free(tx_buf);

    TEST_END;
}
