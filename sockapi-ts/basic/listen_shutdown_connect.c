/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-listen_shutdown_connect Call connect after shutdown on listening socket
 *
 * @objective Check that connect() works correclty after shutdown on
 *            listening socket.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param bind  How to bind IUT socket:
 *              - no: do not bind
 *              - unspecified: @b bind() to unspecified port
 *              - specified: @b bind() to specified port
 * @param use_wildcard  Bind to wildcard address if @c TRUE.
 *
 * @par Scenario:
 *
 * -# Create sockets @p iut_s on @p pco_iut and @p tst_s on @p pco_tst of
 *    the @c SOCK_STREAM type.
 * -# Call @b listen() on @p tst_s socket.
 * -# @b bind() @p iut_s according to the @p bind parameter.
 * -# Call @b listen() on @p iut_s socket.
 * -# Call @b shutdown(SHUT_RD) on @p iut_s socket.
 * -# Call @b connect() on @p iut_s socket to connect to @p tst_s socket.
 * -# Call @b accept() on @p tst_s socket and check peer name on accepted
 *    socket and socket name on @p iut_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/listen_shutdown_connect"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;

    struct sockaddr_storage    aux1_addr;
    socklen_t                  aux1_addrlen;
    struct sockaddr_storage    aux2_addr;
    socklen_t                  aux2_addrlen;
    
    const char                *bind;

    int                        iut_s = -1;
    int                        tst_s = -1;
    int                        acc_s = -1;

    int                        ret;
    te_bool                    use_wildcard = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(bind);
    TEST_GET_BOOL_PARAM(use_wildcard);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    aux1_addrlen = te_sockaddr_get_size(iut_addr);
    memcpy(&aux1_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    if (strcmp(bind,"unspecified") == 0)
        te_sockaddr_set_port(SA(&aux1_addr), 0);
    if (use_wildcard)
        te_sockaddr_set_wildcard(SA(&aux1_addr));

    if (strcmp(bind, "no") != 0)
        rpc_bind(pco_iut, iut_s, SA(&aux1_addr));

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);
    if (ret != 0)
    {
        TEST_VERDICT("shutdown(SHUT_RD) of listening socket failed "
                     "with errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    rpc_connect(pco_iut, iut_s, tst_addr);

    aux1_addrlen = sizeof(aux1_addr);
    acc_s = rpc_accept(pco_tst, tst_s, SA(&aux1_addr), &aux1_addrlen);

    /* Check peer name on Tester and sock name on IUT*/
    aux2_addrlen = sizeof(aux2_addr);
    rpc_getsockname(pco_iut, iut_s, SA(&aux2_addr), &aux2_addrlen);

    rc = te_sockaddrcmp(SA(&aux1_addr), aux1_addrlen,
                        SA(&aux2_addr), aux2_addrlen);
    if (rc != 0)
    {
        TEST_FAIL("Socket address/port returned by getpeername() on tst_s"
                  "and getsockname() on iut_s are not equal.");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    TEST_END;
}
