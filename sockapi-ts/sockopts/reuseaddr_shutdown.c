/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id:
 */

/** @page sockopts-reuseaddr_shutdown Possibility of binding to the same address after shutdown() call on listening socket with SO_REUSEADDR.
 *
 * @objective Check that @c SO_REUSEADDR socket option does not allow
 *            to have new TCP socket bound to the same address
 *            immediately after @b shutdown() was called for previous
 *            listening one.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param iut_addr      address on pco_iut
 * @param pco_tst       PCO on TST
 * @param accepted      Should we use accepted connection?
 * @param wildcard      Should we use wildcard address or @iut_addr to @b
 *                      bind() socket?
 * @param auto_port     Should we allow kernel to select port on its own
 *                      when binding to wildcard address?
 * @param how_to_shut   Flag used when calling @b shutdown().
 *
 * @par Test sequence:
 * -# Create @p iut_s_old socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Call @b setsockopt() enabling @c SO_REUSEADDR socket option on
 *    @p iut_s_old.
 * -# Assign @p iut_bind_addr according values of @p wildcard and
 *    @p auto_port parameters.
 * -# @b bind() @p iut_s_old socket to @p iut_bind_addr address.
 * -# Call @b listen() for @p iut_s_old socket.
 * -# Create @p tst_s socket on the @p pco_tst and @b connect() it to
 *    @p iut_s_old socket.
 * -# If @p accepted is @c TRUE, call @b accept() on @p iut_s_old socket.
 * -# Call @b shutdown() for @p iut_s_old socket.
 * -# Create new @p iut_s_new socket, set SO_REUSEADDR for it and try to
 *    @b bind() it to the @p iut_bind_addr address the first socket was
 *    bound to.
 * -# Check that the function returns @c -1 and sets @b errno to @c
 *    EADDRINUSE.
 *
 * @note For linux kernel of version less than 2.6.38 it is possible to
 *       @b bind() new socket after @b shutdown() call, but in kernel
 *       v2.6.38 it is not (if wildcard address is not used with zero port).
 *       If wildcard is used with zero port (binding to 0.0.0.0:0), kernel
 *       v2.6.38 also allows binding after @b shutdown() call.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/reuseaddr_shutdown"

#include "sockapi-test.h"

#define MIN_PORT 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    int             iut_s_old = -1;
    int             iut_s_new = -1;
    int             tst_s = -1;
    int             acc_s = -1;
    int             opt_val = 1;
    unsigned int    addr_len = 0;
    te_bool         wildcard = FALSE;
    te_bool         accepted = FALSE;
    te_bool         auto_port = FALSE;

    rpc_shut_how    how_to_shut = RPC_SHUT_NONE;

    const struct sockaddr  *iut_addr = NULL;
    struct sockaddr_storage iut_bind_addr;
    struct sockaddr_storage tst_connect_addr;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(accepted);
    TEST_GET_BOOL_PARAM(wildcard);
    if (wildcard == TRUE)
        TEST_GET_BOOL_PARAM(auto_port);
    TEST_GET_SHUT_HOW(how_to_shut);

    iut_s_old = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_setsockopt(pco_iut, iut_s_old, RPC_SO_REUSEADDR, &opt_val);

    tapi_sockaddr_clone_exact(iut_addr, &iut_bind_addr);

    if (wildcard)
    {
        te_sockaddr_set_wildcard(SA(&iut_bind_addr));

        if (!auto_port)
            te_sockaddr_set_port(SA(&iut_bind_addr),
                                 te_sockaddr_get_port(iut_addr));
        else
            te_sockaddr_clear_port(SA(&iut_bind_addr));
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_s_old, SA(&iut_bind_addr));

    if (rc == -1)
    {
        RING_VERDICT("bind() doesn't work");
        TEST_FAIL("bind() returned -1 for the first socket");
    }

    addr_len = sizeof(tst_connect_addr);
    rpc_getsockname(pco_iut, iut_s_old, SA(&iut_bind_addr), &addr_len);
    tapi_sockaddr_clone_exact(SA(&iut_bind_addr), &tst_connect_addr);
    if (wildcard)
        te_sockaddr_set_netaddr(SA(&tst_connect_addr),
                                te_sockaddr_get_netaddr(iut_addr));

    rpc_listen(pco_iut, iut_s_old, SOCKTS_BACKLOG_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst_s, SA(&tst_connect_addr));

    if (accepted == TRUE)
        acc_s = rpc_accept(pco_iut, iut_s_old, NULL, 0);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_shutdown(pco_iut, iut_s_old, how_to_shut);
    if (rc != -1)
        RING("shutdown() call is allowed for listening socket");
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN, "shutdown() didn't return "
                        "correct error code");
        TEST_VERDICT("shutdown() is impossible for listening socket");
    }

    iut_s_new = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_setsockopt(pco_iut, iut_s_new, RPC_SO_REUSEADDR, &opt_val);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_s_new, SA(&iut_bind_addr));
    if (rc != -1)
        RING("bind() after listen() and shutdown() is possible");
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EADDRINUSE, "listen() on 'iut_s_old' "
                        "socket didn't return correct error code");
        TEST_VERDICT("bind() after listen() and shutdown() is impossible");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_new);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_old);

    TEST_END;
}

