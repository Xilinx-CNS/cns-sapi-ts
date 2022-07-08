/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-listen_shutdown_listen Check a possibility to repair socket to the listening state after shutdown
 *
 * @objective Check a possibility to repair the socket to the listening
 *            state after shutdowning in the case with/without of
 *            complete connection on the server.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param connection Establish TCP connection before @b shutdown() if @c TRUE.
 * @param reuseaddr  Set @c SO_REUSEADDR on the listening socket or not.
 * @param bind_before_listen    Perform bind() before lister() (iterate with
 *                              @p use_wildcard_before):
 *                              - no: don't bind
 *                              - specified: bind to non-zero port
 *                              - unspecified: bind to zero port
 * @param use_wildcard_before   Use @c INADDR_ANY binding before listen() if
 *                              @c TRUE.
 * @param bind_after_shutdown    Perform bind() after shutdown() (iterate with
 *                              @p use_wildcard_after):
 *                              - no: don't bind
 *                              - specified: bind to non-zero port
 *                              - unspecified: bind to zero port
 * @param use_wildcard_after    Use @c INADDR_ANY binding before listen() if
 *                              @c TRUE.
 *
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of the @p SOCK_STREAM type.
 * -# If @p reuseaddr is @c TRUE set @c SO_REUSEADDR on @p iut_s.
 * -# If @p bind_before_listen is @c specified, @b bind() it to
 *    the @p iut_addr address/port. If @p bind_before_listen is
 *    @c unspecified, @b bind() it to the @p iut_addr address and zero
 *    port.
 * -# Call @b listen() on @p iut_s.
 * -# Call @b getsockname() on @p iut_s socket and remember the result
 *    as @p listen1_addr. Check that:
 *      - If @p bind_before_listen is @c specified, @p listen_addr is
 *        equal to @p iut_addr;
 *      - If  @p bind_before_listen is @c unspecified, network address 
 *        in @p listen_addr is equal to network address in @p iut_addr.
 * -# If @p connection is @c TRUE:
 *      - Create the @p tst_s socket of the @p SOCK_STREAM type anew,
 *      - @b connect() @p tst_s to the @p iut_s,
 *      - @b accept() on @p iut_s new @p acc_s connection.
 * -# @b shutdown() @p iut_s for reading.
 * -# If @p bind_after_shutdown is:
 *      - @c specified, try to @b bind() @p iut_s to the @p iut_addr
 *        address and a new port. 
 *      - @c unspecified, try to @b bind() @p iut_s to the @p iut_addr
 *        address and zero port.
 *      .
 *    If @p bind_before_listen is @p specified, the second @b bind()
 *    has to fail with @c EINVAL errno.
 * -# Call @b listen() on @p iut_s. If @p connection is @c TRUE and 
 *    @p reuseaddr is @c FALSE, @b listen() has to return @c -1 with
 *    @c EADDRINUSE errno (test is finished).
 * -# Call @b getsockname() on @p iut_s socket and remember the result
 *    as @p listen2_addr. Check that:
 *      - If at least one of @p bind_before_listen or
 *        @p bind_after_shutdown is not @c no, network address in
 *        @p listen2_addr is equal to network address in @p iut_addr;
 *      - If neither @p bind_before_listen nor
 *        @p bind_after_shutdown is @c specified, ports in
 *        @p listen1_addr and @p listen2_addr have to be not equal.
 * -# If @p connection is @c TRUE:
 *      - @b close() @p acc_s,
 *      - @b close() @p tst_s,
 * -# If @p connection is @c FALSE or @p reuseaddr is @c TRUE:
 *      -# Create the @p tst_s socket of the @p SOCK_STREAM type.
 *      -# @b connect() @p tst_s to the @p iut_s server socket.
 *      -# @b accept() on @p iut_s new @p acc_s connection.
 * -# @b close() created sockets.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/listen_shutdown_listen"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut;
    rcf_rpc_server        *pco_tst;

    int                    iut_s = -1;
    int                    acc_s = -1;
    int                    tst_s = -1;
    int                    ret;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    opt_val;
    te_bool                connection;
    te_bool                reuseaddr;
    const char            *bind_before_listen = NULL;
    const char            *bind_after_shutdown = NULL;

    struct sockaddr_storage     bind_addr;
    struct sockaddr_storage     listen1_addr;
    socklen_t                   listen1_addrlen;
    struct sockaddr_storage     listen2_addr;
    socklen_t                   listen2_addrlen;

    te_bool             use_wildcard_before = FALSE;
    te_bool             use_wildcard_after = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(connection);
    TEST_GET_BOOL_PARAM(reuseaddr);
    TEST_GET_STRING_PARAM(bind_before_listen);
    TEST_GET_STRING_PARAM(bind_after_shutdown);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(use_wildcard_before);
    TEST_GET_BOOL_PARAM(use_wildcard_after);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    if (reuseaddr)
    {
        opt_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_REUSEADDR, &opt_val);
    }

    memcpy(&bind_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    if (strcmp(bind_before_listen, "unspecified") == 0)
        te_sockaddr_set_port(SA(&bind_addr), 0);
    if (use_wildcard_before)
        te_sockaddr_set_wildcard(SA(&bind_addr));
    if (strcmp(bind_before_listen, "no") != 0)
        rpc_bind(pco_iut, iut_s, SA(&bind_addr)); 

    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    listen1_addrlen = sizeof(listen1_addr);
    rpc_getsockname(pco_iut, iut_s, SA(&listen1_addr), &listen1_addrlen);
    if (strcmp(bind_before_listen, "unspecified") == 0)
    {
        if (memcmp(te_sockaddr_get_netaddr(SA(&listen1_addr)),
                   te_sockaddr_get_netaddr(SA(&bind_addr)),
                   te_netaddr_get_size(iut_addr->sa_family)) != 0)
        {
            TEST_FAIL("getsockname() returned incorrect address "
                      "when bound to specified address and "
                      "unspecified port");
        }
    }
    else if (strcmp(bind_before_listen, "specified") == 0)
    {
        if (te_sockaddrcmp(SA(&bind_addr), te_sockaddr_get_size(SA(&bind_addr)),
                           SA(&listen1_addr), listen1_addrlen) != 0)
        {
            TEST_FAIL("getsockname() returned incorrect address "
                      "when bound to specified address/port");
        }
    }

    if (connection)
    {
        if (strcmp(bind_before_listen, "no") == 0 || use_wildcard_before)
        {
            memcpy(te_sockaddr_get_netaddr(SA(&listen1_addr)),
                   te_sockaddr_get_netaddr(iut_addr),
                   te_netaddr_get_size(iut_addr->sa_family));
        }

        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s, SA(&listen1_addr));
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);
    if (ret != 0)
    {
        TEST_VERDICT("shutdown(SHUT_RD) of listening socket failed "
                     "with errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (strcmp(bind_after_shutdown, "no") != 0)
    {
        memcpy(&bind_addr, iut_addr, te_sockaddr_get_size(iut_addr));
        if (strcmp(bind_after_shutdown, "unspecified") == 0)
            te_sockaddr_set_port(SA(&bind_addr), 0);
        else if (strcmp(bind_after_shutdown, "specified") == 0)
            TAPI_SET_NEW_PORT(pco_iut, &bind_addr);
        if (use_wildcard_after)
            te_sockaddr_set_wildcard(SA(&bind_addr));

        RPC_AWAIT_IUT_ERROR(pco_iut);
        ret = rpc_bind(pco_iut, iut_s, SA(&bind_addr));

        if (strcmp(bind_before_listen, "specified") == 0)
        {
            if (ret != -1 || RPC_ERRNO(pco_iut) != RPC_EINVAL)
            {
                TEST_VERDICT("The second bind after fully specified the "
                             "first bind returned unexpected result: "
                             "rc=%d, errno=%r", ret, RPC_ERRNO(pco_iut));
            }
        }
        else if (ret != 0)
        {
            TEST_VERDICT("bind() after shutdown() of listening socket "
                         "bound %s unexpectedly failed",
                         (strcmp(bind_before_listen, "no") == 0) ?
                         "implicitly" : "to unspecified port");
        }
    }

    if (connection && !reuseaddr &&
        (strcmp(bind_before_listen, "specified") == 0))
        RPC_AWAIT_IUT_ERROR(pco_iut);

    rc = rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    
    if (connection && !reuseaddr &&
        (strcmp(bind_before_listen, "specified") == 0))
    {
        if (rc != -1)
        {
            TEST_VERDICT("SO_REUSEADDR socket option is not set on "
                         "a listening socket before accept of "
                         "a connection, however attempt to restart "
                         "listening after shutdown returned %d "
                         "instead of -1 with EADDRINUSE errno", rc);
        }
        CHECK_RPC_ERRNO(pco_iut, RPC_EADDRINUSE,
                        "SO_REUSEADDR socket option is not set on "
                        "a listening socket before accept of "
                        "a connection, however attempt to restart "
                        "listening after shutdown returned -1");
    }
    else
    {
        if (connection)
        {
            RPC_CLOSE(pco_iut, acc_s);
            RPC_CLOSE(pco_tst, tst_s);
        }

        listen2_addrlen = sizeof(listen2_addr);
        rpc_getsockname(pco_iut, iut_s,
                        SA(&listen2_addr), &listen2_addrlen);
        if (strcmp(bind_before_listen, "no") != 0 ||
            strcmp(bind_after_shutdown, "no") != 0)
        {
            memcpy(te_sockaddr_get_netaddr(SA(&bind_addr)),
                   te_sockaddr_get_netaddr(iut_addr),
                   te_netaddr_get_size(iut_addr->sa_family));
            if (((strcmp(bind_before_listen, "no") != 0 &&
                  use_wildcard_before) ||
                 (strcmp(bind_before_listen, "specified") != 0 &&
                  strcmp(bind_after_shutdown, "no") != 0 &&
                  use_wildcard_after)) &&
                !(strcmp(bind_before_listen, "unspecified") == 0 &&
                  use_wildcard_before && !use_wildcard_after &&
                  strcmp(bind_after_shutdown, "no") != 0))
                te_sockaddr_set_wildcard(SA(&bind_addr));

            if (memcmp(te_sockaddr_get_netaddr(SA(&listen2_addr)),
                       te_sockaddr_get_netaddr(SA(&bind_addr)),
                       te_netaddr_get_size(iut_addr->sa_family)) != 0)
            {
                TEST_VERDICT("getsockname() returned incorrect network "
                             "address when at least one of bind() calls "
                             "was to specified network address");
            }
        }
        if (strcmp(bind_before_listen, "specified") == 0)
        {
            if (te_sockaddr_get_port(SA(&listen2_addr)) !=
                te_sockaddr_get_port(iut_addr))
            {
                TEST_VERDICT("getsockname() returned incorrect port "
                             "when the first bind() has specified port");
            }
        }
        else if (strcmp(bind_after_shutdown, "specified") == 0)
        {
            if (te_sockaddr_get_port(SA(&listen2_addr)) !=
                te_sockaddr_get_port(SA(&bind_addr)))
            {
                TEST_VERDICT("getsockname() returned incorrect port "
                             "when the second bind() has specified port");
            }
        }
        else if (te_sockaddr_get_port(SA(&listen1_addr)) ==
                 te_sockaddr_get_port(SA(&listen2_addr)))
        {
            TEST_VERDICT("The second %sbind() to unspecified port did "
                         "not changed used port",
                         (strcmp(bind_after_shutdown, "no") == 0) ?
                            "implicit " : "");
        }

        memcpy(te_sockaddr_get_netaddr(SA(&listen2_addr)),
               te_sockaddr_get_netaddr(iut_addr),
               te_netaddr_get_size(iut_addr->sa_family));

        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

        rpc_connect(pco_tst, tst_s, SA(&listen2_addr));

        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);

        {
            char buf[1];

            buf[0] = 'a';
            rpc_send(pco_iut, acc_s, buf, sizeof(buf), 0);
            rpc_recv(pco_tst, tst_s, buf, sizeof(buf), 0);
            if (buf[0] != 'a')
                TEST_VERDICT("Data corruption");
            buf[0] = 'b';
            rpc_send(pco_tst, tst_s, buf, sizeof(buf), 0);
            rpc_recv(pco_iut, acc_s, buf, sizeof(buf), 0);
            if (buf[0] != 'b')
                TEST_VERDICT("Data corruption");
        }
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
