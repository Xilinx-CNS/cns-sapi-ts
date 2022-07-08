/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-get_sock_peer_name_str getsockname()/getpeername() for TCP sockets
 *
 * @objective Check getsockname()/getpeername() behaviour with TCP socket in
 *            different states.
 *
 * @type conformance, compatibility
 *
 * @param env      Private testing environment set:
 *                 - similar to @ref arg_types_env_peer2peer, IUT is TCP server
 *                 - similar to @ref arg_types_env_peer2peer, IUT is TCP client
 *                 - similar to @ref arg_types_env_peer2peer_lo, both client
 *                   and server sockets are on IUT side.
 *
 * @par Scenario:
 *
 * -# Create @c SOCK_STREAM type sockets @p srvr_s, @p clnt_s on 
 *    the @p pco_srvr, @p pco_clnt respectively.
 * -# Call @b getsockname()/getpeername() on the @p srvr_s socket.
 * -# Check that local address and port of @p srvr_s are zeros and 
 *    @b getpeername() on @p srvr_s returned -1 with @b errno @c ENOTCONN.
 * -# Call @b bind() @p srvr_s to @p srvr_addr.
 * -# Call @b getsockname()/getpeername() on the @p srvr_s socket.
 * -# Check that local address and port of @p srvr_s are @p srvr_addr, and
 *    @b getpeername() on @p srvr_s returned -1 with @b errno @c ENOTCONN.
 * -# Call @b bind() @b clnt_s to @p clnt_addr.
 * -# Call @b getsockname()/getpeername() on the @p clnt_s socket.
 * -# Check that local address and port of @p clnt_s are @p clnt_addr, and
 *    @b getpeername() on @p clnt_s returned -1 with @b errno @c ENOTCONN.
 * -# Call @b listen() on the @b srvr_s socket.
 * -# Call @b getsockname()/getpeername() on the @p srvr_s socket.
 * -# Check that local address and port of @p srvr_s are @p srvr_addr, and
 *    @b getpeername() on @p srvr_s returned -1 with @b errno @c ENOTCONN.
 * -# @b connect() @p clnt_s to the @p srvr_s.
 * -# Call @b accept() on the @p srvr_s to get @p acc_s socket.
 * -# Call @b getsockname()/getpeername() on the @p srvr_s.
 * -# Check that local address and port of @p srvr_s are @p srvr_addr, and
 *    @b getpeername() on @p srvr_s returned -1 with @b errno @c ENOTCONN.
 * -# Call @b getsockname()/getpeername() on the @p acc_s socket.
 * -# Check that local address and port of @p acc_s are @p srvr_addr,
 *    and remote address and port are @p clnt_addr.
 * -# Close created sockets.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/get_sock_peer_name_str"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_srvr;
    rcf_rpc_server             *pco_clnt;

    const struct sockaddr      *srvr_addr;
    const struct sockaddr      *clnt_addr;

    struct sockaddr_storage     retaddr;
    socklen_t                   retaddr_len;

    struct sockaddr_storage     wildaddr;

    int                         srvr_s = -1;
    int                         clnt_s = -1;
    int                         acc_s = -1;

    int                         err;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_srvr);
    TEST_GET_PCO(pco_clnt);
    TEST_GET_ADDR(pco_srvr, srvr_addr);
    TEST_GET_ADDR(pco_clnt, clnt_addr);

    memset(&wildaddr, 0, sizeof(wildaddr));
    SA(&wildaddr)->sa_family = srvr_addr->sa_family;

    srvr_s = rpc_socket(pco_srvr, rpc_socket_domain_by_addr(srvr_addr),
                        RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    clnt_s = rpc_socket(pco_clnt, rpc_socket_domain_by_addr(clnt_addr),
                        RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_srvr);
    rc = rpc_getsockname(pco_srvr, srvr_s, SA(&retaddr), &retaddr_len);
    err = RPC_ERRNO(pco_srvr);
    if (rc != 0)
    {
        TEST_FAIL("RPC getsockname() on srvr_s socket failed (not bound) "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    if (te_sockaddrcmp(SA(&retaddr), retaddr_len, SA(&wildaddr),
                       sizeof(wildaddr)) != 0)
    {
        TEST_FAIL("unexpected socket address returned by getsockname()"
                  " on srvr_s (not bound)");
    }

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_srvr);
    rc = rpc_getpeername(pco_srvr, srvr_s, SA(&retaddr), &retaddr_len);
    if (rc != -1)
    {
        TEST_FAIL("unexpected getpeername() return code on srvr_s "
                  "(not bound), rc=%d", rc);
    }
    err = RPC_ERRNO(pco_srvr);
    if (err != RPC_ENOTCONN)
    {
        TEST_FAIL("unexpected getpeername() errno on srvr_s (not bound) "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    rpc_bind(pco_srvr, srvr_s, srvr_addr);

    retaddr_len = sizeof(retaddr);
    rpc_getsockname(pco_srvr, srvr_s, SA(&retaddr), &retaddr_len);

    CHECK_NAME(&retaddr, retaddr_len);

    rc = te_sockaddrcmp(SA(&retaddr), retaddr_len,
                        srvr_addr, te_sockaddr_get_size(srvr_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by getsockname() "
                  "(bound)");
    }

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_srvr);
    rc = rpc_getpeername(pco_srvr, srvr_s, SA(&retaddr), &retaddr_len);
    if (rc != -1)
    {
        TEST_FAIL("unexpected getpeername() return code on srvr_s "
                  "(bound), rc=%d", rc);
    }
    err = RPC_ERRNO(pco_srvr);
    if (err != RPC_ENOTCONN)
    {
        TEST_FAIL("unexpected getpeername() errno on srvr_s (bound) "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    rpc_bind(pco_clnt, clnt_s, clnt_addr);

    retaddr_len = sizeof(retaddr);
    rpc_getsockname(pco_clnt, clnt_s, SA(&retaddr), &retaddr_len);

    CHECK_NAME(&retaddr, retaddr_len);

    rc = te_sockaddrcmp(SA(&retaddr), retaddr_len,
                        clnt_addr, te_sockaddr_get_size(clnt_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by "
                  "getsockname() on clnt_s (bound)");
    }

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_clnt);
    rc = rpc_getpeername(pco_clnt, clnt_s, SA(&retaddr), &retaddr_len);
    if (rc != -1)
    {
        TEST_FAIL("unexpected getpeername() return code on clnt_s (bound), "
                  "rc=%d", rc);
    }
    err = RPC_ERRNO(pco_clnt);
    if (err != RPC_ENOTCONN)
    {
        TEST_FAIL("unexpected getpeername() errno on clnt_s (bound) "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    rpc_listen(pco_srvr, srvr_s, SOCKTS_BACKLOG_DEF);

    retaddr_len = sizeof(retaddr);
    rpc_getsockname(pco_srvr, srvr_s, SA(&retaddr), &retaddr_len);

    CHECK_NAME(&retaddr, retaddr_len);

    rc = te_sockaddrcmp(SA(&retaddr), retaddr_len,
                        srvr_addr, te_sockaddr_get_size(srvr_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by "
                  "getsockname() (after listen)");
    }

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_srvr);
    rc = rpc_getpeername(pco_srvr, srvr_s, SA(&retaddr), &retaddr_len);
    if (rc != -1)
    {
        TEST_FAIL("unexpected getpeername() return code on srvr_s "
                  "(after listen), rc=%d", rc);
    }
    err = RPC_ERRNO(pco_srvr);
    if (err != RPC_ENOTCONN)
    {
        TEST_FAIL("unexpected getpeername() errno on srvr_s (after listen) "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    rpc_connect(pco_clnt, clnt_s, srvr_addr);

    acc_s = rpc_accept(pco_srvr, srvr_s, NULL, NULL);

    retaddr_len = sizeof(retaddr);
    rpc_getsockname(pco_srvr, srvr_s, SA(&retaddr), &retaddr_len);

    CHECK_NAME(&retaddr, retaddr_len);

    rc = te_sockaddrcmp(SA(&retaddr), retaddr_len,
                        srvr_addr, te_sockaddr_get_size(srvr_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by "
                  "getsockname() (after accept)");
    }

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_srvr);
    rc = rpc_getpeername(pco_srvr, srvr_s, SA(&retaddr), &retaddr_len);
    if (rc != -1)
    {
        ERROR("unexpected getpeername() return code on srvr_s "
              "(after accept), rc=%d", rc);
        err = RPC_ERRNO(pco_srvr);
        if (err != RPC_ENOTCONN)
            ERROR("unexpected getpeername() errno on srvr_s (after accept)"
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
        TEST_STOP;
    }

    rc = sockts_compare_sock_peer_name(pco_srvr, acc_s, pco_clnt, clnt_s);
    if (rc != 0)
        TEST_FAIL("acc_s socket local address is not validated");

    rc = sockts_compare_sock_peer_name(pco_clnt, clnt_s, pco_srvr, acc_s);
    if (rc != 0)
         TEST_FAIL("acc_s socket remote address is not validated");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_srvr, srvr_s);
    CLEANUP_RPC_CLOSE(pco_clnt, clnt_s);
    CLEANUP_RPC_CLOSE(pco_srvr, acc_s);

    TEST_END;
}
