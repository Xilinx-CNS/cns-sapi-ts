/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-get_sock_peer_name_dgm getsockname()/getpeername() for datagram sockets
 *
 * @objective Check getsockname()/getpeername() behaviour with socket in
 *            different states.
 *
 * @type conformance, compatibility
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 *
 * @par Scenario:
 *
 * -# Create @c SOCK_DGRAM type socket @p sock on the @p pco.
 * -# Call @b getsockname()/getpeername() on the @p sock socket.
 * -# Check that local address and port of @p sock are zeros and
 *    @b getpeername() on @p sock returned -1 with @b errno @c ENOTCONN.
 * -# Call @b bind() @p sock to @p iut_addr.
 * -# Call @b getsockname()/getpeername() on the @p sock socket.
 * -# Check that local address and port of @p sock are @p iut_addr, and
 *    @b getpeername() on @p sock returned -1 with @b errno @c ENOTCONN.
 * -# Call @b sendto() on the @p sock to the @p tst_addr.
 * -# Call @b getsockname()/getpeername() on the @p sock.
 * -# Check that local address and port of @p sock are @p iut_addr, and
 *    @b getpeername() on @p sock returned -1 with @b errno @c ENOTCONN.
 * -# @b connect() @p sock to the @p tst_addr.
 * -# Call @b getsockname()/getpeername() on the @p sock.
 * -# Check that local address and port of @p sock are @p iut_addr,
 *    and remote address and port are @p tst_addr.
 * -# Close created sockets.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/get_sock_peer_name_dgm"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut;
    rcf_rpc_server             *pco_tst;

    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;

    int                         iut_s = -1;

    struct sockaddr_storage     retaddr;
    socklen_t                   retaddr_len;

    struct sockaddr_storage     wildaddr;

    uint8_t                     buf[10] = { 0, };
    int                         err;


    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memset(&wildaddr, 0, sizeof(wildaddr));
    SA(&wildaddr)->sa_family = iut_addr->sa_family;

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, iut_s, SA(&retaddr), &retaddr_len);
    err = RPC_ERRNO(pco_iut);

    if (rc != 0)
    {
        TEST_FAIL("RPC getsockname() on iut_s socket failed (not bound), "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    if (te_sockaddrcmp(SA(&retaddr), retaddr_len,
                       SA(&wildaddr), sizeof(wildaddr)) != 0)
    {
        TEST_FAIL("unexpected socket address returned by getsockname()"
                  " on iut_s (not bound)");
    }

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, iut_s, SA(&retaddr), &retaddr_len);
    if (rc != -1)
    {
        TEST_FAIL("unexpected getpeername() return code on iut_s, rc=%d",
                  rc);
    }
    err = RPC_ERRNO(pco_iut);
    if (err != RPC_ENOTCONN)
    {
        TEST_FAIL("unexpected getpeername() errno on iut_s"
                  "RPC_errno=%r", TE_RC_GET_ERROR(err));
    }

    rpc_bind(pco_iut, iut_s, iut_addr);

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, iut_s, SA(&retaddr), &retaddr_len);
    if (rc != 0)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC getsockname() on iut_s socket failed (bound), "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    CHECK_NAME(SA(&retaddr), retaddr_len);

    rc = te_sockaddrcmp(SA(&retaddr), retaddr_len,
                        iut_addr, te_sockaddr_get_size(iut_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by getsockname()");
    }

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, iut_s, SA(&retaddr), &retaddr_len);
    if (rc != -1)
    {
        TEST_FAIL("unexpected getpeername() return code on iut_s(bound), "
                  "rc=%d", rc);
    }
    err = RPC_ERRNO(pco_iut);
    if (err != RPC_ENOTCONN)
    {
        TEST_FAIL("unexpected getpeername() errno on iut_s(bound)"
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    RPC_SENDTO(rc, pco_iut, iut_s, buf, sizeof(buf), 0, tst_addr);

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, iut_s, SA(&retaddr), &retaddr_len);
    if (rc != 0)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC getsockname() on iut_s socket failed "
                  "(after sendto()), RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    CHECK_NAME(SA(&retaddr), retaddr_len);

    rc = te_sockaddrcmp(SA(&retaddr), retaddr_len,
                        iut_addr, te_sockaddr_get_size(iut_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by "
                  "getsockname() (after sendto())");
    }

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, iut_s, SA(&retaddr), &retaddr_len);
    if (rc != -1)
    {
        TEST_FAIL("unexpected getpeername() return code on "
                  "iut_s(after sendto()), rc=%d", rc);
    }
    err = RPC_ERRNO(pco_iut);
    if (err != RPC_ENOTCONN)
    {
        TEST_FAIL("unexpected getpeername() errno on iut_s(after sendto()) "
                  "RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    rpc_connect(pco_iut, iut_s, tst_addr);

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockname(pco_iut, iut_s, SA(&retaddr), &retaddr_len);
    if (rc != 0)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC getsockname() on iut_s socket failed "
                  "(after connect()) RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    CHECK_NAME(SA(&retaddr), retaddr_len);

    rc = te_sockaddrcmp(SA(&retaddr), retaddr_len,
                        iut_addr, te_sockaddr_get_size(iut_addr));
    if(rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by getsockname()"
                  "(after connect())");
    }

    retaddr_len = sizeof(retaddr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, iut_s, SA(&retaddr), &retaddr_len);
    if (rc != 0)
    {
        err = RPC_ERRNO(pco_iut);
        TEST_FAIL("RPC getpeername() on iut_s socket failed "
                  "(after connect()) RPC_errno=%X", TE_RC_GET_ERROR(err));
    }

    CHECK_NAME(SA(&retaddr), retaddr_len);

    rc = te_sockaddrcmp(SA(&retaddr), retaddr_len,
                        tst_addr, te_sockaddr_get_size(tst_addr));
    if (rc != 0)
    {
        TEST_FAIL("unexpected socket address/port returned by getsockname()"
                  "(after connect())");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
