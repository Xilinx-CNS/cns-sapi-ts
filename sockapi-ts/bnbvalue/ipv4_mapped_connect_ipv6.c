/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-ipv4_mapped_connect_ipv6 Bind IPv6 socket to IPv4-mapped address and connect to normal IPv6 address or vice versa
 *
 * @objective Check that if IPv6 socket is bound to IPv4-mapped address,
 *            it cannot connect to normal IPv6 address, and vice versa.
 *
 * @type conformance, robustness
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_p2p_ip4_ip6
 * @param sock_type     Socket type:
 *                      - @c SOCK_DGRAM
 *                      - @c SOCK_STREAM
 * @param ipv4_iut      If @c TRUE, IUT socket is bound to IPv4-mapped
 *                      address and connects to normal IPv6 address;
 *                      otherwise it is bound to normal IPv6 address
 *                      (or @c IPV6_V6ONLY option is set) and connects to
 *                      IPv4-mapped address.
 * @param v6only        If @c TRUE, enable @c IPV6_V6ONLY option instead of
 *                      binding the socket (makes sense only when
 *                      @p ipv4_iut is @c FALSE)
 * @param v6only_after  If @c TRUE, set @c IPV6_V6ONLY after @b connect(),
 *                      not before it (makes sense only when @p v6only is
 *                      @c TRUE)
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/ipv4_mapped_connect_ipv6"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *iut_addr6 = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr6 = NULL;
    const struct sockaddr      *tst_addr = NULL;

    int                         iut_s = -1;
    int                         tst_s = -1;
    struct sockaddr_storage     iut_bind_addr;
    struct sockaddr_storage     tst_conn_addr;
    te_errno                    exp_errno;

    rpc_socket_type             sock_type;
    te_bool                     ipv4_iut;
    te_bool                     v6only;
    te_bool                     v6only_after;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr6);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(ipv4_iut);
    TEST_GET_BOOL_PARAM(v6only);
    TEST_GET_BOOL_PARAM(v6only_after);

    TEST_STEP("Create IPv6 socket of type @p sock_type on IUT. If "
              "@p v6only is @c TRUE and @p v6only_after is @c FALSE, "
              "enable @c IPV6_V6ONLY option for it, otherwise disable "
              "the option.");

    iut_s = rpc_socket(pco_iut, RPC_PF_INET6, sock_type,
                       RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_V6ONLY,
                       (v6only && !v6only_after ? 1 : 0));

    if (ipv4_iut)
    {
        tapi_sockaddr_clone_exact(iut_addr, &iut_bind_addr);
        te_sockaddr_ip4_to_ip6_mapped(SA(&iut_bind_addr));

        tapi_sockaddr_clone_exact(tst_addr6, &tst_conn_addr);
    }
    else
    {
        tapi_sockaddr_clone_exact(iut_addr6, &iut_bind_addr);

        tapi_sockaddr_clone_exact(tst_addr, &tst_conn_addr);
        te_sockaddr_ip4_to_ip6_mapped(SA(&tst_conn_addr));
    }

    TEST_STEP("If @p v6only is @c FALSE, @b bind() IUT socket to "
              "an address chosen according to @p ipv4_iut.");

    if (!v6only)
        rpc_bind(pco_iut, iut_s, SA(&iut_bind_addr));

    TEST_STEP("Create socket of type @p sock_type on Tester. If "
              "@p ipv4_iut is @c TRUE, socket should be IPv6 and be "
              "bound to @p tst_addr6. Otherwise it should be IPv4 and "
              "be bound to @p tst_addr.");

    tst_s = rpc_socket(pco_tst, (ipv4_iut ? RPC_PF_INET6 : RPC_PF_INET),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, (ipv4_iut ? tst_addr6 : tst_addr));

    TEST_STEP("If @p sock_type is @c SOCK_STREAM, call @b listen() on "
              "Tester socket.");

    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_tst, tst_s, -1);

    if (ipv4_iut)
        exp_errno = RPC_EAFNOSUPPORT;
    else
        exp_errno = RPC_ENETUNREACH;

    TEST_STEP("Call @b connect() on IUT socket, passing @p tst_addr6 "
              "if @p ipv4_iut is @c TRUE, or IPv4-mapped IPv6 address "
              "corresponding to @p tst_addr otherwise. If @p v6only and "
              "@p v6only_after both are @c TRUE, check that @b connect() "
              "succeeds. Otherwise check that @b connect() fails, "
              "reporting @c EAFNOSUPPORT error if @p ipv4_iut is @c TRUE "
              "or @c ENETUNREACH error otherwise.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, SA(&tst_conn_addr));

    if (v6only && v6only_after)
    {
        if (rc < 0)
        {
            TEST_VERDICT("connect() unexpectedly failed with errno %r",
                         RPC_ERRNO(pco_iut));
        }

        TEST_STEP("If @b connect() was successful as expected, try to "
                  "set @c IPV6_V6ONLY option to @c 1 and check that "
                  "it fails with errno @c EINVAL.");

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_V6ONLY, 1);

        if (rc >= 0)
        {
            TEST_VERDICT("setsockopt(IPV6_V6ONLY, 1) succeeded after "
                         "connecting to IPv4-mapped IPv6 address");
        }
        else if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
        {
            RING_VERDICT("setsockopt(IPV6_V6ONLY, 1) failed after "
                         "connecting to IPv4-mapped IPv6 address "
                         "with unexpected errno %r", RPC_ERRNO(pco_iut));
        }
    }
    else if (rc >= 0)
    {
        TEST_VERDICT("connect() succeeded unexpectedly");
    }
    else if (exp_errno != RPC_ERRNO(pco_iut))
    {
        RING_VERDICT("connect() failed with unexpected errno %r",
                     RPC_ERRNO(pco_iut));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
