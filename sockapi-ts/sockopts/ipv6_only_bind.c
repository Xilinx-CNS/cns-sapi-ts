/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-ipv6_only_bind IPV6_V6ONLY option and bind()
 *
 * @objective Check what happens when we try to bind IPv6 socket and IPv4
 *            socket to the same port when @c IPV6_V6ONLY socket option
 *            is enabled or disabled for IPv6 socket.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_p2p_ip4_ip6
 * @param ipv6_bind     Address to bind IPv6 socket to:
 *                      - @c any (@c IN6ADDR_ANY_INIT)
 *                      - @c ipv4
 *                      - @c ipv4_mapped (constructed from @p iut_addr)
 *                      - @c ipv4_mapped_new (from @p env net)
 *                      - @c ipv4_mapped_any (IPv4-mapped IPv6 corresponding
 *                        to @c INADDR_ANY)
 *                      - @c ipv6
 * @param ipv4_bind     Address to bind IPv4 socket to:
 *                      - @c any (@c INADDR_ANY)
 *                      - @c ipv4
 * @param v6only        Whether to enable @c IPV6_V6ONLY option on IPv6
 *                      socket
 * @param v6only_after  If @c TRUE, @c IPV6_V6ONLY should be changed
 *                      according to @p v6only after bind(), not before
 * @param sock_type     Socket type:
 *                      - @c SOCK_STREAM
 *                      - @c SOCK_DGRAM
 *
 * @reference MAN 7 ipv6
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ipv6_only_bind"

#include "sockapi-test.h"
#include "sockapi-ts_monitor.h"

/** Types of address to which a socket may be bound */
typedef enum {
    SOCKTS_ADDR_ANY,               /**< Wildcard address */
    SOCKTS_ADDR_IPV4,              /**< IPv4 address */
    SOCKTS_ADDR_IPV4_MAPPED,       /**< IPv4-mapped IPv6 */
    SOCKTS_ADDR_IPV4_MAPPED_NEW,   /**< Another IPv4-mapped IPv6 */
    SOCKTS_ADDR_IPV4_MAPPED_ANY,   /**< IPv4-mapped IPv6 corresponding to
                                        INADDR_ANY */
    SOCKTS_ADDR_IPV6,              /**< IPv6 address */
} test_addr_type;

/** List of address types to be used with TEST_GET_ENUM_PARAM() */
#define TEST_ADDR_TYPES \
    { "any", SOCKTS_ADDR_ANY },                          \
    { "ipv4", SOCKTS_ADDR_IPV4 },                        \
    { "ipv4_mapped", SOCKTS_ADDR_IPV4_MAPPED },          \
    { "ipv4_mapped_new", SOCKTS_ADDR_IPV4_MAPPED_NEW },  \
    { "ipv4_mapped_any", SOCKTS_ADDR_IPV4_MAPPED_ANY },  \
    { "ipv6", SOCKTS_ADDR_IPV6 }

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *iut_addr6 = NULL;
    const struct sockaddr      *iut_addr = NULL;
    struct sockaddr            *iut_addr_new = NULL;
    int                         iut_s6 = -1;
    int                         iut_s4 = -1;
    int                         iut_acc6 = -1;
    int                         iut_acc4 = -1;
    int                         tst_s6 = -1;
    int                         tst_s4 = -1;
    int                         opt_val;
    int                         new_opt_val;
    int                         rc1;
    int                         rc2;
    const struct if_nameindex  *iut_if;
    sockts_if_monitor           iut_if_monitor4 = SOCKTS_IF_MONITOR_INIT;
    sockts_if_monitor           iut_if_monitor6 = SOCKTS_IF_MONITOR_INIT;
    cfg_handle                  new_addr_handle = CFG_HANDLE_INVALID;
    tapi_env_net               *net = NULL;

    test_addr_type    ipv6_bind;
    test_addr_type    ipv4_bind;
    te_bool           v6only;
    te_bool           v6only_after;
    rpc_socket_type   sock_type;
    te_bool           if_acc;
    te_bool           should_bind_succeed;
    te_bool           bind_condition;

    struct sockaddr_storage ipv6_bind_addr;
    struct sockaddr_storage ipv4_bind_addr;
    struct sockaddr_storage ipv6_conn_addr;
    struct sockaddr_storage ipv4_conn_addr;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ENUM_PARAM(ipv6_bind, TEST_ADDR_TYPES);
    TEST_GET_ENUM_PARAM(ipv4_bind, TEST_ADDR_TYPES);
    TEST_GET_BOOL_PARAM(v6only);
    TEST_GET_BOOL_PARAM(v6only_after);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IF(iut_if);
    TEST_GET_NET(net);

    tapi_sockaddr_clone_exact(iut_addr6, &ipv6_bind_addr);
    tapi_sockaddr_clone_exact(iut_addr6, &ipv6_conn_addr);
    switch (ipv6_bind)
    {
        case SOCKTS_ADDR_ANY:
            te_sockaddr_set_wildcard(SA(&ipv6_bind_addr));
            break;

        case SOCKTS_ADDR_IPV4:
            tapi_sockaddr_clone_exact(iut_addr, &ipv6_bind_addr);
            SIN(&ipv6_bind_addr)->sin_port = SIN6(iut_addr6)->sin6_port;
            tapi_sockaddr_clone_exact(SA(&ipv6_bind_addr), &ipv6_conn_addr);
            break;

        case SOCKTS_ADDR_IPV4_MAPPED_NEW:
            CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &iut_addr_new, NULL));
            CHECK_RC(tapi_allocate_set_port(pco_iut, iut_addr_new));
            CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                                   iut_addr_new, net->ip4pfx,
                                                   TRUE, &new_addr_handle));
            CFG_WAIT_CHANGES;
            /*@fallthrough@*/

        case SOCKTS_ADDR_IPV4_MAPPED:
            te_sockaddr_set_wildcard(SA(&ipv6_bind_addr));

            if (ipv6_bind == SOCKTS_ADDR_IPV4_MAPPED)
            {
                SIN6(&ipv6_bind_addr)->sin6_addr.s6_addr32[3] =
                    SIN(iut_addr)->sin_addr.s_addr;
            }
            else
            {
                SIN6(&ipv6_bind_addr)->sin6_addr.s6_addr32[3] =
                    SIN(iut_addr_new)->sin_addr.s_addr;
            }

            SIN6(&ipv6_bind_addr)->sin6_addr.s6_addr16[5] = htons(0xFFFF);
            tapi_sockaddr_clone_exact(SA(&ipv6_bind_addr), &ipv6_conn_addr);
            break;

        case SOCKTS_ADDR_IPV4_MAPPED_ANY:
            te_sockaddr_set_wildcard(SA(&ipv6_bind_addr));
            SIN6(&ipv6_bind_addr)->sin6_addr.s6_addr16[5] = htons(0xFFFF);

            tapi_sockaddr_clone_exact(iut_addr, &ipv6_conn_addr);
            SIN(&ipv6_conn_addr)->sin_port = SIN6(iut_addr6)->sin6_port;
            te_sockaddr_ip4_to_ip6_mapped(SA(&ipv6_conn_addr));
            break;

        case SOCKTS_ADDR_IPV6:
            break;

        default:
            TEST_FAIL("Not supported value of ipv6_bind parameter");
    }

    tapi_sockaddr_clone_exact(iut_addr, &ipv4_bind_addr);
    SIN(&ipv4_bind_addr)->sin_port = SIN6(iut_addr6)->sin6_port;
    tapi_sockaddr_clone_exact(SA(&ipv4_bind_addr), &ipv4_conn_addr);

    switch (ipv4_bind)
    {
        case SOCKTS_ADDR_ANY:
            te_sockaddr_set_wildcard(SA(&ipv4_bind_addr));
            break;

        case SOCKTS_ADDR_IPV4:
            break;

        default:
            TEST_FAIL("Not supported value of ipv4_bind parameter");
    }

    TEST_STEP("Create IPv6 and IPv4 sockets of type @p sock_type on IUT.");

    iut_s6 = rpc_socket(pco_iut, RPC_PF_INET6, sock_type,
                        RPC_PROTO_DEF);
    iut_s4 = rpc_socket(pco_iut, RPC_PF_INET, sock_type,
                        RPC_PROTO_DEF);

    TEST_STEP("If @p v6only_after is @c FALSE, set @c IPV6_V6ONLY socket "
              "option according to @p v6only for the IPv6 IUT socket. If "
              "@p v6only_after is @c TRUE, set this option in the opposite "
              "way.");

    if (v6only_after)
    {
        if (v6only)
            opt_val = 0;
        else
            opt_val = 1;
    }
    else
    {
        if (v6only)
            opt_val = 1;
        else
            opt_val = 0;
    }

    rpc_setsockopt_int(pco_iut, iut_s6, RPC_IPV6_V6ONLY, opt_val);

    TEST_STEP("Create peer IPv6 and IPv4 sockets on Tester. Disable "
              "@c IPV6_V6ONLY option for IPv6 Tester socket.");

    tst_s6 = rpc_socket(pco_tst, RPC_PF_INET6, sock_type,
                        RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_tst, tst_s6, RPC_IPV6_V6ONLY, 0);

    tst_s4 = rpc_socket(pco_tst, RPC_PF_INET, sock_type,
                        RPC_PROTO_DEF);

    TEST_STEP("Bind IPv6 IUT socket to an address chosen according to "
              "@p ipv6_bind. Check that @b bind() fails if we try to "
              "use IPv4 address, or if we try to use IPv4 mapped "
              "IPv6 address when @c IPV6_V6ONLY option is enabled. "
              "Check that @b bind() succeeds otherwise.");

    RPC_AWAIT_ERROR(pco_iut);
    rc1 = rpc_bind(pco_iut, iut_s6, SA(&ipv6_bind_addr));
    if (ipv6_bind == SOCKTS_ADDR_IPV4)
    {
        if (rc1 >= 0)
        {
            TEST_VERDICT("Binding IPv6 socket to IPv4 address succeeded");
        }
        else if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
        {
            RING_VERDICT("Binding IPv6 socket to IPv4 address failed "
                         "with errno %r instead of EINVAL",
                         RPC_ERRNO(pco_iut));
        }
    }
    else if (opt_val == 1 &&
             (ipv6_bind == SOCKTS_ADDR_IPV4_MAPPED ||
              ipv6_bind == SOCKTS_ADDR_IPV4_MAPPED_ANY ||
              ipv6_bind == SOCKTS_ADDR_IPV4_MAPPED_NEW))
    {
        if (rc1 >= 0)
        {
            TEST_VERDICT("Binding IPv6 socket to IPv4 mapped IPv6 address "
                         "succeeded while IPV6_V6ONLY is enabled");
        }
        else if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
        {
            RING_VERDICT("Binding IPv6 socket to IPv4 mapped IPv6 address "
                         "failed with errno %r instead of EINVAL",
                         RPC_ERRNO(pco_iut));
        }
    }
    else if (rc1 < 0)
    {
        TEST_VERDICT("Binding IPv6 socket failed unexpectedly with "
                     "errno %r", RPC_ERRNO(pco_iut));
    }

    TEST_STEP("If @p v6only_after is @c TRUE, try to set @c IPV6_V6ONLY "
              "socket option according to @p v6only for the IPv6 IUT "
              "socket. Check that it fails with @c EINVAL if @b bind() "
              "for the socket was successful.");

    if (v6only_after)
    {
        if (v6only)
            new_opt_val = 1;
        else
            new_opt_val = 0;

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_setsockopt_int(pco_iut, iut_s6, RPC_IPV6_V6ONLY,
                                new_opt_val);
        if (rc < 0)
        {
            if (rc1 < 0)
            {
                TEST_VERDICT("setsockopt(IPV6_V6ONLY) failed unexpectedly "
                             "with errno %r when called after unsuccessful "
                             "bind()", RPC_ERRNO(pco_iut));
            }
            else if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
            {
                RING_VERDICT("setsockopt(IPV6_V6ONLY) failed with "
                             "unexpected errno %r after unsuccessful "
                             "bind()", RPC_ERRNO(pco_iut));
            }
        }
        else
        {
            if (rc1 >= 0)
            {
                ERROR_VERDICT("setsockopt(IPV6_V6ONLY) succeeded "
                              "unexpectedly after successful bind()");
            }
            opt_val = new_opt_val;
        }
    }

    TEST_STEP("Bind IPv4 IUT socket to an address chosen according to "
              "@p ipv4_bind and the same port that was used for IPv6 "
              "socket.");

    RPC_AWAIT_ERROR(pco_iut);
    rc2 = rpc_bind(pco_iut, iut_s4, SA(&ipv4_bind_addr));

    should_bind_succeed = (rc1 < 0 || opt_val == 1
                           || ipv6_bind == SOCKTS_ADDR_IPV6);
    bind_condition = (ipv4_bind == SOCKTS_ADDR_IPV4 && (ipv6_bind
                      == SOCKTS_ADDR_IPV4_MAPPED || ipv6_bind
                      == SOCKTS_ADDR_IPV4_MAPPED_ANY) &&
                      v6only != v6only_after);

    if (should_bind_succeed)
    {
        TEST_SUBSTEP("Check that @b bind() succeeds if binding failed "
                     "for IPv6 socket, or if @c IPV6_V6ONLY option was "
                     "enabled for it, or if it was bound to IPv6 address.");
        if (rc2 < 0)
        {
            TEST_VERDICT("Binding IPv4 socket failed unexpectedly with "
                         "errno %r", RPC_ERRNO(pco_iut));
        }
    }
    else if ((bind_condition && sock_type == RPC_SOCK_STREAM)
             || (ipv4_bind == SOCKTS_ADDR_IPV4 && ipv6_bind
             == SOCKTS_ADDR_IPV4_MAPPED_NEW))
    {
        TEST_SUBSTEP("Check that @b bind() succeeds if either:\n"
                     "1) IPv4 socket was bound to IPv4 address, IPv6 socket "
                     "was bound to IPv4-mapped address (constructed from "
                     "this address or INADDR_ANY) and socket type is TCP;\n"
                     "2) or IPv4 socket was bound to IPv4 address and IPv6 "
                     "socket was bound to another IPv4-mapped address.");
        if (rc2 < 0)
        {
            RING_VERDICT("Binding IPv4 socket failed unexpectedly with "
                         "errno %r", RPC_ERRNO(pco_iut));
        }
    }
    else
    {
        TEST_SUBSTEP("Check that @b bind() fails otherwise.");

        if (rc2 >= 0)
        {
            TEST_VERDICT("Binding IPv4 socket unexpectedly succeeded");
        }
        else if (RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
        {
            RING_VERDICT("Binding IPv4 socket failed with errno %r "
                         "instead of EADDRINUSE",
                         RPC_ERRNO(pco_iut));
        }
    }

    CHECK_RC(sockts_if_monitor_init(&iut_if_monitor4,
                                    pco_iut->ta, iut_if->if_name, AF_INET,
                                    sock_type,
                                    NULL, NULL,
                                    TRUE, FALSE));
    CHECK_RC(sockts_if_monitor_init(&iut_if_monitor6,
                                    pco_iut->ta, iut_if->if_name, AF_INET6,
                                    sock_type,
                                    NULL, NULL,
                                    TRUE, FALSE));

    TAPI_WAIT_NETWORK;

    if_acc = sockts_if_accelerated(&env, pco_iut->ta, iut_if->if_name);

    TEST_STEP("If @b bind() was successful for IPv6 IUT socket, check "
              "that it can receive data from its peer on Tester "
              "(if UDP is tested) or can accept connection from it "
              "(if TCP is tested).");

    if (rc1 >= 0)
    {
        sockts_if_monitor *monitor = &iut_if_monitor6;

        if (sock_type == RPC_SOCK_STREAM)
        {
            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_listen(pco_iut, iut_s6, SOCKTS_BACKLOG_DEF);
            if (rc2 >= 0 && bind_condition)
            {
                if (rc >= 0)
                {
                    TEST_VERDICT("listen() on IPv6 socket unexpectedly "
                                 "succeeded");
                }
                else if (RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
                {
                    TEST_VERDICT("listen() on IPv6 socket failed with errno %r "
                                 "instead of EADDRINUSE",
                                 RPC_ERRNO(pco_iut));
                }
            }
            else
            {
                if (rc < 0)
                {
                    TEST_VERDICT("listen() on IPv6 socket failed unexpectedly "
                                 "with errno %r", RPC_ERRNO(pco_iut));
                }

                CHECK_RC(sockts_check_recv_accept(
                                    pco_tst, tst_s6,
                                    pco_iut, iut_s6,
                                    NULL, SA(&ipv6_conn_addr), RPC_PF_UNSPEC,
                                    sock_type, &iut_acc6, "IPv6 socket"));

                TEST_SUBSTEP("Check acceleration for IPv6 socket.");
                if (ipv6_bind == SOCKTS_ADDR_IPV4_MAPPED ||
                    ipv6_bind == SOCKTS_ADDR_IPV4_MAPPED_ANY ||
                    ipv6_bind == SOCKTS_ADDR_IPV4_MAPPED_NEW)
                {
                    monitor = &iut_if_monitor4;
                }

                if (sockts_if_monitor_check_in(monitor) != !if_acc)
                {
                    TEST_VERDICT("IPv6 socket: traffic over IUT interface is %s"
                                 "accelerated", (if_acc ? "not " : ""));
                }
            }
        }
    }

    TEST_STEP("If @b bind() was successful for IPv4 IUT socket, check "
              "that it can receive data from its peer on Tester "
              "(if UDP is tested) or can accept connection from it "
              "(if TCP is tested).");

    if (rc2 >= 0)
    {
        if (sock_type == RPC_SOCK_STREAM)
            rpc_listen(pco_iut, iut_s4, SOCKTS_BACKLOG_DEF);

        CHECK_RC(sockts_check_recv_accept(
                                 pco_tst, tst_s4,
                                 pco_iut, iut_s4,
                                 NULL, SA(&ipv4_conn_addr), RPC_PF_UNSPEC,
                                 sock_type, &iut_acc4, "IPv4 socket"));

        TEST_SUBSTEP("Check acceleration for IPv4 socket.");
        if (sockts_if_monitor_check_in(&iut_if_monitor4) != !if_acc)
        {
            TEST_VERDICT("IPv4 socket: traffic over IUT interface is %s"
                         "accelerated", (if_acc ? "not " : ""));
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&iut_if_monitor4));
    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&iut_if_monitor6));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s4);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s6);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc4);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc6);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s4);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s6);

    if (ipv6_bind == SOCKTS_ADDR_IPV4_MAPPED_NEW)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(new_addr_handle, FALSE));
    }

    TEST_END;
}
