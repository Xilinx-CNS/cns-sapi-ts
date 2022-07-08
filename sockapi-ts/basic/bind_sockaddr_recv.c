/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-bind_sockaddr_recv Influence of bind address argument on receive behaviour
 *
 * @objective Check that @b bind() correctly sets parameters passed
 *            in @a address argument and these parameters rule receive
 *            processing.
 *
 * @type Conformance, compatibility
 *
 * @param env           Private set of environments which provides iterating of:
 *                      -# @p iut_addr:
 *                          - wildcard
 *                          - unicast
 *                          - broadcast (only for @c SOCK_DGRAM sockets)
 *                          - loopback
 *                      -# @p pco_tst:
 *                          - on the same host as @p pco_iut for all values
 *                            of @p iut_addr;
 *                          - on the other host, but connected using SFC
 *                            interface for 'unicast' and 'broadcast' values
 *                            of @p iut_addr;
 *                          - on the host in another network as @p iut_addr
 *                            for 'unicast' value of @p iut_addr.
 * @param iut_user      Boolean flag to change uid from super-user to 
 *                      non-privileged user:
 *                      - @c TRUE: switch uid to non-privileged user on @p pco_iut
 *                      - @c FALSE: leave super-user uid on @p pco_iut
 * @param port_type     Type of port to be passed to @b bind():
 *                      - user: explicit user-domain free port
 *                      - undef: zero port
 *                      - system: explicit system-domain free port
 * @param sock_type     Socket type:
 *                      - SOCK_STREAM
 *                      - SOCK_DGRAM
 * @param dst_addr      Address on @p pco_iut host, respective to same 
 *                      network, where @p pco_tst located, will be used
 *                      for send operation from @p pco_tst.
 *
 * @par Scenario
 *
 * -# If @p iut_user specified @c TRUE, switch uid on @p pco_iut.
 * -# Create sockets @p sock_iut and @p sock_tst of requested type 
 *     on @p pco_iut and @p pco_tst respectively.
 * -# Prepare port for bind of @p sock_iut according with passed @p port_type.  
 * -# Call @b bind() @p sock_iut to the @p iut_addr with prepared port.
 * -# If @p iut_user specified @c TRUE and @b bind() call fails with @b errno
 *    @c EACCES, finish the test with successful result. 
 * -# Call @b getsockname() on @p sock_iut.
 * -# Set port in @p dst_addr to local port of @p sock_iut.
 * -# If @p sock_type is @c SOCK_STREAM, call @b listen() on @p sock_iut. 
 * -# @b bind() @p sock_tst to the local address on @p pco_tst. 
 * -# Switch on @p sock_type: 
 *   - @c SOCK_DGRAM: call @b sendto() on @p sock_tst to address @p dst_addr.
 *   - @c SOCK_STREAM: call @b connect() on @p sock_tst to address @p dst_addr.
 * -# Check @p sock_iut for readability. It should be readable if and only if 
 *    @p need_route passed @c FALSE.
 * -# If @p need_route is @c TRUE: 
 *   -# add route on @p pco_tst for destination @p iut_addr via @p dst_addr;
 *   -# repeat @b sendto() or @b connect() operation, respective to 
 *      socket type, destined to @p iut_addr;
 *   -# check that @p sock_iut is readable. 
 * -# Close sockets 
 *
 * @par Expected results
 *
 * Message should not pass only in tests where @p iut_addr is unicast or 
 * subnetwork-broadcast and belongs to other network, then @p pco_tst.
 * Note, that in any case @p dst_addr belongs to the network, where 
 * @p pco_tst  is located. 
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/bind_sockaddr_recv"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "tapi_cfg.h"


/** This port seems to be unused by any application */
#define TST_SYSTEM_PORT     2

int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type; 
    te_bool                 need_route = FALSE;
    te_bool                 iut_user;
    sockts_port_type_t      port_type;

    void                   *tx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    int                     sock_iut = -1;
    int                     sock_tst = -1;
    int                     sock_acc = -1;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    const struct sockaddr  *dst_addr = NULL;
    const struct sockaddr  *iut_addr_ucast = NULL;

    struct sockaddr_storage loc_addr;
    socklen_t               loc_addrlen; 
    int                     sys_port_to_use = TST_SYSTEM_PORT;

    te_bool                 route_set = FALSE;
    te_bool                 is_readable;

    rpc_socket_domain domain;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(dst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PORT_TYPE(port_type);
    TEST_GET_BOOL_PARAM(iut_user);
    dst_addr = tapi_env_get_addr(&env, "dst_addr", NULL);
    if (dst_addr == NULL)
        TEST_STOP;
    
    /*
     * Check whether we use environment with route. See package.xml for
     * more info.
     */
    iut_addr_ucast = tapi_env_get_addr(&env, "iut_addr_ucast", NULL);
    if (te_sockaddrcmp(dst_addr, te_sockaddr_get_size(dst_addr),
                       iut_addr, te_sockaddr_get_size(iut_addr)) == -1 &&
        iut_addr_ucast == NULL)
    {
        need_route = TRUE;
    }

    domain = rpc_socket_domain_by_addr(iut_addr);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));

    if (port_type == PORT_SYSTEM)
    {
        while (sys_port_to_use < 1024)
        {
            if (rpc_check_port_is_free(pco_iut, sys_port_to_use))
                break;
            sys_port_to_use++;
        }
        if (sys_port_to_use == 1024)
            TEST_FAIL("Failed to find free system port");
    }

    if (iut_user)
        sockts_server_change_uid(pco_iut);

    sock_iut = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF); 

    sock_tst = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF); 

    memcpy(&loc_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    loc_addrlen = te_sockaddr_get_size(iut_addr);
    switch (port_type)
    {
        case PORT_UNDEF:
            te_sockaddr_set_port(SA(&loc_addr), 0);
            break;
        case PORT_SYSTEM:
            te_sockaddr_set_port(SA(&loc_addr), htons(sys_port_to_use));
            break; 
        case PORT_USER: /* do nothing, leave set port */
            break;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, sock_iut, SA(&loc_addr)); 
    if (rc != 0)
    {
        int err = RPC_ERRNO(pco_iut);

        if (iut_user && err == RPC_EACCES)
        {
            INFO("Operation is not permitted, test successfull");
            TEST_SUCCESS;
        }

        TEST_FAIL("RPC bind of sock_iut failed with unexpected errno.");
    } 
    else if (iut_user && port_type == PORT_SYSTEM)
    {
        TEST_FAIL("RPC bind() to system port for non-previledged user "
                  "unexpectedly passed");
    }

    memset(&loc_addr, 0, sizeof(loc_addr));
    loc_addrlen = sizeof(loc_addr);
    rpc_getsockname(pco_iut, sock_iut, SA(&loc_addr), &loc_addrlen);

    if (te_sockaddr_get_port(SA(&loc_addr)) == 0)
    {
        TEST_VERDICT("Undefined port in socket after bind");
    }
    else
    {
        te_sockaddr_set_netaddr(SA(&loc_addr),
                                te_sockaddr_get_netaddr(SA(dst_addr)));
    }

    rpc_bind(pco_tst, sock_tst, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_iut, sock_iut, SOCKTS_BACKLOG_DEF);

    /*
     * Sockopt SO_BROADCAST is only supported for DGRAM sockets with
     * address family AF_INET
     */
    if (sock_type == RPC_SOCK_DGRAM)
    {
        if (domain == RPC_PF_INET)
        {
            int opt = 1;
            rpc_setsockopt(pco_tst, sock_tst, RPC_SO_BROADCAST, &opt);
        }
        else
        {
            SIN6(&loc_addr)->sin6_scope_id = SIN6(tst_addr)->sin6_scope_id;
        }
    }

    switch (sock_type)
    {
        case RPC_SOCK_DGRAM:
            RPC_SENDTO(rc, pco_tst, sock_tst, tx_buf, buf_len, 0, 
                       SA(&loc_addr));
            break;

        case RPC_SOCK_STREAM: 
            RPC_AWAIT_IUT_ERROR(pco_tst);
            rc = rpc_connect(pco_tst, sock_tst, SA(&loc_addr));
            if (rc == -1)
            {
                int err = RPC_ERRNO(pco_tst); 

                RING("RPC connect on sock_tst failed; RPC_errno=%r",
                     TE_RC_GET_ERROR(err)); 
            } 
            break;

        default:
            TEST_FAIL("Unsupported socket type");
    } 
    TAPI_WAIT_NETWORK;

    /* Initialize to unexpected value */
    is_readable = need_route;
    RPC_GET_READABILITY(is_readable, pco_iut, sock_iut, 0);

    if ((!need_route) != is_readable)
    {
        TEST_FAIL("Unexpected readability of sock_iut: exp %d != got %d",
                  !need_route, is_readable);
    } 

    if (need_route)
    { 
        if (tapi_cfg_add_route_via_gw(pco_tst->ta,
                   addr_family_rpc2h(sockts_domain2family(domain)),
                   te_sockaddr_get_netaddr(iut_addr),
                   te_netaddr_get_size(addr_family_rpc2h(
                       sockts_domain2family(domain))) * 8,
                   te_sockaddr_get_netaddr(dst_addr)) != 0)
        {
            TEST_FAIL("Cannot add route 'r1'");
        }
        route_set = TRUE;
        CFG_WAIT_CHANGES;

        te_sockaddr_set_netaddr(SA(&loc_addr),
                                te_sockaddr_get_netaddr(iut_addr));

        switch (sock_type)
        {
            case RPC_SOCK_DGRAM:
                RPC_SENDTO(rc, pco_tst, sock_tst, tx_buf, buf_len, 0, 
                           SA(&loc_addr));
                break;

            case RPC_SOCK_STREAM: 
                rpc_connect(pco_tst, sock_tst, SA(&loc_addr));
                break;

            default:
                TEST_FAIL("Unsupported socket type");
        } 

        TAPI_WAIT_NETWORK;
        RPC_GET_READABILITY(is_readable, pco_iut, sock_iut, 0);
        if (!is_readable)
        {
            TEST_FAIL("sock_iut is NOT readable after add route", sock_iut);
        } 
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, sock_acc); 
    CLEANUP_RPC_CLOSE(pco_iut, sock_iut); 
    CLEANUP_RPC_CLOSE(pco_tst, sock_tst); 

    if (route_set)
    {
       if (tapi_cfg_del_route_via_gw(pco_tst->ta,
               addr_family_rpc2h(sockts_domain2family(domain)),
               te_sockaddr_get_netaddr(iut_addr),
               te_netaddr_get_size(addr_family_rpc2h(
                   sockts_domain2family(domain))) * 8,
               te_sockaddr_get_netaddr(dst_addr)) != 0)
        {
            ERROR("Cannot delete route 'r1'");
            result = EXIT_FAILURE;
        }
    }

    if (pco_iut != NULL && iut_user && rcf_rpc_server_restart(pco_iut) != 0)
    {
        ERROR("Failed to restart pco_iut");
        result = EXIT_FAILURE;
    }

    TEST_END;
}

