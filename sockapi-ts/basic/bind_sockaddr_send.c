/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-bind_sockaddr_send Influence of bind address argument on send behaviour
 * 
 * @objective Check that @b bind() correctly sets parameters passed
 *            in @a address argument and these parameters rule send
 *            processing.
 *
 * @type Conformance, compatibility
 *
 * @param env           Private set of environments which provides iterating of:
 *                      -# @p iut_addr (IPv4 or IPv6):
 *                          - wildcard
 *                          - unicast
 *                          - broadcast (only for @c SOCK_DGRAM sockets)
 *                          - loopback
 *                      -# @p pco_tst:
 *                          - on the same host as @p pco_iut for all values
 *                            of @p iut_addr;
 *                          - on the other host, but connected using SFC
 *                            interface for values of @p iut_addr not equal to
 *                            'loopback';
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
 *                      for send operation from @p pco_tst. Used only if
 *                      @p need_route is @c TRUE.
 *
 * @par Scenario
 *
 * -# If @p iut_user specified @c TRUE, switch uid on @p pco_iut.
 * -# Create sockets @p sock_iut and @p sock_tst of requested type 
 *    on @p pco_iut and @p pco_tst respectively.
 * -# Prepare port for bind of @p sock_iut according with passed @p port_type.
 * -# Call @b bind() @p sock_iut to the @p iut_addr with prepared port.
 * -# If @p iut_user specified @c TRUE and @b bind() call fails with @b errno
 *    @c EACCES, finish the test with successful result. 
 * -# Call @b getsockname() on @p sock_iut.
 * -# If @p port_type is @c PORT_UNDEF, check that got port is valid. 
 * -# @b bind() @p sock_tst to the local address on @p pco_tst. 
 * -# If @p sock_type is @c SOCK_STREAM: 
 *    -# call @b listen() on @p sock_tst. 
 *    -# if @p need_route is @c TRUE add route on @p pco_tst for 
 *       destination @p iut_addr via @p dst_addr.
 * -# Switch on @p sock_type: 
 *   - @c SOCK_DGRAM: call @b sendto() on @p sock_iut to address 
 *     of @p sock_tst.
 *   - @c SOCK_STREAM: call @b connect() on @p sock_iut to address 
 *     of @p sock_tst.
 * -# Switch on @p sock_type: 
 *   - @c SOCK_DGRAM: call @b recvfrom() on @p sock_tst.
 *   - @c SOCK_STREAM: call @b accept() on @p sock_tst.
 * -# Check that remote port got on @p sock_tst is equal to local port 
 *  of @p sock_iut.
 * -# Close sockets 
 *
 *  Note, that if socket bound to broadcast address, its behaviour on send
 *  is not specified exactly, on Linux it sends successfully with source IP 
 *  address of related IP interface (detected by destination), on BSD it 
 *  sends with broadcast source IP address.
 *
 *  @pre In case @p iut_user is @c TRUE test assumes that user with 
 *  same uid as test's exists on the host where @p pco_iut executed.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/bind_sockaddr_send"

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
    int                     iut_user;
    sockts_port_type_t      port_type;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;

    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    int                     sock_iut = -1;
    int                     sock_tst = -1;
    int                     sock_acc = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *dst_addr = NULL;

    struct sockaddr_storage loc_addr;
    socklen_t               loc_addrlen; 
    int                     sys_port_to_use = TST_SYSTEM_PORT;

    struct sockaddr_storage rcv_addr;
    socklen_t               rcv_addrlen;

    te_bool                 route_added = FALSE;
    
    rpc_socket_domain       domain;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PORT_TYPE(port_type);
    TEST_GET_BOOL_PARAM(iut_user);
    
    domain = rpc_socket_domain_by_addr(iut_addr);

    dst_addr = tapi_env_get_addr(&env, "dst_addr", NULL);
    if (dst_addr != NULL)
        need_route = TRUE;

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

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
    switch(port_type)
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

        if (iut_user && port_type == PORT_SYSTEM && err == RPC_EACCES)
        {
            INFO("Operation is not permitted, test successfull");
            TEST_SUCCESS;
        }
        TEST_FAIL("RPC bind on sock_iut failed; RPC_errno=%X",
                  TE_RC_GET_ERROR(err)); 
    } 
    else if (iut_user && port_type == PORT_SYSTEM)
    {
        TEST_FAIL("RPC bind() to system port for non-previledged user "
                  "unexpectedly passed");
    }

    loc_addrlen = sizeof(loc_addr);
    rpc_getsockname(pco_iut, sock_iut, SA(&loc_addr), &loc_addrlen);

    if ((port_type == PORT_UNDEF) &&
        (te_sockaddr_get_port(SA(&loc_addr)) == 0))
    {
        TEST_VERDICT("Undefined port in socket after bind");
    }

    rpc_bind(pco_tst, sock_tst, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_tst, sock_tst, SOCKTS_BACKLOG_DEF);

    /*
     * The route is required for both TCP and UDP.
     * Fot TCP it's obviously required to establish connection.
     * For UDP it's required to successful ARP processing.
     */
    if (need_route)
    { 
        if (tapi_cfg_add_route_via_gw(pco_tst->ta,
                addr_family_rpc2h(sockts_domain2family(domain)),
                te_sockaddr_get_netaddr(iut_addr),
                te_netaddr_get_size(addr_family_rpc2h(
                    sockts_domain2family(domain))) * 8,
                te_sockaddr_get_netaddr(dst_addr)) != 0)
        {
            TEST_FAIL("Failed to add route");
        }
        route_added = TRUE;
        CFG_WAIT_CHANGES;
    }

    switch (sock_type)
    {
        case RPC_SOCK_DGRAM:
            RPC_SENDTO(rc, pco_iut, sock_iut, tx_buf, buf_len, 0, tst_addr);
            rcv_addrlen = sizeof(rcv_addr);
            rc = rpc_recvfrom(pco_tst, sock_tst, rx_buf, buf_len, 0, 
                    SA(&rcv_addr), &rcv_addrlen);
            break;

        case RPC_SOCK_STREAM: 
            rpc_connect(pco_iut, sock_iut, tst_addr);

            rcv_addrlen = sizeof(rcv_addr);
            sock_acc = rpc_accept(pco_tst, sock_tst,
                                  SA(&rcv_addr), &rcv_addrlen); 
            break;

        default:
            TEST_FAIL("Unsupported socket type");
    }

    if (te_sockaddr_get_port(SA(&rcv_addr)) !=
        te_sockaddr_get_port(SA(&loc_addr)))
    {
        INFO("recv from port %u, auto-bound was %u",
             ntohs(te_sockaddr_get_port(SA(&rcv_addr))),
             ntohs(te_sockaddr_get_port(SA(&loc_addr))));
        TEST_FAIL("Received data from differ port then auto-bound");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, sock_acc); 
    CLEANUP_RPC_CLOSE(pco_iut, sock_iut); 
    CLEANUP_RPC_CLOSE(pco_tst, sock_tst); 

    if (route_added)
    {
       if (tapi_cfg_del_route_via_gw(pco_tst->ta,
               addr_family_rpc2h(sockts_domain2family(domain)),
               te_sockaddr_get_netaddr(iut_addr),
               te_netaddr_get_size(addr_family_rpc2h(
                   sockts_domain2family(domain))) * 8,
               te_sockaddr_get_netaddr(dst_addr)) != 0)
        {
            ERROR("Cannot delete route");
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
