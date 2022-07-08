/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-error Usage of SO_ERROR socket option
 *
 * @objective Check that @c SO_ERROR socket option can be used 
 *            to get the pending errors on the socket.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, setcion 7.5
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param gw_addr       Network address of a host in the tested network
 *                      that is able to forward incoming packets (router)
 * @param dst_addr      Destination address used in the test, the address
 *                      should not be accessed from 'pco_iut' directly and
 *                      should not be assigned to 'gw_addr'
 * @param connect       Whether @b connect() / @b send() or @b sendto()
 *                      should be used to send data
 * @param ip_recverr    Whether @c IP_RECVERR socket option should be
 *                      set to @c 1
 * 
 * @par Test sequence:
 * -# Create @p iut_s socket of type @c SOCK_DGRAM on @p pco_iut.
 * -# If @p ip_recverr is @c TRUE, set @c IP_RECVERR socket option to
 *    @c 1 on @p iut_s socket.
 * -# Add route @p r1 to @p dst_addr via a gateway with @p gw_addr address;
 * -# Set @p new_ttl to @c 1.
 * -# Call @b setsockopt(@p pco_iut, @c SOL_IP, @c IP_TTL, @p &new_ttl,
 *                       @c sizeof(new_ttl)) - 
 *    TTL field of outgoing unicast packets is set to one.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_ERROR socket 
 *    option to get its initial value.
 *    Check that it returns @c 0 and @a option_value parameter is updated 
 *    to @c 0.
 * -# Call @b setsockopt() on @p iut_s socket with @c SO_ERROR socket
 *    option. Check that the function returns @c -1 and sets @b errno to
 *    @c ENOPROTOOPT.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p connect is @c TRUE, @b connect() @p iut_s socket to
 *    @p dst_addr and send some data using @b send() function. Otherwise
 *    send some data using @b sendto() function to @p dst_addr. This 
 *    packet goes to the router according to the route and the router
 *    drops the packet sending ICMP Time Exceeded message back to
 *    the sender, because the packet has TTL field equals to 1.
 * -# Wait for a while for a couple of seconds (to make sure that ICMP
 *    message is processed).
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_ERROR socket option.
 *    Check that if @p ip_recverr is @c FALSE, the function returns @c 0 and
 *    @a option_value parameter is @c 0 since ICMP Desitnation Unreachable
 *    (Time Exceeded) is transient error and ignored by default. Check
 *    that is @p ip_recverr is @c TRUE, the function returns @c 0 and
 *    @a option_value parameter is @c EHOSTUNREACH.
 *    See @ref sockopts_error_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p connect is @c TRUE, @b connect() @p iut_s socket to @p gw_addr
 *    using port that is not being listened on the router and send some
 *    data using @b send() function. Otherwise send some data using
 *    @b sendto() function to @p gw_addr and the same port. Router sending
 *    ICMP Port Unreachable ICMP message back to the sender.
 * -# Wait for a while for a couple of seconds (to make sure that ICMP
 *    message is processed).
 * -# Call @b getsockopt() on @p pco_iut socket with @c SO_ERROR socket
 *    option and check check that the function returns @c 0 and i
 *    f @p connect is @c TRUE or @p ip_recverr is @c TRUE, 
 *    @a option_value parameter is updated to @c ECONNREFUSED, else
 *    @a option_value parameter is updated to @c 0 (errors are not
 *    reported on not connected sockets).
 *    See @ref sockopts_error_2 "note 2".
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_ERROR socket option.
 *    Check that it returns @c 0 and @a option_value parameter is updated 
 *    to @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete route @p r1.
 * -# Close @p iut_s socket.
 *
 * @note
 * -# @anchor sockopts_error_1
 *    In Linux if @c IP_RECVERR is enbale, ICMP Destination Unreachable
 *    Time Exceeded (as well as many other ICMP error message) are
 *    reported by @c SO_ERROR socket option.
 * -# @anchor sockopts_error_2
 *    Mapping from ICMPv4/ICMPv6 error coded to @b errno can be found in
 *    @ref STEVENS, section 25.7.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/error"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_gw = NULL;
    rcf_rpc_server *pco_iut = NULL;
    int             iut_s = -1;
    te_bool         connect = FALSE;
    te_bool         ip_recverr = FALSE;

    const struct sockaddr *dst_addr;
    const struct sockaddr *gw_addr;
    void                  *tx_buf = NULL;
    size_t                 buf_len;
    int                    opt_val;
    te_bool                route_added = FALSE;
    int                    ttl_val;

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_ADDR(pco_gw, dst_addr);
    TEST_GET_ADDR(pco_gw, gw_addr);
    TEST_GET_BOOL_PARAM(connect);
    TEST_GET_BOOL_PARAM(ip_recverr);

    domain=  rpc_socket_domain_by_addr(dst_addr);

    CHECK_NOT_NULL(tx_buf = sockts_make_buf_dgram(&buf_len));


    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));

    /* Add route on 'pco_iut': 'dst_addr' via gateway 'gw_addr' */
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(dst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw_addr)) != 0)
    {
        TEST_FAIL("Cannot add route 'r1'");
    }
    route_added = TRUE;
    CFG_WAIT_CHANGES;

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    if (ip_recverr)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        opt_val = 1;
        if (rpc_setsockopt(pco_iut, iut_s, RPC_IP_RECVERR, &opt_val) != 0)
        {
            TEST_VERDICT("setsockopt(IP_RECVERR) failed with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    if (domain == RPC_PF_INET)
    {
        ttl_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_IP_TTL, &ttl_val);
    }
    else
    {
        TEST_FAIL("Test does not support %s domain yet",
                  domain_rpc2str(domain));
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != 0)
    {
        TEST_VERDICT("SO_ERROR socket option value is not 0 on just "
                     "created socket");
    }
    
    /* Try to set this option */
    opt_val = 1;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (rc != -1)
    {
        TEST_FAIL("setsockopt(SO_ERROR) returns %d, but expected -1", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_ENOPROTOOPT,
                    "setsockopt(SO_ERROR) returns -1, but");

    if (connect)
    {
        rpc_connect(pco_iut, iut_s, dst_addr);
        RPC_SEND(rc, pco_iut, iut_s, tx_buf, buf_len, 0);
    }
    else
    {
        RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, buf_len, 0, dst_addr);
    }

    TAPI_WAIT_NETWORK;
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (!ip_recverr && opt_val != 0)
    {
        TEST_VERDICT("After receiving ICMP destination unreachable "
                     "(TTL exceeded) SO_ERROR option is set to %s, "
                     "but is expected to be 0 since this error is "
                     "transient and ignored by default (IP_RECVERR is "
                     "disabled)",
                     errno_rpc2str(opt_val));
    }
    else if (ip_recverr && opt_val != RPC_EHOSTUNREACH)
    {
        TEST_VERDICT("After receiving ICMP destination unreachable "
                     "(TTL exceeded) SO_ERROR option is set to %s, "
                     "but is expected to be EHOSTUNREACH since "
                     "IP_RECVERR is enabled",
                     errno_rpc2str(opt_val));
    }

    if (connect)
    {
        rpc_connect(pco_iut, iut_s, gw_addr);
        RPC_SEND(rc, pco_iut, iut_s, tx_buf, buf_len, 0);
    }
    else
    {
        RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, buf_len, 0, gw_addr);
    }

    TAPI_WAIT_NETWORK;
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (connect || ip_recverr)
    {
        if (opt_val != RPC_ECONNREFUSED)
            TEST_VERDICT("After receiving ICMP destination unreachable "
                         "(Port unreachable) SO_ERROR option is set "
                         "to %s, but it is expected to be ECONNREFUSED",
                         errno_rpc2str(opt_val));

        /* Check that the value of SO_ERROR socket option is cleared now */
        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
        if (opt_val != 0)
        {
            TEST_VERDICT("The value of SO_ERROR socket option is not "
                         "cleared after calling getsockopt() for "
                         "the option");
        }
    }
    else
    {
        if (opt_val != 0)
            TEST_VERDICT("After receiving ICMP destination unreachable "
                         "(Port unreachable) SO_ERROR option is set "
                         "to %s, but it is expected to be 0 since the "
                         "socket is not connected and IP_RECVERR is "
                         "not set", errno_rpc2str(opt_val));
    }
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (route_added &&
        tapi_cfg_del_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(dst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw_addr)) != 0)
    {
        ERROR("Cannot delete route 'r1'");
        result = EXIT_FAILURE;
    }

    free(tx_buf);

    TEST_END;
}
