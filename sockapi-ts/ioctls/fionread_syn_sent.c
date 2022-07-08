/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page ioctls-fionread_syn_sent Usage of FIONREAD/SIOCINQ request on TCP sockets in SYN-SENT state.
 *
 * @objective Check the behavior of @c FIONREAD/SIOCINQ request on TCP socket in @c SYN-SENT state.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param pco_gw        PCO on host in the tested network that is able 
 *                      to forward incoming packets (router)
 * @param iut_addr      Address on the host with @p pco_iut in the same
 *                      subnet as @p gw_iut_addr address
 * @param gw_iut_addr   Address on the host with @p pco_gw in the same
 *                      subnet as @p iut_addr address
 * @param gw_tst_addr   Address on the host with @p pco_gw in the same
 *                      subnet as @p tst_addr address
 * @param tst_addr      Address on the host with @p pco_tst in the same
 *                      subnet as @p gw_tst_addr address
 * @param req           Type of IOCTL request, that should be made 
 *                      (@c FIONREAD/SIOCINQ).
 * 
 * @par Test sequence:
 * -# Enable forwarding on the host with @p pco_gw.
 * -# Establish routing on the hosts with @p pco_iut and @p pco_tst
 *    to reach each other via @p gw_iut_addr and @p gw_tst_addr
 *    addresses.
 * -# Create listening TCP socket @p tst_s on @p pco_tst, bound to 
 *    @p tst_addr address.
 * -# Create TCP socket @p iut_s on @p pco_iut and bind it to @p iut_addr 
 *    address.
 * -# Make @p iut_s nonblocking using @c FIONBIO IOCTL request. 
 * -# Add static neighbour cache entry for @p gw_tst_addr address with
 *    @p alien_addr hardware address on the host with @p pco_tst to
 *    prevent connection establishment.
 * -# Call @b connect() on @p pco_iut, it should return @c -1 and
 *    @c EINPROGRESS errno (obtaining TCP socket in SYN-SENT state).
 * -# Make @p req request on @p iut_s and check that returned IOCTL request
 *    value is equal to @c 0.
 * -# Close @p iut_s and @p tst_s sockets.
 *
 * @author Georgij Volfson <Georgij.Volfson@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionread_syn_sent"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"

#define DATA_BULK           1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    rcf_rpc_server             *pco_gw = NULL;

    int                         iut_s = -1;
    int                         tst_s = -1;

    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;

    const void                 *alien_link_addr = NULL;

    rpc_ioctl_code              req;

    const struct sockaddr      *gw_iut_addr = NULL;
    const struct sockaddr      *gw_tst_addr = NULL;
    int                         req_val;

    const struct if_nameindex  *tst_if = NULL;
    int                         ret;

    /* Preambule */
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_gw);
    
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(gw_iut_addr);
    TEST_GET_ADDR_NO_PORT(gw_tst_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IOCTL_REQ(req);

    TEST_GET_IF(tst_if);

    /* Scenario */

    /* Turn on forwarding on router host */
    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));

    /* Add route on 'pco_iut': 'tst_addr' via gateway 'gw_iut_addr' */
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
            tst_addr->sa_family,
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(tst_addr->sa_family) * 8,
            te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the dst");
    }
    /* Add route on 'pco_tst': 'iut_addr' via gateway 'gw_tst_addr' */
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
            iut_addr->sa_family,
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(iut_addr->sa_family) * 8,
            te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the src");
    }

    CFG_WAIT_CHANGES;
    
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    
    /* Add static ARP entry to prevent connection establishment */

    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             gw_tst_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));

    /* Making socket to the SYN-SENT state*/
    req_val = TRUE;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    CHECK_RPC_ERRNO(pco_iut, RPC_EINPROGRESS, 
                    "connect() fails and returns -1, but");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_ioctl(pco_iut, iut_s, req, &req_val);
    if (ret != 0)
    {
        TEST_VERDICT("ioctl(%s) unexpectedly failed with errno %s",
                     ioctl_rpc2str(req),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (req_val != 0)
        TEST_FAIL("Incorrect behavior of IOCTL call");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

