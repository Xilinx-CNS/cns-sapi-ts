/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-sndtimeo_connect Behaviour of connect() if  SO_SNDTIMEO socket option is set on socket
 *
 * @objective Check that @c SO_SNDTIMEO option set on socket influences on
 *            @b connect() behaviour.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on IUT
 * @param pco_gw    PCO on host in the tested network
 *                  that is able to forward incoming packets (router)
 *
 * @param pco_tst   PCO on TESTER
 *
 * @par Test sequence:
 *
 * -# Create @p pco_iut socket of type @c SOCK_STREAM on @p pco_iut;
 * -# Create @p pco_tst socket of type @c SOCK_STREAM on @p pco_tst;
 * -# Create a buffer @p tx_buf of an arbitrary number of bytes;
 * -# Call @b setsockopt() on @p pco_iut socket with @c SO_SNDTIMEO
 *    option specifying with @c 1 second timeout value;
 * -# Bind @p pco_tst socket to a local address and port;
 * -# Call @b listen() on @p pco_tst socket;
 * -# Redirect traffic to alien address by means of faked ARP entry;
 * -# @b connect() @p pco_iut socket to @p pco_tst;
 * -# Check that connect() returned @c -1 and errno set to @c EINPROGRESS;
 * -# Check that the duration of the connect() is @c 1 second;
 * -# @b connect() @p pco_iut socket to @p pco_tst;
 * -# Check that connect() returned @c -1 and errno set to @c EALREADY;
 * -# Restore traffic to the normal way;
 * -# @b accept() on @p pco_tst socket to get a new connection @p acc_s;
 * -# @b connect() on @p pco_iut socket to @p pco_tst address, check
 *    that @c 0 is returned;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete allocated resources and close opened sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/sndtimeo_connect"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"

/* Timeout in seconds */
#define TST_SNDTIMEO   1


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_gw = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             acc_s = -1;
    int             ret;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    const struct sockaddr *gw1_addr = NULL;
    const struct sockaddr *gw2_addr = NULL;

    const struct if_nameindex *gw2_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    te_bool                route_dst_added = FALSE;
    te_bool                route_src_added = FALSE;
    te_bool                arp_entry_added = FALSE;

    const void             *alien_link_addr;

    void                   *tx_buf = NULL;
    size_t                  buf_len = 4096;

    tarpc_timeval           optval;
    
    rpc_socket_domain       domain;

    TEST_START;
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(gw1_addr);
    TEST_GET_ADDR_NO_PORT(gw2_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(gw2_if);
    TEST_GET_IF(tst_if);
    
    domain = rpc_socket_domain_by_addr(iut_addr);

    /* Prepare data to transmit by means of: */
    /* write(), send(), sendto() */
    tx_buf = te_make_buf_by_len(buf_len);

    /* Add route on 'pco_iut': 'tst_addr' via gateway 'gw1_addr' */
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw1_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the dst");
    }
    route_dst_added = TRUE;

    /* Add route on 'pco_tst': 'iut_addr' via gateway 'gw2_addr' */
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw2_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the src");
    }
    route_src_added = TRUE;

    /* Turn on forwarding on router host */
    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));
    CFG_WAIT_CHANGES;


    /* Scenario */

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    optval.tv_sec = TST_SNDTIMEO;
    optval.tv_usec = 0;
    ret = rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDTIMEO, &optval);
    if (ret != 0)
    {
        TEST_VERDICT("setsockopt(SOL_SOCKET, SO_SNDTIMEO, {%d,%d}) "
                     "failed with errno %s", (int)optval.tv_sec,
                     (int)optval.tv_usec, errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDTIMEO, &optval);
    if (optval.tv_sec != TST_SNDTIMEO || optval.tv_usec != 0)
    {
        TEST_FAIL("Unexpected optval returned by getsockopt()");
    }

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, 1);

    /* Add a new static ARP entry */
    if (tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                        gw2_addr, CVT_HW_ADDR(alien_link_addr),
                        TRUE) != 0)
    {
        TEST_FAIL("Cannot add a new ARP entry");
    }
    arp_entry_added = TRUE;
    CFG_WAIT_CHANGES;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (rc != -1)
        TEST_FAIL("connect() returned %d instead of -1, "
                  "whereas ARP table has not valid entry", rc);

    CHECK_RPC_ERRNO(pco_iut, RPC_EINPROGRESS, "connect() returned -1, but");

    CHECK_CALL_DURATION(pco_iut->duration, TST_SNDTIMEO * 1000000);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (rc != -1)
        TEST_FAIL("connect() returned %d instead of -1, "
                  "whereas socket should be already connected", rc);
    CHECK_RPC_ERRNO(pco_iut, RPC_EALREADY, "connect() returned -1, but");

    /* Delete ARP entry to allow connect to 'pco_tst' */
    if (tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, gw2_addr) != 0)
    {
        TEST_FAIL("Cannot delete ARP entry");
    }
    arp_entry_added = FALSE;
    CFG_WAIT_CHANGES;

    RING("ARP entry is deleted to restore traffic");

    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    rpc_connect(pco_iut, iut_s, tst_addr);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    if (arp_entry_added &&
        tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, gw2_addr) != 0)
    {
        ERROR("Cannot delete ARP entry while cleanup");
        result = EXIT_FAILURE;
    }

    if (route_dst_added &&
        tapi_cfg_del_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw1_addr)) != 0)
    {
        ERROR("Cannot delete route to the dst");
        result = EXIT_FAILURE;
    }

    if (route_src_added &&
        tapi_cfg_del_route_via_gw(pco_tst->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw2_addr)) != 0)
    {
        ERROR("Cannot delete route to the src");
        result = EXIT_FAILURE;
    }

    free(tx_buf);

    TEST_END;
}
