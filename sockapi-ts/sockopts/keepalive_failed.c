/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-keepalive_failed iomux function breaks out with read event if keepalive failed
 *
 * @objective Check that iomux function breaks out with read event if keepalive
 *            procedure fails on this socket.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_gw        PCO on host in the tested network
 *                      that is able to forward incoming packets (router)
 * @param pco_tst       PCO on TESTER
 * @param intv_cor      Correction for KEEPINTVL socket option to make
 *                      condition when KEEPINTVL < KEEPIDLE and
 *                      KEEPINTVL > KEEPIDLE
 *
 * @par Test sequence:
 * -# Create @c SOCK_STREAM connection between @p pco_iut and @p pco_tst, as 
 *    local address on @p pco_tst use @p tst_addr address. As a result two
 *    sockets appear @p iut_s and @p tst_s.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Configure idle time, number of probes and interval between probes.
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_KEEPALIVE socket 
 *    option to get its initial value.
 * -# Check that it is set to zero - disabled by default. If the option is
 *    enabled disable it with @b setsockopt().
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p iut_s socket enabling @c SO_KEEPALIVE
 *    socket option.
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_KEEPALIVE socket
 *    option, and check that its value is @c 1.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# On @p pco_tst side add a new static ARP entry for @p iut_addr 
 *    specifying as link layer address one that is not belong to any 
 *    stations in subnetwork.
 * -# Call @b iomux_call() on @p pco_iut waiting for @p iut_s socket becomes
 *    readable with @p timeout as the "idle time" * 2.
 * -# Check that @b iomux_call() returns the readable event.
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_ERROR option.
 * -# Check that option value is not @c 0.
 * -# Delete the static ARP entry.
 * -# Close @p tst_s, and @p iut_s sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/keepalive_failed"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"
#include "iomux.h"

#define TIME_BEFORE_PROBES   10
#define PROB_INTERVAL        6
#define PROB_NUM             1

static int kalive_idle_time  = TIME_BEFORE_PROBES;
static int kalive_intvl_time = PROB_INTERVAL;
static int kalive_probe_cnt  = PROB_NUM;

int
main(int argc, char *argv[])
{
    rpc_socket_domain      domain;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_gw = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr;
    const struct sockaddr *gw1_addr = NULL;
    const struct sockaddr *gw2_addr = NULL;

    const struct if_nameindex *gw2_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    te_bool                route_dst_added = FALSE;
    te_bool                route_src_added = FALSE;
    te_bool                arp_entry_added = FALSE;

    const void            *alien_link_addr;
    int                    opt_val;

    int                    ret;

    int                    intv_cor;
    

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(gw1_addr);
    TEST_GET_ADDR_NO_PORT(gw2_addr);

    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(gw2_if);
    TEST_GET_IF(tst_if);

    TEST_GET_INT_PARAM(intv_cor);

    kalive_intvl_time += intv_cor;
    
    domain = rpc_socket_domain_by_addr(iut_addr);

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

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Configure idle time, number of probes and interval between probes */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_setsockopt(pco_iut, iut_s, RPC_TCP_KEEPIDLE,
                         &kalive_idle_time);
    if (ret == 0)
    {
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_KEEPINTVL,
                       &kalive_intvl_time);
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_KEEPCNT,
                       &kalive_probe_cnt);
    }
    else
    {
        int kalive_threshold = TE_SEC2MS(kalive_idle_time);
        int kalive_abort = TE_SEC2MS(kalive_intvl_time * kalive_probe_cnt);

        CHECK_RPC_ERRNO(pco_iut, RPC_ENOPROTOOPT,
                        "setsockopt(TCP_KEEPIDLE) failed");

        RPC_AWAIT_IUT_ERROR(pco_iut);
        ret = rpc_setsockopt(pco_iut, iut_s,
                             RPC_TCP_KEEPALIVE_THRESHOLD,
                             &kalive_threshold);
        if (ret != 0)
        {
            TEST_VERDICT("setsockopt(TCP_KEEPALIVE_THRESHOLD) failed "
                         "with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }

        RPC_AWAIT_IUT_ERROR(pco_iut);
        ret = rpc_setsockopt(pco_iut, iut_s,
                             RPC_TCP_KEEPALIVE_ABORT_THRESHOLD,
                             &kalive_abort);
        if (ret != 0)
        {
            TEST_VERDICT("setsockopt(TCP_KEEPALIVE_ABORT_THRESHOLD) "
                         "failed with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }


    rpc_getsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &opt_val);
    if (opt_val != 0)
    {
        WARN("SO_KEEPALIVE socket option is enabled by default");

        opt_val = 0;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &opt_val);
    }

    /* Switch on SO_KEEPALIVE socket option */
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &opt_val);

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_KEEPALIVE, &opt_val);
    if (opt_val == 0)
    {
        TEST_FAIL("The value of SO_KEEPALIVE socket option is not updated "
                  "by setsockopt() function");
    }

    /* Add a new static ARP entry */
    if (tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                        gw2_addr, CVT_HW_ADDR(alien_link_addr),
                        TRUE) != 0)
    {
        TEST_FAIL("Cannot add a new ARP entry");
    }
    arp_entry_added = TRUE;
    RING("ARP entry to break connection added");

    rc = iomux_call_default_simple(pco_iut, iut_s, EVT_RD, NULL,
                TE_SEC2MS(kalive_idle_time +
                          kalive_intvl_time * kalive_probe_cnt + 10));

    if (rc != 1)
    {
        TEST_FAIL("'iut_s' socket is not readable after keepalive is failed");
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != 0)
    {
        RING("The value of SO_ERROR socket option is set to %s "
             "after previous 'select()' returns with readable event",
              errno_rpc2str(opt_val));
    }
    else
    {
        TEST_FAIL("Some error is expected when keepalive procedure failed");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

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

    TEST_END;
}

