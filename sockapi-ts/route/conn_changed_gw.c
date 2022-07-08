/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-conn_changed_gw Changing route to the peer after connecting sockets
 *
 * @objective Check that TCP and UDP connections stay alive after changing
 *            the gateway providing access to the peer.
 *
 * @type conformance
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_triangle_variants_with_ipv6
 * @param rt_sock_type    Type of sockets used in test
 * @param with_arp_entry  If @c TRUE, add a neighbor table entry
 *                        on IUT for Tester and Gateway addresses.
 *
 * @par Test sequence:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/conn_changed_gw"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

/** How long to wait for data arrival, milliseconds. */
#define TST_RCV_TIMEOUT       500

int
main(int argc, char *argv[])
{
    SOCKTS_RT_CNS_DECLARE_PARAMS;

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_gw = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *iut1_addr;
    const struct sockaddr *iut2_addr;
    const struct sockaddr *gwa_addr = NULL;
    const struct sockaddr *gwb_addr = NULL;
    const struct sockaddr *tst1_addr;
    const struct sockaddr *tst2_addr;

    te_bool                via_gwa_added = FALSE;
    te_bool                via_gwb_added = FALSE;
    te_bool                via_iut2_added = FALSE;
    te_bool                via_tst2_added = FALSE;

    int                    af;
    rpc_socket_type        sock_type;
    sockts_socket_type     rt_sock_type;
    te_bool                with_arp_entry;

    const struct if_nameindex *iut1_if = NULL;
    const struct if_nameindex *iut2_if = NULL;
    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;
    const struct sockaddr     *gw_hwaddr = NULL;
    const struct sockaddr     *tst_hwaddr = NULL;

    sockts_if_monitor iut1_if_monitor = SOCKTS_IF_MONITOR_INIT;
    sockts_if_monitor iut2_if_monitor = SOCKTS_IF_MONITOR_INIT;
    sockts_if_monitor tst1_if_monitor = SOCKTS_IF_MONITOR_INIT;
    sockts_if_monitor tst2_if_monitor = SOCKTS_IF_MONITOR_INIT;
    te_bool           handover = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut1_if);
    TEST_GET_IF(iut2_if);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_ADDR(pco_iut, iut1_addr);
    TEST_GET_ADDR(pco_iut, iut2_addr);
    TEST_GET_ADDR(pco_tst, tst1_addr);
    TEST_GET_ADDR(pco_tst, tst2_addr);
    TEST_GET_ADDR_NO_PORT(gwa_addr);
    TEST_GET_ADDR_NO_PORT(gwb_addr);
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_BOOL_PARAM(with_arp_entry);
    TEST_GET_LINK_ADDR(gw_hwaddr);
    TEST_GET_LINK_ADDR(tst_hwaddr);
    SOCKTS_RT_CNS_GET_PARAMS(iut1_addr->sa_family);

    sock_type = sock_type_sockts2rpc(rt_sock_type);
    af = iut1_addr->sa_family;

    TEST_STEP("Let @b iut_addr be the network address assigned to "
              "the first IUT interface.");
    if (SOCKTS_RT_CNS_TEST)
    {
        iut_addr = iut_addr_cns;

        if (strcmp(pco_gw->ta, pco_tst->ta) != 0)
        {
            CHECK_RC(
              tapi_cfg_add_route_via_gw(
                pco_gw->ta,
                af, te_sockaddr_get_netaddr(iut_addr),
                te_netaddr_get_bitsize(af),
                te_sockaddr_get_netaddr(iut1_addr)));
        }
    }
    else
    {
        iut_addr = iut1_addr;

        if (!sockts_if_accelerated(&env, pco_iut->ta,
                                   iut1_if->if_name))
            handover = TRUE;
    }

    /*
     * The test uses triangular configuration.
     * Adjust routing:
     *    iut_addr <-> (gwa_addr-gwb_addr) <-> tst1_addr.
     */

    /* Turn on forwarding on gateway host. */
    if (af == AF_INET)
        CHECK_RC(tapi_cfg_base_ipv4_fw(pco_gw->ta, TRUE));
    else
        CHECK_RC(tapi_cfg_base_ipv6_fw(pco_gw->ta, TRUE));

    TEST_STEP("Add route on Tester: @b iut_addr via gateway @p gwb_addr.");
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
            af, te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(gwb_addr)) != 0)
    {
        TEST_FAIL("Cannot add route on 'pco_tst' to access "
                  "'iut_addr' via 'gwb_addr'");
    }
    via_gwb_added = TRUE;

    TEST_STEP("Add route on IUT: @p tst1_addr via gateway @p gwa_addr.");
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
            af, te_sockaddr_get_netaddr(tst1_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(gwa_addr)) != 0)
    {
        TEST_FAIL("Cannot add route on 'pco_iut' to access "
                  "'tst1_addr' via 'gwa_addr'");
    }
    via_gwa_added = TRUE;

    CHECK_RC(sockts_if_monitor_init(&tst1_if_monitor,
                                    pco_tst->ta, tst1_if->if_name,
                                    af, sock_type,
                                    NULL, iut_addr,
                                    TRUE, FALSE));

    CHECK_RC(sockts_if_monitor_init(&tst2_if_monitor,
                                    pco_tst->ta, tst2_if->if_name,
                                    af, sock_type,
                                    NULL, iut_addr,
                                    TRUE, FALSE));

    CHECK_RC(sockts_if_monitor_init(&iut1_if_monitor,
                                    pco_iut->ta, iut1_if->if_name,
                                    af, sock_type,
                                    iut_addr, NULL,
                                    FALSE, TRUE));

    CHECK_RC(sockts_if_monitor_init(&iut2_if_monitor,
                                    pco_iut->ta, iut2_if->if_name,
                                    af, sock_type,
                                    iut_addr, NULL,
                                    FALSE, TRUE));

    TEST_STEP("If @p with_arp_entry is @c TRUE, add neighbor table entries "
              "on IUT for @p tst2_addr and @p gwa_addr.");

    if (with_arp_entry)
    {
        CHECK_RC(tapi_update_arp(pco_iut->ta, iut2_if->if_name, NULL, NULL,
                                 tst2_addr, CVT_HW_ADDR(tst_hwaddr),
                                 FALSE));
        CHECK_RC(tapi_update_arp(pco_iut->ta, iut1_if->if_name, NULL, NULL,
                                 gwa_addr, CVT_HW_ADDR(gw_hwaddr),
                                 FALSE));
    }
    else
    {
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut2_if->if_name,
                                          tst2_addr));
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut1_if->if_name,
                                          gwa_addr));
    }

    CFG_WAIT_CHANGES;

    TEST_STEP("Create sockets on IUT and Tester according to "
              "@p rt_sock_type, binding IUT socket to @b iut_addr "
              "and Tester socket to @p tst1_addr.");
    TEST_STEP("Establish connection if required by @p rt_sock_type; "
              "send/receive data in both directions between the sockets. "
              "Check that IUT packets are sent over @p iut1_if "
              "interface.");

    sockts_rt_one_sock_check_route(TRUE, iut_addr, tst1_addr,
                                   "Before gateway change",
                                   &env, SOCKTS_RT_PCO_IUT_SOCK, pco_tst,
                                   &iut_s, &tst_s,
                                   rt_sock_type,
                                   &iut1_if_monitor,
                                   &iut2_if_monitor,
                                   &tst1_if_monitor,
                                   &tst2_if_monitor,
                                   handover);

    TEST_STEP("Remove previously added routes.");

    if (via_gwa_added &&
        tapi_cfg_del_route_via_gw(pco_iut->ta,
            af, te_sockaddr_get_netaddr(tst1_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(gwa_addr)) != 0)
    {
        TEST_FAIL("Cannot delete route on 'pco_iut' to access "
                  "'tst1_addr' via 'gwa_addr'");
    }
    via_gwa_added = FALSE;

    if (via_gwb_added &&
        tapi_cfg_del_route_via_gw(pco_tst->ta,
            af, te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(gwb_addr)) != 0)
    {
        TEST_FAIL("Cannot delete route on 'pco_tst' to access "
                  "'iut_addr' via 'gwb_addr'");
    }
    via_gwb_added = FALSE;

    TEST_STEP("Add a new route on Tester to access @b iut_addr "
              "via gateway @p iut2_addr.");
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
            af, te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(iut2_addr)) != 0)
    {
        TEST_FAIL("Cannot add route on 'pco_tst' to access "
                  "'iut_addr' via 'iut2_addr'");
    }
    via_iut2_added = TRUE;

    TEST_STEP("Add new route on IUT to access @p tst1_addr "
              "via gateway @p tst2_addr.");
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
            af, te_sockaddr_get_netaddr(tst1_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(tst2_addr)) != 0)
    {
        TEST_FAIL("Cannot add route on 'pco_iut' to access "
                  "'tst1_addr' via 'tst2_addr'");
    }
    via_tst2_added = TRUE;

    CFG_WAIT_CHANGES;

    TEST_STEP("Send/receive data in both directions between the sockets. "
              "Check that IUT packets are sent over @p iut2_if "
              "interface.");

    sockts_rt_one_sock_check_route(FALSE, iut_addr, tst1_addr,
                                   "After gateway change",
                                   &env, SOCKTS_RT_PCO_IUT_SOCK, pco_tst,
                                   &iut_s, &tst_s,
                                   rt_sock_type,
                                   &iut1_if_monitor,
                                   &iut2_if_monitor,
                                   &tst1_if_monitor,
                                   &tst2_if_monitor,
                                   handover);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(SOCKTS_RT_PCO_IUT_SOCK, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(
        sockts_if_monitor_destroy(&tst1_if_monitor));
    CLEANUP_CHECK_RC(
        sockts_if_monitor_destroy(&tst2_if_monitor));
    CLEANUP_CHECK_RC(
        sockts_if_monitor_destroy(&iut1_if_monitor));
    CLEANUP_CHECK_RC(
        sockts_if_monitor_destroy(&iut2_if_monitor));

    if (via_tst2_added)
    {
        CLEANUP_CHECK_RC(
          tapi_cfg_del_route_via_gw(
            pco_iut->ta,
            af, te_sockaddr_get_netaddr(tst1_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(tst2_addr)));
    }

    if (via_iut2_added)
    {
        CLEANUP_CHECK_RC(
          tapi_cfg_del_route_via_gw(
            pco_tst->ta,
            af, te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(iut2_addr)));
    }

    if (via_gwa_added)
    {
        CLEANUP_CHECK_RC(
          tapi_cfg_del_route_via_gw(
            pco_iut->ta,
            af, te_sockaddr_get_netaddr(tst1_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(gwa_addr)));
    }

    if (via_gwb_added)
    {
        CLEANUP_CHECK_RC(
          tapi_cfg_del_route_via_gw(
            pco_tst->ta,
            af, te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_bitsize(af),
            te_sockaddr_get_netaddr(gwb_addr)));
    }

    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
