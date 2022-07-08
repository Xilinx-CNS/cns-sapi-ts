/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Routing table
 */

/**
 * @page route-asymmetric Asymmetric routing
 *
 * @objective Check routing configuration when traffic is sent over
 *            one interface but received over another interface.
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_triangle_variants_with_ipv6
 * @param rt_sock_type    Type of sockets used in the test:
 *                        - @c tcp_active
 *                        - @c tcp_passive
 *                        - @c udp
 *                        - @c udp_connect
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/asymmetric"

#include "sockapi-test.h"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

int
main(int argc, char *argv[])
{
    SOCKTS_CNS_DECLARE_PARAMS;

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_gw = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;

    const struct if_nameindex *iut1_if = NULL;
    const struct if_nameindex *iut2_if = NULL;
    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;
    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *iut_if2 = NULL;

    const struct sockaddr *iut1_addr = NULL;
    const struct sockaddr *iut2_addr = NULL;
    const struct sockaddr *gwa_addr = NULL;
    const struct sockaddr *tst_remote_addr = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    int                    af;
    sockts_socket_type     rt_sock_type;
    te_bool                handover = FALSE;

    tarpc_linger  linger_val = { .l_onoff = 1, .l_linger = 0 };
    int           iut_s = -1;
    int           tst_s = -1;

    DECLARE_TWO_IFS_MONITORS;

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
    TEST_GET_ADDR_NO_PORT(gwa_addr);
    TEST_GET_ADDR(pco_tst, tst_remote_addr);
    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);

    SOCKTS_CNS_GET_PARAMS(iut1_addr->sa_family);

    TEST_STEP("Let @b iut_addr be the network address on "
              "the first IUT interface.");

    af = iut1_addr->sa_family;
    /* These assignments are done to make common macros usable. */
    pco_tst1 = pco_tst;
    pco_tst2 = pco_tst;
    iut_if1 = iut1_if;
    iut_if2 = iut2_if;
    if (SOCKTS_RT_CNS_TEST)
        iut_addr = iut_addr_cns;
    else
        iut_addr = iut1_addr;
    tst_addr = tst_remote_addr;

    if (sockts_if_accelerated(&env, pco_iut->ta, iut_if1->if_name) == FALSE)
        handover = TRUE;

    TEST_STEP("Enable forwarding on gateway host.");
    if (af == AF_INET)
        CHECK_RC(tapi_cfg_base_ipv4_fw(pco_gw->ta, TRUE));
    else
        CHECK_RC(tapi_cfg_base_ipv6_fw(pco_gw->ta, TRUE));

    TEST_STEP("If IPv4 is checked, set @c rp_filter to @c 2 on @p iut2_if "
              "and @p tst1_if interfaces; otherwise incoming packets may "
              "be dropped when they come from an interface which differs "
              "from outgoing interface to the same destination.");
    if (af == AF_INET)
    {
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 2, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      iut2_if->if_name));
        CHECK_RC(tapi_cfg_sys_set_int(pco_tst->ta, 2, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      tst1_if->if_name));
    }

    TEST_STEP("On Tester add a route to @b iut_addr via gateway "
              "@p iut2_addr (which is reachable over @p tst2_if).");

    CHECK_RC(tapi_cfg_add_route_via_gw(
                pco_tst->ta, af, te_sockaddr_get_netaddr(iut_addr),
                te_netaddr_get_bitsize(af),
                te_sockaddr_get_netaddr(iut2_addr)));

    TEST_STEP("On IUT add a route to @p tst_remote_addr via gateway "
              "@p gwa_addr (which is reachable over @p iut1_if).");
    CHECK_RC(tapi_cfg_add_route_via_gw(
                pco_iut->ta, af, te_sockaddr_get_netaddr(tst_remote_addr),
                te_netaddr_get_bitsize(af),
                te_sockaddr_get_netaddr(gwa_addr)));

    if (SOCKTS_RT_CNS_TEST &&
        strcmp(pco_gw->ta, pco_tst->ta) != 0)
    {
        TEST_STEP("If Calico-style configuration is checked and gateway "
                  "is used, configure route to @b iut_addr via "
                  "@p iut_addr1 on gateway - otherwise packets sent "
                  "from an address inside Calico-style namespace may be "
                  "dropped.");
        CHECK_RC(tapi_cfg_add_route_via_gw(
                    pco_gw->ta, af, te_sockaddr_get_netaddr(iut_addr),
                    te_netaddr_get_bitsize(af),
                    te_sockaddr_get_netaddr(iut1_addr)));
    }

    CFG_WAIT_CHANGES;

    INIT_TWO_IFS_MONITORS_EXT(tst_remote_addr, af, rt_sock_type,
                              TRUE, FALSE);

    TEST_STEP("Create a pair of sockets of type @p rt_sock_type on IUT "
              "and Tester, binding them to @b iut_addr and "
              "@p tst_remote_addr. Establish connection if required.");
    TEST_STEP("Three times send and receive data in both directions "
              "over the created sockets.");

    SOCKTS_RT_CHECK_ROUTE_ONE_SOCK(TRUE, handover, "The first check");
    SOCKTS_RT_CHECK_ROUTE_ONE_SOCK(TRUE, handover, "The second check");
    SOCKTS_RT_CHECK_ROUTE_ONE_SOCK(TRUE, handover, "The third check");

    if (sockts_if_monitor_check_out(&tst1_if_monitor, FALSE))
        TEST_VERDICT("Tester sent packet(s) over the first interface");
    if (!sockts_if_monitor_check_out(&tst2_if_monitor, FALSE))
    {
        TEST_VERDICT("Tester did not send packets over the second "
                     "interface");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_TWO_IFS_MONITORS;

    /*
     * Set SO_LINGER to zero before closing to avoid disturbing
     * the next iteration with retransmits.
     */
    rpc_setsockopt(SOCKTS_RT_PCO_IUT_SOCK, iut_s,
                   RPC_SO_LINGER, &linger_val);
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER, &linger_val);
    CLEANUP_RPC_CLOSE(SOCKTS_RT_PCO_IUT_SOCK, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
