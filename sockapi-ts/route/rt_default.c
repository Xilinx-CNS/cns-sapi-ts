/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-rt_default Default route
 *
 * @objective Check that the default route is taken into account
 *            in routing decision.
 *
 * @type conformance
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_single_if_variants_with_ipv6
 * @param rt_sock_type    Type of sockets used in the test
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_default"

#define SOCKTS_RT_CNS_SUPPORT
#include "ts_route.h"

#undef L5LINUX_STRONG_DEBUGING_ONLY

int
main(int argc, char **argv)
{
    SOCKTS_CNS_DECLARE_PARAMS;

    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    const struct sockaddr *alien_addr;
    tapi_env_net          *net;

    te_bool                resource_added = FALSE;
    cfg_handle             tst_addr_hndl = CFG_HANDLE_INVALID;
    cfg_handle             rt_hndl = CFG_HANDLE_INVALID;

    struct sockaddr_storage zero_addr;

    tapi_rt_entry_t       *rt_tbl = NULL;
    tapi_rt_entry_t       *rt_def = NULL;
    unsigned int           rt_num;

    int                   i;
    int                   af;
    sockts_socket_type    rt_sock_type;
    unsigned int          net_pfx;

    cfg_val_type     val_type;
    char            *def_ifname = NULL;

    sockts_if_monitor iut_if_monitor = SOCKTS_IF_MONITOR_INIT;

    TEST_START;

    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_NET(net);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, alien_addr);

    SOCKTS_CNS_GET_PARAMS(iut_addr->sa_family);

    af = tst_addr->sa_family;
    net_pfx = (af == AF_INET ? net->ip4pfx : net->ip6pfx);

    memset(&zero_addr, 0, sizeof(zero_addr));
    zero_addr.ss_family = af;

    TEST_STEP("Add @p alien_addr network address on @p tst_if interface.");

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           alien_addr, net_pfx, FALSE,
                                           &tst_addr_hndl));

    /* Get default route interface */
    val_type = CVT_STRING;
    rc = cfg_get_instance_fmt(
                &val_type, &def_ifname,
                "/agent:%s/ip%d_rt_default_if:",
                pco_iut->ta, (af == AF_INET ? 4 : 6));
    if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
    {
        def_ifname = NULL;
    }
    else if (rc != 0)
    {
        TEST_FAIL("Obtaining ip%d_rt_default_if value failed with rc = %r",
                  (af == AF_INET ? 4 : 6), rc);
    }

    if (def_ifname != NULL && def_ifname[0] != '\0')
    {
        /* Reserve interface used by default route for test purposes */
        CHECK_RC(tapi_cfg_base_if_check_add_rsrc(pco_iut->ta, def_ifname));
        resource_added = TRUE;
    }

#if L5LINUX_STRONG_DEBUGING_ONLY
    rpc_system(pco_iut, "ip route");
    rpc_system(pco_iut, "ip neigh");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-fwd");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-mac");
#endif

    TEST_STEP("Remove existing default route on IUT if it is present.");
    CHECK_RC(tapi_cfg_get_route_table(pco_iut->ta, af,
                                      &rt_tbl, &rt_num));
    for (i = 0; i < (int)rt_num; i++)
    {
        if (rt_tbl[i].prefix == 0 &&
            rt_tbl[i].dst.ss_family == af &&
            rt_tbl[i].table == TAPI_RT_TABLE_MAIN)
        {
            rt_def = &rt_tbl[i];
            CHECK_RC(tapi_cfg_del_route(&(rt_tbl[i].hndl)));
            break;
        }
    }

    TEST_STEP("On IUT add the default route via gateway @p tst_addr, which "
              "is directly accessed via @p iut_if interface.");

#if L5LINUX_STRONG_DEBUGING_ONLY
    rpc_system(pco_iut, "ip route");
    rpc_system(pco_iut, "ip neigh");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-fwd");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-mac");
#endif
    /* Add a new default route */
    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(SA(&zero_addr)), 0 /* Default route */,
            te_sockaddr_get_netaddr(tst_addr), NULL, NULL,
            0, 0, 0, 0, 0, 0, &rt_hndl) != 0)
    {
        TEST_FAIL("Cannot add default route");
    }

    SINGLE_IF_CNS_ROUTE;

    CFG_WAIT_CHANGES;

#if L5LINUX_STRONG_DEBUGING_ONLY
    rpc_system(pco_iut, "ip route");
    rpc_system(pco_iut, "ip neigh");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-fwd");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-mac");
#endif

    CHECK_RC(sockts_if_monitor_init(&iut_if_monitor,
                                    pco_iut->ta, iut_if->if_name, af,
                                    sock_type_sockts2rpc(rt_sock_type),
                                    NULL, alien_addr,
                                    FALSE, TRUE));

    TEST_STEP("Check than data can be sent from IUT to @p alien_addr "
              "on TESTER via default route, using a pair of "
              "sockets of type defined by @p rt_sock_type.");

    SOCKTS_RT_CHECK_RC(sockts_rt_check_route(
                                      rt_sock_type,
                                      SOCKTS_RT_PCO_IUT_SOCK,
                                      SOCKTS_RT_IUT_ADDR,
                                      pco_tst, alien_addr,
                                      SOCKTS_ADDR_NONE, FALSE,
                                      "Check after adding default route"));
    CHECK_IF_ACCELERATED(&env, &iut_if_monitor,
                         "Check after adding default route");

    TEST_STEP("Delete the default route on IUT.");
    CHECK_RC(tapi_cfg_del_route(&rt_hndl));
    rt_hndl = CFG_HANDLE_INVALID;
    CFG_WAIT_CHANGES;

#if L5LINUX_STRONG_DEBUGING_ONLY
    rpc_system(pco_iut, "ip route");
    rpc_system(pco_iut, "ip neigh");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-fwd");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-mac");
#endif

    TEST_STEP("Try to send data from IUT to @p alien_addr again, "
              "check that it fails.");
    rc = sockts_rt_check_route(rt_sock_type,
                               SOCKTS_RT_PCO_IUT_SOCK,
                               SOCKTS_RT_IUT_ADDR,
                               pco_tst, alien_addr,
                               SOCKTS_ADDR_NONE, FALSE,
                               NULL);
    if (rc == 0)
    {
        TEST_VERDICT("After removing default route data "
                     "can still be sent to alien_addr");
    }
    else
    {
        sockts_rt_error exp_error;

        exp_error.rpcs = pco_iut;
        if (SOCKTS_RT_CNS_TEST)
        {
            /*
             * In Calico-style netns a route to main
             * netns remains, so there is no failure of
             * connect()/send().
             */
            if (sock_type_sockts2rpc(rt_sock_type) == RPC_SOCK_STREAM)
            {
                exp_error.err_code = SOCKTS_RT_ERR_NOT_ACCEPTED;
            }
            else
            {
                exp_error.err_code = SOCKTS_RT_ERR_SEND_RECV;
                exp_error.test_send_err = SOCKTS_TEST_SEND_NO_DATA;
            }
        }
        else
        {
            switch (rt_sock_type)
            {
                case SOCKTS_SOCK_UDP:
                case SOCKTS_SOCK_TCP_ACTIVE:
                    exp_error.err_code = SOCKTS_RT_ERR_RPC_CONNECT;
                    break;

                case SOCKTS_SOCK_UDP_NOTCONN:
                    exp_error.err_code = SOCKTS_RT_ERR_SEND_RECV;
                    exp_error.test_send_err =
                                SOCKTS_TEST_SEND_FIRST_SEND_FAIL;
                    break;

                case SOCKTS_SOCK_TCP_PASSIVE_CL:
                    exp_error.err_code = SOCKTS_RT_ERR_NOT_ACCEPTED;
                    break;

                default:
                    TEST_FAIL("Not supported rt_sock_type value");
            }
        }

        exp_error.rpc_errno = RPC_ENETUNREACH;

        if (!sockts_rt_error_check(&exp_error))
        {
            ERROR("Expected error is %s",
                  sockts_rt_error2str(&exp_error));
            ERROR("Obtained error is %s",
                  sockts_rt_error2str(&rt_error));

            TEST_VERDICT("After removing a default route "
                         "sockts_rt_check_route() reported "
                         "unexpected failure %s",
                         sockts_rt_error2str(&rt_error));
        }
    }

    TEST_STEP("Recover the default route which was created earlier.");
    if (tapi_cfg_add_route(pco_iut->ta, af,
            te_sockaddr_get_netaddr(SA(&zero_addr)), 0 /* Default route */,
            te_sockaddr_get_netaddr(tst_addr), NULL, NULL,
            0, 0, 0, 0, 0, 0, &rt_hndl) != 0)
    {
        TEST_FAIL("Cannot add default route");
    }
    CFG_WAIT_CHANGES;

#if L5LINUX_STRONG_DEBUGING_ONLY
    rpc_system(pco_iut, "ip route");
    rpc_system(pco_iut, "ip neigh");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-fwd");
    rpc_system(pco_iut, "cat /proc/driver/level5/mib-mac");
#endif

    TEST_STEP("Check that now data can be successfully sent from IUT to "
              "@p alien_addr.");
    SOCKTS_RT_CHECK_RC(sockts_rt_check_route(
                                   rt_sock_type,
                                   SOCKTS_RT_PCO_IUT_SOCK,
                                   SOCKTS_RT_IUT_ADDR,
                                   pco_tst, alien_addr,
                                   SOCKTS_ADDR_NONE, FALSE,
                                   "Check after adding "
                                   "default route again"));

    CHECK_IF_ACCELERATED(&env, &iut_if_monitor,
                         "Check after adding default route again");

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(
        sockts_if_monitor_destroy(&iut_if_monitor));

    if (rt_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&rt_hndl));

    /* Restore the original default route */
    if (rt_def != NULL && rt_def->hndl == CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(tapi_cfg_add_route(
            pco_iut->ta, af,
            te_sockaddr_get_netaddr(SA(&zero_addr)), 0 /* Default route */,
            (rt_def->flags & TAPI_RT_GW) ?
                te_sockaddr_get_netaddr(SA(&(rt_def->gw))) : NULL,
            (rt_def->flags & TAPI_RT_IF) ? rt_def->dev : NULL, NULL,
            rt_def->flags, rt_def->metric, 0,
            rt_def->mtu, rt_def->win, rt_def->irtt, &rt_hndl));
    }

    if (tst_addr_hndl != CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(tst_addr_hndl, FALSE));
        /*
         * This is done to prevent issues with FAILED neighbor
         * entries on IPv6, see bug 9774.
         */
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                                  iut_if->if_name,
                                                  alien_addr));
    }

    if (resource_added)
    {
        CLEANUP_CHECK_RC(tapi_cfg_base_if_del_rsrc(pco_iut->ta,
                                                   def_ifname));
    }

    free(def_ifname);
    free(rt_tbl);

    SOCKTS_RT_CNS_CLEANUP;

    TEST_END;
}
