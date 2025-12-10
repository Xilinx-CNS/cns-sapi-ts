/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 *
 * Implementation of test API to create new network connections
 * based on VLAN, MACVLAN or IPVLAN interfaces.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#include "sockapi-ts.h"
#include "sockapi-ts_net_conns.h"
#include "vlan_common.h"
#include "tapi_test.h"

/* See description in sockapi-ts_net_conns.h */
void
sockts_allocate_network(cfg_handle *net_handle,
                        unsigned int *net_prefix,
                        int af)
{
    cfg_val_type           val_type;
    char                  *net_oid = NULL;

    if (af == AF_INET)
        CHECK_RC(tapi_cfg_alloc_ip4_net(net_handle));
    else
        CHECK_RC(tapi_cfg_alloc_ip6_net(net_handle));

    if (net_prefix != NULL)
    {
        CHECK_RC(cfg_get_oid_str(*net_handle, &net_oid));
        val_type = CVT_INTEGER;
        CHECK_RC(cfg_get_instance_fmt(&val_type, net_prefix,
                                      "%s/prefix:", net_oid));
        free(net_oid);
    }
}

/**
 * Create a pair of VLAN interfaces on IUT and Tester,
 * assign IP addresses from a new network to them.
 *
 * @param pco_iut             RPC server on IUT.
 * @param pco_tst             RPC server on Tester.
 * @param iut_if              Base network interface on IUT.
 * @param tst_if              Base network interface on Tester.
 * @param vlan_id             VLAN ID.
 * @param af                  @c AF_INET or @c AF_INET6 - determines
 *                            whether IPv4 or IPv6 addresses should
 *                            be assigned.
 * @param conn                Where to save information
 *                            about newly created objects
 *                            and configuration changes.
 */
static void
configure_vlan_pair(rcf_rpc_server *pco_iut,
                    rcf_rpc_server *pco_tst,
                    const struct if_nameindex *iut_if,
                    const struct if_nameindex *tst_if,
                    int vlan_id, int af,
                    sockts_net_conn *conn)
{
    sockts_allocate_network(&conn->net_handle, &conn->net_prefix,
                            af);

    conn->vlan_id = vlan_id;

    CREATE_CONFIGURE_VLAN_EXT(pco_iut, conn->net_handle,
                              conn->iut_addr_handle,
                              conn->iut_addr, conn->net_prefix,
                              iut_if, vlan_id,
                              conn->iut_new_if.if_name,
                              conn->iut_new_if_configured, TRUE);
    CREATE_CONFIGURE_VLAN_EXT(pco_tst, conn->net_handle,
                              conn->tst_addr_handle,
                              conn->tst_addr, conn->net_prefix,
                              tst_if, vlan_id,
                              conn->tst_new_if.if_name,
                              conn->tst_new_if_configured, TRUE);

    conn->iut_new_if.if_index = rpc_if_nametoindex(
                                              pco_iut,
                                              conn->iut_new_if.if_name);

    conn->tst_new_if.if_index = rpc_if_nametoindex(
                                              pco_tst,
                                              conn->tst_new_if.if_name);

    TAPI_SET_NEW_PORT(pco_iut, conn->iut_addr);
    TAPI_SET_NEW_PORT(pco_tst, conn->tst_addr);
}

/**
 * Create two VLAN interfaces on IUT and Tester; assign
 * IP addresses from a different network to each pair.
 *
 * @param pco_iut             RPC server on IUT.
 * @param pco_tst             RPC server on Tester.
 * @param iut_if              Base network interface on IUT.
 * @param tst_if              Base network interface on Tester.
 * @param vlan1               The first VLAN ID.
 * @param vlan2               The second VLAN ID.
 * @param af                  Address family of assigned addresses
 *                            (@c AF_INET or @c AF_INET6).
 * @param conns               Where to save information
 *                            about newly created objects
 *                            and configuration changes.
 */
static void
configure_vlans(rcf_rpc_server *pco_iut,
                rcf_rpc_server *pco_tst,
                const struct if_nameindex *iut_if,
                const struct if_nameindex *tst_if,
                int vlan1, int vlan2,
                int af, sockts_net_conns *conns)
{
    conns->pco_iut = pco_iut;
    conns->pco_tst = pco_tst;
    conns->iut_if = iut_if;
    conns->tst_if = tst_if;

    if (vlan1 >= 0)
    {
        configure_vlan_pair(pco_iut, pco_tst, iut_if, tst_if,
                            vlan1, af, &conns->conn1);
    }

    if (vlan2 >= 0)
    {
        configure_vlan_pair(pco_iut, pco_tst, iut_if, tst_if,
                            vlan2, af, &conns->conn2);
    }
}

/**
 * Create a new MACVLAN or IPVLAN interface on IUT, assign an address
 * from a new network to it and to Tester interface.
 *
 * @param pco_iut             RPC server on IUT.
 * @param pco_tst             RPC server on Tester.
 * @param iut_if              Base network interface on IUT.
 * @param tst_if              Base network interface on Tester.
 * @param macvlan             If @c TRUE, create MACVLAN interface,
 *                            otherwise IPVLAN interface.
 * @param if_id               ID to be used in interface name
 *                            to make it unique.
 * @param af                  @c AF_INET or @c AF_INET6 - determines
 *                            whether IPv4 or IPv6 addresses should
 *                            be assigned.
 * @param conn                Where to save information
 *                            about newly created objects
 *                            and configuration changes.
 */
static void
configure_macvlan_or_ipvlan_pair(
                   rcf_rpc_server *pco_iut,
                   rcf_rpc_server *pco_tst,
                   const struct if_nameindex *iut_if,
                   const struct if_nameindex *tst_if,
                   te_bool macvlan, int if_id, int af,
                   sockts_net_conn *conn)
{
    te_string if_name = TE_STRING_INIT;

    sockts_allocate_network(&conn->net_handle, &conn->net_prefix,
                            af);

    te_string_append(&if_name, "%svlan_%d", (macvlan ? "mac" : "ip"), if_id);
    conn->iut_new_if.if_name = if_name.ptr;

    if (macvlan)
    {
        CHECK_RC(tapi_cfg_base_if_add_macvlan(pco_iut->ta,
                                              iut_if->if_name,
                                              conn->iut_new_if.if_name,
                                              NULL));
    }
    else
    {
        const char *ipvlan_mode = getenv("SOCKAPI_TS_IPVLAN_MODE");
        const char *ipvlan_flag = getenv("SOCKAPI_TS_IPVLAN_FLAG");

        if (ipvlan_mode == NULL)
            ipvlan_mode = TAPI_CFG_IPVLAN_MODE_L2;
        if (ipvlan_flag == NULL)
            ipvlan_flag = TAPI_CFG_IPVLAN_FLAG_PRIVATE;

        CHECK_RC(tapi_cfg_base_if_add_ipvlan(pco_iut->ta,
                                             iut_if->if_name,
                                             conn->iut_new_if.if_name,
                                             ipvlan_mode, ipvlan_flag));
    }
    conn->iut_new_if_configured = TRUE;

    conn->iut_new_if.if_index = rpc_if_nametoindex(
                                              pco_iut,
                                              conn->iut_new_if.if_name);

    if (macvlan)
    {
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 2, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      conn->iut_new_if.if_name));
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 1, NULL,
                                      "net/ipv4/conf:%s/arp_ignore",
                                      conn->iut_new_if.if_name));
    }

    CHECK_RC(tapi_cfg_alloc_net_addr(conn->net_handle,
                                     &conn->iut_addr_handle,
                                     &conn->iut_addr));
    CHECK_RC(tapi_cfg_alloc_net_addr(conn->net_handle,
                                     &conn->tst_addr_handle,
                                     &conn->tst_addr));

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta,
                                           conn->iut_new_if.if_name,
                                           conn->iut_addr,
                                           conn->net_prefix,
                                           TRUE, NULL));

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta,
                                           tst_if->if_name,
                                           conn->tst_addr,
                                           conn->net_prefix,
                                           TRUE,
                                           &conn->tst_addr_handle2));

    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta,
                                 conn->iut_new_if.if_name));

    /*
     * ARP entry with another MAC may survive from the previous
     * test run, so it should be removed.
     */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      conn->iut_addr));

    TAPI_SET_NEW_PORT(pco_iut, conn->iut_addr);
    TAPI_SET_NEW_PORT(pco_tst, conn->tst_addr);
}

/**
 * Create two MACVLAN or IPVLAN interfaces on IUT, assign to them
 * addresses from different networks; assign two addresses
 * from the same networks to Tester interface.
 *
 * @param pco_iut             RPC server on IUT.
 * @param pco_tst             RPC server on Tester.
 * @param iut_if              Base network interface on IUT.
 * @param tst_if              Base network interface on Tester.
 * @param macvlan             If @c TRUE, create MACVLAN interfaces,
 *                            otherwise IPVLAN.
 * @param if_id1              An ID to use in the name of the first
 *                            MACVLAN or IPVLAN interface to make it
 *                            unique.
 * @param if_id2              An ID to use in the name of the second
 *                            MACVLAN or IPVLAN interface to make it
 *                            unique.
 * @param af                  Address family of assigned addresses
 *                            (@c AF_INET or @c AF_INET6).
 * @param conns               Where to save information
 *                            about newly created objects
 *                            and configuration changes.
 */
static void
configure_macvlans_or_ipvlans(
                   rcf_rpc_server *pco_iut,
                   rcf_rpc_server *pco_tst,
                   const struct if_nameindex *iut_if,
                   const struct if_nameindex *tst_if,
                   te_bool macvlan,
                   int if_id1, int if_id2, int af,
                   sockts_net_conns *conns)
{
    conns->pco_iut = pco_iut;
    conns->pco_tst = pco_tst;
    conns->iut_if = iut_if;
    conns->tst_if = tst_if;

    if (if_id1 >= 0)
    {
        configure_macvlan_or_ipvlan_pair(pco_iut, pco_tst, iut_if, tst_if,
                                         macvlan, if_id1, af,
                                         &conns->conn1);
    }
    if (if_id2 >= 0)
    {
        configure_macvlan_or_ipvlan_pair(pco_iut, pco_tst, iut_if, tst_if,
                                         macvlan, if_id2, af,
                                         &conns->conn2);
    }

    if (macvlan)
    {
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 2,
                                      &conns->old_iut_if_rp_filter,
                                      "net/ipv4/conf:%s/rp_filter",
                                      iut_if->if_name));
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 1,
                                      &conns->old_iut_if_arp_ignore,
                                      "net/ipv4/conf:%s/arp_ignore",
                                      iut_if->if_name));
    }
}

/* See description in sockapi-ts_net_conns.h */
void
sockts_configure_net_conns(rcf_rpc_server *pco_iut,
                           rcf_rpc_server *pco_tst,
                           const struct if_nameindex *iut_if,
                           const struct if_nameindex *tst_if,
                           int if_id1, int if_id2, int af,
                           te_interface_kind if_type,
                           sockts_net_conns *conns)
{
    conns->if_type = if_type;

    switch (if_type)
    {
        case TE_INTERFACE_KIND_VLAN:
            configure_vlans(pco_iut, pco_tst, iut_if, tst_if,
                            if_id1, if_id2, af, conns);
            break;

        case TE_INTERFACE_KIND_MACVLAN:
        case TE_INTERFACE_KIND_IPVLAN:
            configure_macvlans_or_ipvlans(
                                  pco_iut, pco_tst, iut_if, tst_if,
                                  (if_type == TE_INTERFACE_KIND_MACVLAN),
                                  if_id1, if_id2, af, conns);
            break;

        default:
            TEST_FAIL("%s(): not supported value %d of if_type argument",
                      __FUNCTION__, if_type);

    }
}

/* See description in sockapi-ts_net_conns.h */
te_errno
sockts_destroy_net_conns(sockts_net_conns *conns)
{
#define CHECK_RETURN(expr_) \
    do {                                                    \
        int rc_ = (expr_);                                  \
        if (rc_ != 0)                                       \
        {                                                   \
            ERROR(#expr_ " on line %d returned %r",         \
                  __LINE__, rc_);                           \
            return rc_;                                     \
        }                                                   \
    } while (0)

    if (conns->conn1.tst_addr_handle2 != CFG_HANDLE_INVALID)
        CHECK_RETURN(cfg_del_instance(conns->conn1.tst_addr_handle2,
                                      FALSE));

    if (conns->conn2.tst_addr_handle2 != CFG_HANDLE_INVALID)
        CHECK_RETURN(cfg_del_instance(conns->conn2.tst_addr_handle2,
                                      FALSE));

    if (conns->conn1.iut_addr_handle != CFG_HANDLE_INVALID)
        CHECK_RETURN(cfg_del_instance(conns->conn1.iut_addr_handle,
                                      FALSE));

    if (conns->conn1.tst_addr_handle != CFG_HANDLE_INVALID)
        CHECK_RETURN(cfg_del_instance(conns->conn1.tst_addr_handle,
                                      FALSE));

    if (conns->conn2.iut_addr_handle != CFG_HANDLE_INVALID)
        CHECK_RETURN(cfg_del_instance(conns->conn2.iut_addr_handle,
                                      FALSE));

    if (conns->conn2.tst_addr_handle != CFG_HANDLE_INVALID)
        CHECK_RETURN(cfg_del_instance(conns->conn2.tst_addr_handle,
                                      FALSE));

    if (conns->conn1.net_handle != CFG_HANDLE_INVALID)
        CHECK_RETURN(tapi_cfg_free_entry(&conns->conn1.net_handle));

    if (conns->conn2.net_handle != CFG_HANDLE_INVALID)
        CHECK_RETURN(tapi_cfg_free_entry(&conns->conn2.net_handle));

    if (conns->if_type == TE_INTERFACE_KIND_VLAN)
    {
        if (conns->conn1.iut_new_if_configured)
            CHECK_RETURN(
                tapi_cfg_base_if_del_vlan(conns->pco_iut->ta,
                                          conns->iut_if->if_name,
                                          conns->conn1.vlan_id));

        if (conns->conn1.tst_new_if_configured)
            CHECK_RETURN(
                tapi_cfg_base_if_del_vlan(conns->pco_tst->ta,
                                          conns->tst_if->if_name,
                                          conns->conn1.vlan_id));

        if (conns->conn2.iut_new_if_configured)
            CHECK_RETURN(
                tapi_cfg_base_if_del_vlan(conns->pco_iut->ta,
                                          conns->iut_if->if_name,
                                          conns->conn2.vlan_id));

        if (conns->conn2.tst_new_if_configured)
            CHECK_RETURN(
                tapi_cfg_base_if_del_vlan(conns->pco_tst->ta,
                                          conns->tst_if->if_name,
                                          conns->conn2.vlan_id));
    }
    else
    {
        char if_parent[IF_NAMESIZE];

        /*
         * If MACVLAN or IPVLAN is created over MACVLAN or IPVLAN, it
         * has base interface of that MACVLAN / IPVLAN as its parent,
         * not that interface itself.
         */
        CHECK_RETURN(tapi_cfg_get_if_parent(conns->pco_iut->ta,
                                            conns->conn1.iut_new_if.if_name,
                                            if_parent,
                                            sizeof(if_parent)));

        if (conns->if_type == TE_INTERFACE_KIND_MACVLAN)
        {
            if (conns->conn1.iut_new_if_configured)
            {
                CHECK_RETURN(
                    tapi_cfg_base_if_del_macvlan(
                                          conns->pco_iut->ta,
                                          if_parent,
                                          conns->conn1.iut_new_if.if_name));
            }

            if (conns->conn2.iut_new_if_configured)
            {
                CHECK_RETURN(
                    tapi_cfg_base_if_del_macvlan(
                                          conns->pco_iut->ta,
                                          if_parent,
                                          conns->conn2.iut_new_if.if_name));
            }
        }
        else
        {
            if (conns->conn1.iut_new_if_configured)
            {
                CHECK_RETURN(
                    tapi_cfg_base_if_del_ipvlan(
                                          conns->pco_iut->ta,
                                          if_parent,
                                          conns->conn1.iut_new_if.if_name));
            }

            if (conns->conn2.iut_new_if_configured)
            {
                CHECK_RETURN(
                    tapi_cfg_base_if_del_ipvlan(
                                          conns->pco_iut->ta,
                                          if_parent,
                                          conns->conn2.iut_new_if.if_name));
            }
        }
    }

    if (conns->conn1.tst_addr != NULL)
        CHECK_RC(tapi_cfg_del_neigh_entry(conns->pco_iut->ta,
                                          conns->iut_if->if_name,
                                          conns->conn1.tst_addr));
    if (conns->conn2.tst_addr != NULL)
        CHECK_RC(tapi_cfg_del_neigh_entry(conns->pco_iut->ta,
                                          conns->iut_if->if_name,
                                          conns->conn2.tst_addr));

    if (conns->conn1.iut_addr != NULL)
        CHECK_RC(tapi_cfg_del_neigh_entry(conns->pco_tst->ta,
                                          conns->tst_if->if_name,
                                          conns->conn1.iut_addr));
    if (conns->conn2.iut_addr != NULL)
        CHECK_RC(tapi_cfg_del_neigh_entry(conns->pco_tst->ta,
                                          conns->tst_if->if_name,
                                          conns->conn2.iut_addr));

    free(conns->conn1.iut_new_if.if_name);
    free(conns->conn1.tst_new_if.if_name);
    free(conns->conn2.iut_new_if.if_name);
    free(conns->conn2.tst_new_if.if_name);
    free(conns->conn1.iut_addr);
    free(conns->conn1.tst_addr);
    free(conns->conn2.iut_addr);
    free(conns->conn2.tst_addr);

    if (conns->old_iut_if_rp_filter >= 0)
        CHECK_RETURN(tapi_cfg_sys_set_int(conns->pco_iut->ta,
                                          conns->old_iut_if_rp_filter, NULL,
                                          "net/ipv4/conf:%s/rp_filter",
                                          conns->iut_if->if_name));

    if (conns->old_iut_if_arp_ignore >= 0)
        CHECK_RETURN(tapi_cfg_sys_set_int(conns->pco_iut->ta,
                                          conns->old_iut_if_arp_ignore, NULL,
                                          "net/ipv4/conf:%s/arp_ignore",
                                          conns->iut_if->if_name));

    return 0;
}

