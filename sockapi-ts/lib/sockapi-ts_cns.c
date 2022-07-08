/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TAPI for checking Calico-style network namespace
 *
 * Implementation TAPI for checking Calico-style network namespace
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#include "sockapi-test.h"
#include "tapi_namespaces.h"
#include "tapi_host_ns.h"
#include "sockapi-ts_cns.h"

/* See description in sockapi-ts_cns.h */
void
sockts_cns_setup(const char *ta)
{
    const char *test_calico = getenv("SOCKAPI_TS_NETNS_CALICO");
    const char *ta_type;
    const char *host;
    const char *ip4_local_addr_str = NULL;
    const char *ta_ns = NULL;
    const char *ta_rpcprovider = NULL;
    const char *rpcs_name = NULL;
    const char *ipv4_only_run_str = NULL;
    te_bool     ipv4_only_run = FALSE;

    const char *veth1_name = NULL;
    const char *veth2_name = NULL;
    const char *ns_name = NULL;
    const char *rcfport_str = NULL;
    int         rcfport = -1;
    int         rc;

    struct sockaddr_storage ip4_addr;
    struct sockaddr_storage ip6_addr;
    struct sockaddr_storage ip4_local_addr;
    struct sockaddr_storage ip6_local_addr;

    struct in_addr   ip4_zero_addr;
    struct in6_addr  ip6_zero_addr;

    if (test_calico == NULL || strcmp(test_calico, "true") != 0)
        return;

    memset(&ip4_local_addr, 0, sizeof(ip4_local_addr));
    memset(&ip6_local_addr, 0, sizeof(ip6_local_addr));
    memset(&ip4_zero_addr, 0, sizeof(ip4_zero_addr));
    memset(&ip6_zero_addr, 0, sizeof(ip6_zero_addr));

    CHECK_NOT_NULL(ta_type = getenv("TE_IUT_TA_TYPE"));
    CHECK_NOT_NULL(host = getenv("TE_IUT"));
    CHECK_NOT_NULL(rcfport_str = getenv("SOCKAPI_TS_NETNS_CALICO_RCFPORT"));
    CHECK_NOT_NULL(ta_ns = getenv("SOCKAPI_TS_NETNS_CALICO_TA"));
    CHECK_NOT_NULL(ta_rpcprovider = getenv("SF_TS_IUT_RPCPROVIDER"));
    CHECK_NOT_NULL(rpcs_name = getenv("SOCKAPI_TS_NETNS_CALICO_RPCS"));
    CHECK_NOT_NULL(ns_name = getenv("SOCKAPI_TS_NETNS_CALICO_NS"));
    CHECK_NOT_NULL(veth1_name =
                        getenv("SOCKAPI_TS_NETNS_CALICO_VETH1_NAME"));
    CHECK_NOT_NULL(veth2_name =
                        getenv("SOCKAPI_TS_NETNS_CALICO_VETH2_NAME"));
    CHECK_NOT_NULL(ip4_local_addr_str =
                          getenv("SOCKAPI_TS_NETNS_CALICO_LOCAL_ADDR"));

    ipv4_only_run_str = getenv("ST_IPV4_ONLY_RUN");
    if (ipv4_only_run_str != NULL &&
        strcasecmp(ipv4_only_run_str, "yes") == 0)
        ipv4_only_run = TRUE;

    rcfport = atoi(rcfport_str);

    memset(&ip4_addr, 0, sizeof(ip4_addr));
    memset(&ip6_addr, 0, sizeof(ip6_addr));

    CHECK_RC(sockts_cns_get_addrs(&ip4_addr, &ip6_addr));

    SA(&ip4_local_addr)->sa_family = AF_INET;
    rc = inet_pton(AF_INET, ip4_local_addr_str,
                   &SIN(&ip4_local_addr)->sin_addr.s_addr);
    if (rc != 1)
    {
        TEST_FAIL("Failed to convert '%s' to IPv4 address",
                  ip4_local_addr_str);
    }

    tapi_sockaddr_clone_exact(SA(&ip4_local_addr), &ip6_local_addr);
    CHECK_RC(te_sockaddr_ip4_to_ip6_mapped(SA(&ip6_local_addr)));

    CHECK_RC(tapi_netns_add(ta, ns_name));
    CHECK_RC(tapi_cfg_base_if_add_veth(ta, veth1_name, veth2_name));
    CHECK_RC(tapi_netns_if_set(ta, ns_name, veth2_name));

    CHECK_RC(tapi_netns_add_ta(host, ns_name, ta_ns, ta_type, rcfport,
                               NULL, NULL, TRUE));
    CHECK_RC(cfg_synchronize("/:", TRUE));
    CHECK_RC(cfg_set_instance_fmt(CVT_STRING, ta_rpcprovider,
                                  "/agent:%s/rpcprovider:", ta_ns));

    CHECK_RC(tapi_cfg_base_if_add_rsrc(ta_ns, veth2_name));
    CHECK_RC(tapi_cfg_base_if_up(ta_ns, veth2_name));

    CHECK_RC(tapi_cfg_base_if_add_net_addr(ta_ns, veth2_name, SA(&ip4_addr),
                                           te_netaddr_get_bitsize(AF_INET),
                                           FALSE, NULL));

    /*
     * TE grabs interface by its name, so it does not allow to grab
     * "lo" interface in two different namespaces by two different
     * TAs simultaneously.
     */
    CHECK_RC(tapi_cfg_base_if_del_rsrc(ta, "lo"));
    CHECK_RC(tapi_cfg_base_if_add_rsrc(ta_ns, "lo"));
    CHECK_RC(tapi_cfg_base_if_up(ta_ns, "lo"));

    CHECK_RC(tapi_cfg_add_route(ta, AF_INET,
                                te_sockaddr_get_netaddr(SA(&ip4_addr)),
                                te_netaddr_get_bitsize(AF_INET),
                                NULL, veth1_name, NULL,
                                0, 0, 0, 0, 0, 0, NULL));

    CHECK_RC(tapi_cfg_add_route(ta_ns, AF_INET,
                                te_sockaddr_get_netaddr(
                                                SA(&ip4_local_addr)),
                                te_netaddr_get_bitsize(AF_INET),
                                NULL, veth2_name, NULL,
                                0, 0, 0, 0, 0, 0, NULL));

    CHECK_RC(tapi_cfg_add_route(ta_ns, AF_INET,
                                &ip4_zero_addr, 0,
                                te_sockaddr_get_netaddr(
                                                SA(&ip4_local_addr)),
                                veth2_name, NULL,
                                0, 0, 0, 0, 0, 0, NULL));

    CHECK_RC(tapi_cfg_base_ipv4_fw(ta, TRUE));

    CHECK_RC(tapi_cfg_sys_set_int(
                            ta, 1, NULL,
                            "net/ipv4/conf:%s/proxy_arp", veth1_name));

    if (!ipv4_only_run)
    {
        CHECK_RC(tapi_cfg_base_if_add_net_addr(
                                        ta_ns, veth2_name, SA(&ip6_addr),
                                        te_netaddr_get_bitsize(AF_INET6),
                                        FALSE, NULL));

        CHECK_RC(tapi_cfg_add_route(ta, AF_INET6,
                                    te_sockaddr_get_netaddr(SA(&ip6_addr)),
                                    te_netaddr_get_bitsize(AF_INET6),
                                    NULL, veth1_name, NULL,
                                    0, 0, 0, 0, 0, 0, NULL));

        CHECK_RC(tapi_cfg_add_route(ta_ns, AF_INET6,
                                    te_sockaddr_get_netaddr(
                                                    SA(&ip6_local_addr)),
                                    te_netaddr_get_bitsize(AF_INET6),
                                    NULL, veth2_name, NULL,
                                    0, 0, 0, 0, 0, 0, NULL));

        CHECK_RC(tapi_cfg_add_route(ta_ns, AF_INET6,
                                    &ip6_zero_addr, 0,
                                    te_sockaddr_get_netaddr(
                                                    SA(&ip6_local_addr)),
                                    veth2_name, NULL,
                                    0, 0, 0, 0, 0, 0, NULL));

        CHECK_RC(tapi_cfg_base_ipv6_fw(ta, TRUE));

        CHECK_RC(tapi_cfg_sys_set_int(
                                ta, 1, NULL,
                                "net/ipv6/conf:%s/proxy_ndp", veth1_name));

        CHECK_RC(tapi_cfg_add_neigh_proxy(ta, veth1_name, SA(&ip6_local_addr),
                                          NULL));
    }

    CHECK_RC(rcf_rpc_server_create(ta_ns, "pco_iut_cns", NULL));

    CFG_WAIT_CHANGES;
}

/* See description in sockapi-ts_cns.h */
void
sockts_cns_cleanup(const char *ta)
{
    const char *test_calico = getenv("SOCKAPI_TS_NETNS_CALICO");
    const char *ns_name = NULL;
    const char *ta_ns = NULL;
    const char *veth1_name = NULL;

    if (test_calico == NULL || strcmp(test_calico, "true") != 0)
        return;

    CHECK_NOT_NULL(ns_name = getenv("SOCKAPI_TS_NETNS_CALICO_NS"));
    CHECK_NOT_NULL(ta_ns = getenv("SOCKAPI_TS_NETNS_CALICO_TA"));
    CHECK_NOT_NULL(veth1_name =
                        getenv("SOCKAPI_TS_NETNS_CALICO_VETH1_NAME"));

    CHECK_RC(rcf_del_ta(ta_ns));
    CHECK_RC(tapi_host_ns_agent_del(ta_ns));
    CHECK_RC(tapi_netns_del(ta, ns_name));
    CHECK_RC(tapi_cfg_base_if_del_veth(ta, veth1_name));

    CHECK_RC(cfg_synchronize_fmt(TRUE, "/agent:%s", ta_ns));
}

/* See description in sockapi-ts_cns.h */
te_errno
sockts_cns_get_addrs(struct sockaddr_storage *ip4_addr,
                     struct sockaddr_storage *ip6_addr)
{
    const char *ip4_addr_str = NULL;
    const char *ip6_addr_str = NULL;
    te_errno    rc = 0;

    ip4_addr_str = getenv("SOCKAPI_TS_NETNS_CALICO_IP4_ADDR");
    ip6_addr_str = getenv("SOCKAPI_TS_NETNS_CALICO_IP6_ADDR");
    if (ip4_addr_str == NULL || ip6_addr_str == NULL)
    {
        ERROR("SOCKAPI_TS_NETNS_CALICO_IP4_ADDR or "
              "SOCKAPI_TS_NETNS_CALICO_IP6_ADDR is not set");
        return TE_RC(TE_TAPI, TE_ENOENT);
    }

    memset(ip4_addr, 0, sizeof(*ip4_addr));
    SA(ip4_addr)->sa_family = AF_INET;
    rc = inet_pton(AF_INET, ip4_addr_str,
                   &SIN(ip4_addr)->sin_addr.s_addr);
    if (rc != 1)
    {
        ERROR("Failed to convert '%s' to IPv4 address",
              ip4_addr_str);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    memset(ip6_addr, 0, sizeof(*ip6_addr));
    SA(ip6_addr)->sa_family = AF_INET6;
    rc = inet_pton(AF_INET6, ip6_addr_str,
                   &SIN6(ip6_addr)->sin6_addr.s6_addr);
    if (rc != 1)
    {
        ERROR("Failed to convert '%s' to IPv6 address",
              ip6_addr_str);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    return 0;
}

/* See description in sockapi-ts_cns.h */
te_errno
sockts_cns_get_rpcs(rcf_rpc_server *pco_iut,
                    te_bool no_reuse_pco,
                    rcf_rpc_server **rpcs)
{
    const char    *reuse_pco = getenv("TE_ENV_REUSE_PCO");
    const char    *ta_name_cns = NULL;
    const char    *rpcs_name_cns = NULL;
    te_bool        get_reuse_pco = FALSE;
    te_errno       rc;

    ta_name_cns = getenv("SOCKAPI_TS_NETNS_CALICO_TA");
    if (ta_name_cns == NULL)
    {
        ERROR("SOCKAPI_TS_NETNS_CALICO_TA is not set");
        return TE_RC(TE_TAPI, TE_ENOENT);
    }
    rpcs_name_cns = getenv("SOCKAPI_TS_NETNS_CALICO_RPCS");
    if (rpcs_name_cns == NULL)
    {
        ERROR("SOCKAPI_TS_NETNS_CALICO_RPCS is not set");
        return TE_RC(TE_TAPI, TE_ENOENT);
    }

    get_reuse_pco = reuse_pco != NULL &&
                    strcasecmp(reuse_pco, "yes") == 0 &&
                    !no_reuse_pco;

    if (get_reuse_pco)
    {
        rc = rcf_rpc_server_get(ta_name_cns, rpcs_name_cns, NULL,
                                RCF_RPC_SERVER_GET_EXISTING |
                                RCF_RPC_SERVER_GET_REUSE,
                                rpcs);
    }
    else
    {
        rc = rcf_rpc_server_get(ta_name_cns, rpcs_name_cns, NULL,
                                RCF_RPC_SERVER_GET_EXISTING,
                                rpcs);
    }

    if (rc != 0)
        return rc;

    (*rpcs)->errno_change_check = pco_iut->errno_change_check;
    if (!te_str_is_null_or_empty(pco_iut->nv_lib))
        return rcf_rpc_setlibname(*rpcs, pco_iut->nv_lib);

    return 0;
}
