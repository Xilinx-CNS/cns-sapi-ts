/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Implementation of helper functions for congestion tests.
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#include "sockapi-test.h"
#include "tapi_cfg_qdisc.h"
#include "tapi_cfg_tbf.h"
#include "tapi_cfg_netem.h"
#include "tapi_namespaces.h"
#include "tapi_host_ns.h"
#include "ts_congestion.h"

/* See description in ts_congestion.h */
char *
sockts_ct_param_get(const char *name)
{
    te_errno rc;
    cfg_val_type val_type = CVT_STRING;
    char *val = NULL;

    rc = cfg_get_instance_fmt(&val_type, &val, "/local:/congestion:/%s:", name);
    if (rc != 0)
        return NULL;

    return val;
}

/**
 * Add Linux bridge and add two interfaces to it.
 *
 * @param ta            Test agent.
 * @param br_name       Bridge name.
 * @param first_ifname  Name of the first interface in bridge.
 * @param second_ifname Name of the second interface in bridge.
 */
static void
sockts_ct_br_setup(const char *ta,
                   const char *br_name,
                   const char* first_ifname,
                   const char *second_ifname)
{
    char buf[RCF_MAX_VAL];

    CHECK_RC(tapi_cfg_base_if_add_rsrc(ta, br_name));

    CHECK_RC(cfg_add_instance_fmt(NULL, CFG_VAL(NONE, NULL),
                                  "/agent:%s/bridge:%s", ta, br_name));
    CHECK_RC(tapi_cfg_base_if_up(ta, br_name));

    TE_SPRINTF(buf, "/agent:%s/interface:%s", ta, first_ifname);
    CHECK_RC(cfg_add_instance_fmt(NULL, CFG_VAL(STRING, buf),
                                  "/agent:%s/bridge:%s/port:%s", ta, br_name,
                                  first_ifname));

    TE_SPRINTF(buf, "/agent:%s/interface:%s", ta, second_ifname);
    CHECK_RC(cfg_add_instance_fmt(NULL, CFG_VAL(STRING, buf),
                                  "/agent:%s/bridge:%s/port:%s", ta, br_name,
                                  second_ifname));
}

/**
 * Add 2 pairs of VETHs and 2 Linux bridges.
 * Connect them in the following order:
 * @p ifname - @p ct_btlnck_br_name - @p ct_btlnck_veth1_name -
 * @p ct_btlnck_veth2_name - @p ct_recv_br_name - @p ct_recv_veth1_name -
 * @p ct_recv_veth2_name.
 *
 * @param ta                    Test agent.
 * @param ifname                Interface name.
 * @param ct_btlnck_veth1_name  Name of the first VETH in "bottleneck" pair.
 * @param ct_btlnck_veth2_name  Name of the second VETH in "bottleneck" pair.
 * @param ct_recv_veth1_name    Name of the first VETH in "receiver" pair.
 * @param ct_recv_veth2_name    Name of the second VETH in "receiver" pair.
 * @param ct_btlnck_br_name     Name of the first bridge.
 * @param ct_recv_br_name       Name of the second bridge.
 */
static void
sockts_ct_veths_brs_setup(const char *ta, const char *ifname,
                          const char *ct_btlnck_veth1_name,
                          const char *ct_btlnck_veth2_name,
                          const char *ct_recv_veth1_name,
                          const char *ct_recv_veth2_name,
                          const char *ct_btlnck_br_name,
                          const char *ct_recv_br_name)
{
    CHECK_RC(tapi_cfg_base_if_add_veth(ta, ct_btlnck_veth1_name,
                                       ct_btlnck_veth2_name));
    CHECK_RC(tapi_cfg_base_if_add_veth(ta, ct_recv_veth1_name,
                                       ct_recv_veth2_name));

    sockts_ct_br_setup(ta, ct_btlnck_br_name, ifname, ct_btlnck_veth1_name);
    sockts_ct_br_setup(ta, ct_recv_br_name, ct_btlnck_veth2_name,
                       ct_recv_veth1_name);
}

/**
 * Add namespace on TST host and @p ct_recv_veth2_name interface to it.
 * Allocate IP address from @p net and add it to interface.
 * Start test agent and RPC server in namespace.
 *
 * @param ta                    Test agent on TST.
 * @param net                   Network addresses pool
 * @param ct_recv_veth2_name    Name of the interface to pass to namespace.
 */
static void
sockts_ct_tst_netns_setup(const char *ta, tapi_env_net *net,
                          const char *ct_recv_veth2_name)
{
    const char *host;
    const char *ta_type;
    struct sockaddr *ns_addr = NULL;
    char *ct_ns_name;
    char *ct_ns_agent_name;
    char *ct_ns_agent_rpcprovider;
    char *ct_ns_agent_rcf_port;
    char *ct_ns_pco_name;
    int rcfport = -1;

    CHECK_NOT_NULL(host = getenv("TE_TST1"));
    CHECK_NOT_NULL(ta_type = getenv("TE_TST1_TA_TYPE"));

    CHECK_NOT_NULL(ct_ns_name = sockts_ct_param_get("ns_name"));
    CHECK_NOT_NULL(ct_ns_agent_name = sockts_ct_param_get("ns_agent_name"));
    CHECK_NOT_NULL(ct_ns_agent_rpcprovider =
                        sockts_ct_param_get("ns_agent_rpcprovider"));
    CHECK_NOT_NULL(ct_ns_pco_name = sockts_ct_param_get("ns_pco_name"));
    CHECK_NOT_NULL(ct_ns_agent_rcf_port =
                        sockts_ct_param_get("ns_agent_rcf_port"));
    rcfport = atoi(ct_ns_agent_rcf_port);

    CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &ns_addr, NULL));

    sockts_netns_setup_common(ta, host, ta_type, ct_ns_agent_rpcprovider,
                              CFG_HANDLE_INVALID, ct_recv_veth2_name,
                              ct_ns_name, ct_ns_agent_name, ct_ns_pco_name,
                              rcfport, NULL, &ns_addr, NULL);

    CHECK_RC(tapi_cfg_add_route_simple(ct_ns_agent_name, ns_addr, net->ip4pfx,
                                       NULL, ct_recv_veth2_name));

    free(ns_addr);
    free(ct_ns_name);
    free(ct_ns_agent_name);
    free(ct_ns_agent_rcf_port);
    free(ct_ns_pco_name);
}

/* See description in ts_congestion.h */
void
sockts_ct_tst_net_setup(const char *ta, const char *ifname, tapi_env_net *net)
{
    char *ct_btlnck_veth1_name;
    char *ct_btlnck_veth2_name;
    char *ct_recv_veth1_name;
    char *ct_recv_veth2_name;
    char *ct_recv_br_name;
    char *ct_btlnck_br_name;

    CHECK_NOT_NULL(ct_btlnck_veth1_name =
                        sockts_ct_param_get("bottleneck_first_veth_name"));
    CHECK_NOT_NULL(ct_btlnck_veth2_name =
                        sockts_ct_param_get("bottleneck_second_veth_name"));
    CHECK_NOT_NULL(ct_recv_veth1_name =
                        sockts_ct_param_get("receiver_first_veth_name"));
    CHECK_NOT_NULL(ct_recv_veth2_name =
                        sockts_ct_param_get("receiver_second_veth_name"));
    CHECK_NOT_NULL(ct_recv_br_name =
                        sockts_ct_param_get("receiver_bridge_name"));
    CHECK_NOT_NULL(ct_btlnck_br_name =
                        sockts_ct_param_get("bottleneck_bridge_name"));

    sockts_ct_veths_brs_setup(ta, ifname, ct_btlnck_veth1_name,
                              ct_btlnck_veth2_name, ct_recv_veth1_name,
                              ct_recv_veth2_name, ct_btlnck_br_name,
                              ct_recv_br_name);
    sockts_ct_tst_netns_setup(ta, net, ct_recv_veth2_name);

    free(ct_btlnck_veth1_name);
    free(ct_btlnck_veth2_name);
    free(ct_recv_veth1_name);
    free(ct_recv_veth2_name);
    free(ct_recv_br_name);
    free(ct_btlnck_br_name);
}

/* See description in ts_congestion.h */
void
sockts_ct_tst_net_cleanup(const char *ta)
{
    char *ct_ns_name;
    char *ct_ns_agent_name;
    char *ct_btlnck_br_name;
    char *ct_recv_br_name;
    char *ct_btlnck_veth1_name;
    char *ct_recv_veth1_name;

    CHECK_NOT_NULL(ct_ns_name = sockts_ct_param_get("ns_name"));
    CHECK_NOT_NULL(ct_ns_agent_name = sockts_ct_param_get("ns_agent_name"));
    CHECK_NOT_NULL(ct_btlnck_veth1_name =
                        sockts_ct_param_get("bottleneck_first_veth_name"));
    CHECK_NOT_NULL(ct_recv_veth1_name =
                        sockts_ct_param_get("receiver_first_veth_name"));
    CHECK_NOT_NULL(ct_recv_br_name =
                        sockts_ct_param_get("receiver_bridge_name"));
    CHECK_NOT_NULL(ct_btlnck_br_name =
                        sockts_ct_param_get("bottleneck_bridge_name"));

    CHECK_RC(rcf_del_ta(ct_ns_agent_name));
    CHECK_RC(tapi_host_ns_agent_del(ct_ns_agent_name));
    CHECK_RC(tapi_netns_del(ta, ct_ns_name));

    CHECK_RC(cfg_del_instance_fmt(TRUE, "/agent:%s/bridge:%s", ta,
                                  ct_btlnck_br_name));
    CHECK_RC(cfg_del_instance_fmt(TRUE, "/agent:%s/bridge:%s", ta,
                                  ct_recv_br_name));

    CHECK_RC(tapi_cfg_base_if_del_veth(ta, ct_btlnck_veth1_name));
    CHECK_RC(tapi_cfg_base_if_del_veth(ta, ct_recv_veth1_name));

    CHECK_RC(cfg_synchronize_fmt(TRUE, "/agent:%s", ct_ns_agent_name));

    free(ct_ns_name);
    free(ct_ns_agent_name);
    free(ct_btlnck_br_name);
    free(ct_recv_br_name);
    free(ct_btlnck_veth1_name);
    free(ct_recv_veth1_name);
}

/* See description in ts_congestion.h */
void
sockts_ct_get_ns_rpcs(rcf_rpc_server **rpcs)
{
    char *ct_ns_agent_name;
    char *ct_ns_pco_name;

    CHECK_NOT_NULL(ct_ns_agent_name = sockts_ct_param_get("ns_agent_name"));
    CHECK_NOT_NULL(ct_ns_pco_name = sockts_ct_param_get("ns_pco_name"));

    TEST_GET_RPCS(ct_ns_agent_name, ct_ns_pco_name, *rpcs);

    free(ct_ns_agent_name);
    free(ct_ns_pco_name);
}

/* See description in ts_congestion.h */
void
sockts_ct_set_btlnck_tbf_params(const char *ta, int rate,
                                int burst, int limit)
{
    char *ct_btlnck_veth1_name;

    CHECK_NOT_NULL(ct_btlnck_veth1_name =
                        sockts_ct_param_get("bottleneck_first_veth_name"));

    CHECK_RC(tapi_cfg_qdisc_disable(ta, ct_btlnck_veth1_name));
    CHECK_RC(tapi_cfg_tbf_set_rate(ta, ct_btlnck_veth1_name, rate));
    CHECK_RC(tapi_cfg_tbf_set_bucket(ta, ct_btlnck_veth1_name, burst));
    CHECK_RC(tapi_cfg_tbf_set_limit(ta, ct_btlnck_veth1_name, limit));
    CHECK_RC(tapi_cfg_qdisc_enable(ta, ct_btlnck_veth1_name));

    free(ct_btlnck_veth1_name);
}

/* See description in ts_congestion.h */
void
sockts_ct_set_btlnck_netem_delay(const char *ta, int delay)
{
    char *ct_recv_veth1_name;

    CHECK_NOT_NULL(ct_recv_veth1_name =
                        sockts_ct_param_get("receiver_first_veth_name"));

    CHECK_RC(tapi_cfg_qdisc_disable(ta, ct_recv_veth1_name));
    if (delay != 0)
    {
        CHECK_RC(tapi_cfg_netem_set_delay(ta, ct_recv_veth1_name,
                                          TE_MS2US(delay)));
        CHECK_RC(tapi_cfg_qdisc_enable(ta, ct_recv_veth1_name));
    }

    free(ct_recv_veth1_name);
}

/* See description in ts_congestion.h */
void
sockts_ct_get_ns_veth_net_addr(rcf_rpc_server *pco_ns, tapi_env_net *net,
                               struct sockaddr **ns_addr)
{
    unsigned int n_addrs = 0;
    char *ct_recv_veth2_name = NULL;
    struct sockaddr_storage *ns_addrs = NULL;

    CHECK_NOT_NULL(ct_recv_veth2_name =
                        sockts_ct_param_get("receiver_second_veth_name"));

    CHECK_RC(sockts_get_net_addrs_from_if(pco_ns, ct_recv_veth2_name, net,
                                          AF_INET, &ns_addrs, &n_addrs));
    if (n_addrs != 1)
        TEST_FAIL("Interface inside namespace has more that one address.");

    *ns_addr = (struct sockaddr *)ns_addrs;

    free(ct_recv_veth2_name);
}
