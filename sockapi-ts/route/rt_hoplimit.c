/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/**
 * @page route-rt_hoplimit Route hoplimit attribute
 *
 * @objective Check that if route hoplimit attribute is set, then
 *            IPv4 TTL or IPv6 Hop Limit header field is set to its
 *            value in sent packets unless @c IP_TTL (or
 *            @c IPV6_UNICAST_HOPS) specifies another value.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_tst
 *                          - @ref arg_types_env_peer2peer_ipv6
 *                          - @ref arg_types_env_peer2peer_tst_ipv6
 * @param sock_type         Socket type:
 *                          - @c tcp_active
 *                          - @c tcp_passive
 *                          - @c udp
 *                          - @c udp_notconn
 * @param opt_set           If @c TRUE, @c IP_TTL (for IPv4) or
 *                          @c IPV6_UNICAST_HOPS (for IPv6) socket option
 *                          should be set.
 * @param opt_val           Value to set for the checked socket option
 *                          (is taken into account only if @p opt_set is
 *                          @c TRUE):
 *                          - @c -1
 *                          - @c 0
 *                          - @c 139
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "route/rt_hoplimit"

#include "sockapi-test.h"
#include "ts_route.h"
#include "tapi_ip_common.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    sockts_socket_type   sock_type;
    rpc_socket_type      rpc_sock_type;
    te_bool              opt_set;
    int                  opt_val;

    tapi_cfg_rt_params   rt_params;
    cfg_handle           rt_hndl = CFG_HANDLE_INVALID;
    csap_handle_t        csap = CSAP_INVALID_HANDLE;
    int                  iut_s = -1;
    int                  iut_listener = -1;
    int                  tst_s = -1;
    int                  def_val;
    int                  exp_val;
    rpc_sockopt          opt_name;
    int                  route_hoplimit;
    te_bool              setopt_failed = FALSE;
    te_bool              test_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(opt_val);
    TEST_GET_BOOL_PARAM(opt_set);

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    TEST_STEP("Choose @b route_hoplimit value so that it is "
              "some positive number not equal to @p opt_val "
              "and not equal to default TTL (in case of IPv4) "
              "or Hop Limit (in case of IPv6).");

    if (iut_addr->sa_family == AF_INET)
    {
        opt_name = RPC_IP_TTL;
        rc = tapi_cfg_sys_get_int(pco_iut->ta, &def_val,
                                  "net/ipv4/ip_default_ttl");
    }
    else
    {
        opt_name = RPC_IPV6_UNICAST_HOPS;
        rc = tapi_cfg_sys_get_int(pco_iut->ta, &def_val,
                                  "net/ipv6/conf:%s/hop_limit",
                                  iut_if->if_name);
    }
    if (rc != 0)
    {
        ERROR("Failed to get default header field value");
        def_val = -1;
    }
    else
    {
        RING("Default header field value is %d", def_val);
    }

    do {
        route_hoplimit = rand_range(1, 0xff);
    } while (route_hoplimit == def_val || route_hoplimit == opt_val);

    TEST_STEP("Add a route to @p tst_addr on IUT with @b hoplimit "
              "set to @b route_hoplimit.");
    tapi_cfg_rt_params_init(&rt_params);
    rt_params.hoplimit = route_hoplimit;
    rt_params.dst_addr = tst_addr;
    rt_params.prefix = te_netaddr_get_bitsize(tst_addr->sa_family);
    rt_params.dev = iut_if->if_name;
    CHECK_RC(tapi_cfg_add_route2(pco_iut->ta, &rt_params, &rt_hndl));

    CFG_WAIT_CHANGES;

    TEST_STEP("Create a CSAP on Tester to capture packets sent from "
              "IUT.");

    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                        pco_tst->ta, 0, tst_if->if_name,
                        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                        NULL, NULL, tst_addr->sa_family,
                        (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                        TAD_SA2ARGS(tst_addr,
                                    iut_addr),
                        &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Create sockets of type @p sock_type on IUT and Tester.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       rpc_sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       rpc_sock_type, RPC_PROTO_DEF);

    if (opt_set)
    {
        te_bool zero_ip_ttl = (opt_val == 0 && opt_name == RPC_IP_TTL);

        TEST_STEP("If @p opt_set is @c TRUE, set @c IP_TTL (in case of "
                  "IPv4) or @c IPV6_UNICAST_HOPS (in case of IPv6) to "
                  "@p opt_val.");

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_setsockopt_int(pco_iut, iut_s, opt_name, opt_val);
        if (rc < 0)
        {
            if (zero_ip_ttl && RPC_ERRNO(pco_iut) == RPC_EINVAL)
            {
                WARN("Linux does not allow to set IP_TTL to zero");
            }
            else
            {
                ERROR_VERDICT("setsockopt() failed with errno %r",
                              RPC_ERRNO(pco_iut));
            }
            setopt_failed = TRUE;
        }
        else if (zero_ip_ttl)
        {
            RING_VERDICT("Setting IP_TTL to zero was successful");
        }
    }

    TEST_STEP("Establish connection between sockets if required by "
              "@p sock_type.");
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, FALSE, TRUE, NULL,
                      &iut_s, &tst_s, &iut_listener,
                      SOCKTS_SOCK_FUNC_SOCKET);

    TEST_STEP("Send some data from the IUT socket to its peer on Tester. "
              "Check that in all sent packets captured by CSAP Time To "
              "Live field (if IPv4 is checked) or Hop Limit field (if "
              "IPv6 is checked) is set to @b route_hoplimit if "
              "@p opt_set is @c FALSE, or @p opt_val is negative, or "
              "setsockopt() failed before, and is set to @p opt_val "
              "otherwise.");

    if (!opt_set || opt_val < 0 || setopt_failed)
        exp_val = route_hoplimit;
    else
        exp_val = opt_val;

    if (tst_addr->sa_family == AF_INET)
    {
        sockts_send_check_field(pco_iut, iut_s, pco_tst, tst_s,
                                sock_type, tst_addr,
                                "Time To Live",
                                "pdus.1.#ip4.time-to-live.plain",
                                "expected value", exp_val,
                                "", 0,
                                csap, &test_failed,
                                "Sending packets over the route");
    }
    else
    {
        sockts_send_check_field(pco_iut, iut_s, pco_tst, tst_s,
                                sock_type, tst_addr,
                                "Hop Limit",
                                "pdus.1.#ip6.hop-limit.plain",
                                "expected value", exp_val,
                                "", 0,
                                csap, &test_failed,
                                "Sending packets over the route");
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_listener);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                           csap));

    TEST_END;
}
