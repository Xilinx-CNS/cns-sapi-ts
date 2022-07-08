/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-rt_many_subnets_via_gw Routing decision in case of many routes to different subnetworks
 *
 * @objective Check that the routing is correctly done in case there are
 *            a set of routes to different subnetworks via different
 *            gateways.
 *
 * @type conformance
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_single_if_variants_with_ipv6
 * @param route_info        Routing information used in the test that keeps
 *                          the following tuple:
 *                          [target/netmask/gateway],
 *                          target  - destination network or host;
 *                          netmask - when adding a network route,
 *                                    the netmask to be used;
 *                          gateway - gateway address for the route;
 * @param dst_addr_str      Destination address used in the test to send
 *                          data to
 * @param exp_gw_addr_str   Expected gateway address used as the next-hop
 *                          for the datagram sent in the test to
 *                          @p dst_addr_str
 * @param rt_sock_type      Type of sockets used in the test:
 *                          - @c tcp_active
 *                          - @c tcp_passive
 *                          - @c udp
 *                          - @c udp_connect
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_many_subnets_via_gw"

#include "te_config.h"

#include <net/ethernet.h>
#include <ctype.h>

#include "ts_route.h"
#include "tapi_eth.h"
#include "tapi_arp.h"
#include "tapi_cfg.h"
#include "tapi_ip_common.h"

/** Test private routing info data structure used in the test */
typedef struct rt_info {
    struct sockaddr_storage tgt; /**< Target address */
    int                     prefix; /**< Prefix for the target address */
    struct sockaddr_storage gw; /**< Gateway address */
    cfg_handle              addr_hndl; /**< Handle of the gateway address */
    cfg_handle              dr_hndl; /**< Handle of the direct route */
    cfg_handle              ir_hndl; /**< Handle of the indirect route */

    char                    tst_macvlan[IF_NAMESIZE]; /** Name of MACVLAN
                                                          interface on
                                                          Tester */
    te_bool                 macvlan_added;            /** Whether MACVLAN
                                                          interface was
                                                          added. */
} rt_info_t;

/* Forward declaration */
static int test_parse_rt_info_param(int af, const char *rt_info_str,
                                    rt_info_t **rt_info, int *n);

/** Data passed to CSAP callback. */
typedef struct test_csap_data {
    te_bool        failed;       /**< Will be set to TRUE if processing
                                      failed */
    te_bool        unexp_mac;    /**< Will be set to TRUE if unexpected
                                      destination MAC address was
                                      encountered */
    const uint8_t *exp_mac;      /**< Expected destination MAC address */
} test_csap_data;

/**
 * CSAP callback to process packets captured on Tester.
 *
 * @param pkt         Captured packet.
 * @param user_data   Pointer to test_csap_data structure.
 */
static void
csap_cb(asn_value *pkt, void *user_data)
{
    test_csap_data *test_data = (test_csap_data *)user_data;

    uint8_t     dst_mac[ETHER_ADDR_LEN] = { 0, };
    size_t      len = sizeof(dst_mac);
    int         rc;

    if (test_data->failed)
        goto cleanup;

    rc = asn_read_value_field(pkt, dst_mac, &len,
                              "pdus.1.#eth.dst-addr.#plain");
    if (rc != 0 || len != sizeof(dst_mac))
    {
        ERROR("Failed to obtain destination MAC address");
        test_data->failed = TRUE;
        goto cleanup;
    }

    if (memcmp(dst_mac, test_data->exp_mac, ETHER_ADDR_LEN) != 0)
    {
        test_data->unexp_mac = TRUE;
        ERROR("Packet was sent to " TE_PRINTF_MAC_FMT " instead of "
              TE_PRINTF_MAC_FMT,
              TE_PRINTF_MAC_VAL(dst_mac),
              TE_PRINTF_MAC_VAL(test_data->exp_mac));
    }

cleanup:

    asn_free_value(pkt);
}

int
main(int argc, char **argv)
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    tapi_env_net              *net;
    unsigned int               net_pfx = 0;

    const struct sockaddr    *alien_addr;
    const struct sockaddr    *iut_addr;

    struct sockaddr_storage  dst_addr;
    struct sockaddr_storage  exp_gw_addr;

    const char            *route_info;
    const char            *dst_addr_str;
    const char            *exp_gw_addr_str;

    struct in6_addr        bin_addr;
    cfg_handle             dst_hndl = CFG_HANDLE_INVALID;

    size_t                 mac_len;
    uint8_t                cur_mac[ETHER_ADDR_LEN] = { 0, };
    uint8_t                exp_mac[ETHER_ADDR_LEN] = { 0, };
    te_bool                got_exp_mac = FALSE;
    const char            *cur_tst_if_name = NULL;

    test_csap_data            test_data;
    tapi_tad_trrecv_cb_data   cb_data;
    unsigned int              pkts_num = 0;
    te_bool                   test_failed = FALSE;

    rt_info_t             *rt_tbl = NULL;
    int                    n = 0;
    int                    i;

    int                    iut_s = -1;
    int                    iut_s_listener = -1;
    int                    tst_s = -1;
    int                    tst_s_listener = -1;

    int                    af;
    int                    route_prefix;
    csap_handle_t          tst_csap = CSAP_INVALID_HANDLE;

    rpc_socket_domain     domain;
    rpc_socket_type       sock_type;
    sockts_socket_type    rt_sock_type;

    sockts_if_monitor   iut_if_monitor = SOCKTS_IF_MONITOR_INIT;

    TEST_START;

    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_NET(net);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, alien_addr);

    TEST_GET_STRING_PARAM(dst_addr_str);
    TEST_GET_STRING_PARAM(exp_gw_addr_str);

    TEST_GET_STRING_PARAM(route_info);

    sock_type = sock_type_sockts2rpc(rt_sock_type);
    GET_DOMAIN_AF_PREFIX(iut_addr, domain, af, route_prefix);

    memset(&dst_addr, 0, sizeof(dst_addr));
    memset(&exp_gw_addr, 0, sizeof(exp_gw_addr));
    dst_addr.ss_family = af;
    exp_gw_addr.ss_family = af;

    TEST_STEP("Parse @p dst_addr_str to @b dst_addr.");

    if (inet_pton(af, dst_addr_str, &bin_addr) <= 0)
    {
        TEST_FAIL("IP address passed in 'dst_addr_str' parameter "
                  "cannot be converted into binary representation");
    }
    te_sockaddr_set_netaddr(SA(&dst_addr), &bin_addr);
    te_sockaddr_set_port(SA(&dst_addr), te_sockaddr_get_port(alien_addr));

    TEST_STEP("Parse @p exp_gw_addr_str to @b exp_gw_addr.");

    if (inet_pton(af, exp_gw_addr_str, &bin_addr) <= 0)
    {
        TEST_FAIL("IP address passed in 'exp_gw_addr_str' parameter "
                  "cannot be converted into binary representation");
    }
    te_sockaddr_set_netaddr(SA(&exp_gw_addr), &bin_addr);
    te_sockaddr_set_port(SA(&exp_gw_addr), 0);

    CHECK_RC(test_parse_rt_info_param(af, route_info, &rt_tbl, &n));

    net_pfx = (af == AF_INET ? net->ip4pfx : net->ip6pfx);

    TEST_STEP("Add @b dst_addr on @p tst_if interface.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(
                 pco_tst->ta, tst_if->if_name,
                 SA(&dst_addr), net_pfx, FALSE, &dst_hndl));

    CHECK_RC(sockts_rt_fix_macvlan_conf(pco_tst->ta, tst_if->if_name));

    mac_len = sizeof(cur_mac);
    CHECK_RC(tapi_cfg_get_hwaddr(pco_tst->ta, tst_if->if_name,
                                 cur_mac, &mac_len));

    RING("MAC address of the main Tester interface (%s) is "
         TE_PRINTF_MAC_FMT, tst_if->if_name,
         TE_PRINTF_MAC_VAL(cur_mac));

    TEST_STEP("For each route description in @p route_info parameter:");
    for (i = 0; i < n; i++)
    {
        TEST_SUBSTEP("Add a MAC VLAN interface on top of @p tst_if, "
                     "and set @b cur_tst_if_name to the name of the "
                     "added MAC VLAN.");

        TE_SPRINTF(rt_tbl[i].tst_macvlan, "te_macvlan_%d", i);
        CHECK_RC(tapi_cfg_base_if_add_macvlan(pco_tst->ta,
                                              tst_if->if_name,
                                              rt_tbl[i].tst_macvlan,
                                              NULL));
        rt_tbl[i].macvlan_added = TRUE;
        CHECK_RC(sockts_rt_fix_macvlan_conf(pco_tst->ta,
                                            rt_tbl[i].tst_macvlan));
        cur_tst_if_name = rt_tbl[i].tst_macvlan;

        TEST_SUBSTEP("Add the gateway address from the current route "
                     "description to @b cur_tst_if_name.");
        CHECK_RC(tapi_cfg_base_if_add_net_addr(
                     pco_tst->ta, cur_tst_if_name,
                     SA(&(rt_tbl[i].gw)), net_pfx, FALSE,
                     &(rt_tbl[i].addr_hndl)));

        TEST_SUBSTEP("On IUT add a route to the gateway address via "
                     "@p iut_if interface.");
        if (tapi_cfg_add_route(pco_iut->ta, af,
                te_sockaddr_get_netaddr(SA(&(rt_tbl[i].gw))), route_prefix,
                NULL, iut_if->if_name, NULL,
                0, 0, 0, 0, 0, 0, &(rt_tbl[i].dr_hndl)) != 0)
        {
            TEST_FAIL("Cannot add direct route on IUT");
        }

        TEST_SUBSTEP("On IUT add an indirect route to @b dst_addr via "
                     "the gateway, using prefix from the current route "
                     "description.");
        if (tapi_cfg_add_route(pco_iut->ta, af,
                te_sockaddr_get_netaddr(SA(&(rt_tbl[i].tgt))),
                rt_tbl[i].prefix,
                te_sockaddr_get_netaddr(SA(&(rt_tbl[i].gw))), NULL, NULL,
                0, 0, 0, 0, 0, 0, &(rt_tbl[i].ir_hndl)) != 0)
        {
            TEST_FAIL("Cannot add indirect route on IUT");
        }

        TEST_SUBSTEP("If current gateway matches @b exp_gw_addr, save "
                     "MAC address of @b cur_tst_if_name in @b exp_mac.");

        mac_len = sizeof(cur_mac);
        CHECK_RC(tapi_cfg_get_hwaddr(pco_tst->ta, cur_tst_if_name,
                                     cur_mac, &mac_len));

        RING("MAC address of %d (%s) Tester interface is "
             TE_PRINTF_MAC_FMT, i, cur_tst_if_name,
             TE_PRINTF_MAC_VAL(cur_mac));

        if (tapi_sockaddr_cmp(SA(&exp_gw_addr), SA(&rt_tbl[i].gw)) == 0)
        {
            memcpy(exp_mac, cur_mac, sizeof(cur_mac));
            got_exp_mac = TRUE;
        }
    }

    if (!got_exp_mac)
    {
        TEST_FAIL("Expected MAC address was not obtained");
    }
    else
    {
        RING("Packets from IUT should go to " TE_PRINTF_MAC_FMT,
             TE_PRINTF_MAC_VAL(exp_mac));
    }

    TEST_STEP("Delete neighbor table entries on @p iut_if interface.");
    tapi_cfg_del_neigh_dynamic(pco_iut->ta, iut_if->if_name);
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a CSAP on Tester to capture packets sent from IUT "
              "to @b dst_addr.");

    CHECK_RC(tapi_ip_eth_csap_create(
               pco_tst->ta, 0, tst_if->if_name,
               TAD_ETH_RECV_DEF, NULL, NULL, af,
               te_sockaddr_get_netaddr(SA(&dst_addr)),
               te_sockaddr_get_netaddr(iut_addr),
               (sock_type_sockts2rpc(rt_sock_type) == RPC_SOCK_STREAM ?
                          IPPROTO_TCP : IPPROTO_UDP),
               &tst_csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, tst_csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Configure traffic monitor on IUT to check whether traffic "
              "is accelerated.");

    CHECK_RC(sockts_if_monitor_init(&iut_if_monitor,
                                    pco_iut->ta, iut_if->if_name,
                                    af, sock_type,
                                    NULL, SA(&dst_addr),
                                    FALSE, TRUE));

    TEST_STEP("Create a pair of sockets on IUT and Tester according "
              "to @p rt_sock_type, send data from IUT to @b dst_addr.");

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    if ((tst_s = rpc_create_and_bind_socket(pco_tst,
                    sock_type, RPC_PROTO_DEF,
                    FALSE, TRUE, SA(&dst_addr))) < 0)
    {
        TEST_FAIL("Cannot create and bind 'tst_s' socket");
    }

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_bind(pco_iut, iut_s, iut_addr);
        if (rt_sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        {
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_iut, iut_s, SA(&dst_addr));
            tst_s_listener = tst_s;
            tst_s = rpc_accept(pco_tst, tst_s_listener, NULL, NULL);
        }
        else
        {
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_tst, tst_s, iut_addr);
            iut_s_listener = iut_s;
            iut_s = rpc_accept(pco_iut, iut_s_listener, NULL, NULL);
        }
    }
    else if (rt_sock_type == SOCKTS_SOCK_UDP)
    {
        rpc_connect(pco_iut, iut_s, SA(&dst_addr));
    }

    CHECK_SOCKTS_TEST_SEND_RC(
          sockts_rt_test_send(rt_sock_type, pco_iut, iut_s,
                              pco_tst, tst_s,
                              SA(&dst_addr), NULL,
                              TRUE, "Sending data from IUT"));

    TEST_STEP("Check that all the packets from IUT were sent to "
              "@b exp_mac MAC address.");

    memset(&test_data, 0, sizeof(test_data));
    test_data.exp_mac = exp_mac;
    cb_data.callback = &csap_cb;
    cb_data.user_data = &test_data;

    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, tst_csap,
                                 &cb_data, &pkts_num));
    if (pkts_num == 0)
        TEST_VERDICT("CSAP did not catch packets on Tester");
    if (test_data.unexp_mac)
    {
        test_failed = TRUE;
        ERROR_VERDICT("Packet(s) was sent to unexpected MAC");
    }
    if (test_data.failed)
        TEST_FAIL("Failed to parse all the captured packets");

    TEST_STEP("Check that traffic over IUT was or was not accelerated "
              "as expected.");
    CHECK_IF_ACCELERATED(&env, &iut_if_monitor, "");

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (tst_csap != CSAP_INVALID_HANDLE)
        tapi_tad_csap_destroy(pco_tst->ta, 0, tst_csap);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listener);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listener);

    for (i = n - 1; i >= 0; i--)
    {
        tapi_cfg_del_route(&(rt_tbl[i].ir_hndl));
        tapi_cfg_del_route(&(rt_tbl[i].dr_hndl));

        if (rt_tbl[i].addr_hndl != CFG_HANDLE_INVALID)
            cfg_del_instance(rt_tbl[i].addr_hndl, FALSE);

        if (rt_tbl[i].macvlan_added)
        {
            CLEANUP_CHECK_RC(tapi_cfg_base_if_del_macvlan(
                                      pco_tst->ta, tst_if->if_name,
                                      rt_tbl[i].tst_macvlan));
        }
    }

    if (dst_hndl != CFG_HANDLE_INVALID)
        cfg_del_instance(dst_hndl, FALSE);

    CLEANUP_CHECK_RC(
        sockts_if_monitor_destroy(&iut_if_monitor));

    TEST_END;
}

/**
 * Parses route infor parameter, which is in format
 *   [target/prefix/gateway]*
 * target  - destination network or host;
 * prefix  - when adding a network route, the prefix to be used;
 * gateway - gateway address for the route;
 *
 * @param af           Address family of the route
 * @param rt_info_str  Routing info in string representation
 * @param rt_info      Pointer to routing info table (OUT)
 * @param n            The number of elements in routing info table (OUT)
 *
 * @return Status code (0 on success, errno on failure)
 */
static int
test_parse_rt_info_param(int af, const char *rt_info_str,
                         rt_info_t **rt_info, int *n)
{
    rt_info_t *rt = NULL;
    rt_info_t *tmp_rt;
    int        i = 0;
    char      *ptr;
    char      *buf;
    char      *buf_start = NULL;
    char      *end_ptr;
    int        str_len;

    struct in6_addr bin_addr;

#define RET_WITH_ERR(err_, fmt_...) \
    do {                            \
        free(rt);                   \
        free(buf_start);            \
        ERROR(fmt_);                \
        return err_;                \
    } while (0)

    if (rt_info_str == NULL || rt_info == NULL || n == NULL)
        RET_WITH_ERR(EINVAL, "'rt_info_str', 'rt_info', 'n' should not "
                     "be NULL");

    str_len = strlen(rt_info_str);

    if ((buf_start = buf = strdup(rt_info_str)) == NULL)
        RET_WITH_ERR(ENOMEM, "Cannot allocate memory under "
                     "copy of 'rt_info_str' string");

    while (*buf != '\0')
    {
        /* Skip spaces */
        while (isspace(*buf))
            buf++;

        if (*buf == '\0')
            break;

        if ((ptr = strchr(buf, '/')) == NULL)
        {
            RET_WITH_ERR(EINVAL, "Incorrect format in %s value starting "
                         "with %s", rt_info_str, buf);
        }
        *ptr = '\0';

        tmp_rt = (rt_info_t *)realloc(rt, sizeof(rt_info_t) * (++i));
        if (tmp_rt == NULL)
            RET_WITH_ERR(ENOMEM, "Cannot allocate memory under "
                         "%d elements of type rt_info_t", i);
        rt = tmp_rt;

        rt[i - 1].addr_hndl = CFG_HANDLE_INVALID;
        rt[i - 1].dr_hndl = CFG_HANDLE_INVALID;
        rt[i - 1].ir_hndl = CFG_HANDLE_INVALID;
        rt[i - 1].tst_macvlan[0] = '\0';
        rt[i - 1].macvlan_added = FALSE;

        /* Process target address */
        rt[i - 1].tgt.ss_family = af;
        if (inet_pton(af, buf, &bin_addr) <= 0)
        {
            RET_WITH_ERR(EINVAL, "Cannot convert %s address into binary "
                         "representation", buf);
        }
        te_sockaddr_set_netaddr(SA(&(rt[i - 1].tgt)), &bin_addr);
        te_sockaddr_set_port(SA(&(rt[i - 1].tgt)), 0);
        buf = ptr + 1;

        if ((ptr = strchr(buf, '/')) == NULL)
        {
            RET_WITH_ERR(EINVAL, "Incorrect format in %s value starting "
                         "with %s", rt_info_str, buf);
        }
        *ptr = '\0';
        if ((rt[i - 1].prefix = strtol(buf, &end_ptr, 10),
             end_ptr == buf || *end_ptr != '\0'))
        {
            RET_WITH_ERR(EINVAL, "Incorrect format of prefix in %s "
                         "starting with %s", rt_info_str, buf);
        }
        buf = ptr = ptr + 1;

        while (!isspace(*ptr) && *ptr != '\0')
            ptr++;

        *ptr = '\0';

        /* Process gateway address */
        rt[i - 1].gw.ss_family = af;
        if (inet_pton(af, buf, &bin_addr) <= 0)
        {
            RET_WITH_ERR(EINVAL, "Cannot convert %s address into binary "
                         "representation", buf);
        }
        te_sockaddr_set_netaddr(SA(&(rt[i - 1].gw)), &bin_addr);
        te_sockaddr_set_port(SA(&(rt[i - 1].gw)), 0);
        buf = ptr;

        if (buf_start + str_len != ptr)
        {
            /* Shift ptr if we are not in the end of the string */
            buf++;
        }
    }
    free(buf_start);

    if (rt == NULL)
    {
        ERROR("There is no entry in configuration string");
        return TE_EFAULT;
    }

    *rt_info = rt;
    *n = i;

    return 0;
}
