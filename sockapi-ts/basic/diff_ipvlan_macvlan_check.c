/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2023 Advanced Micro Devices, Inc. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-diff_vlan_check_id Check that received packets have correct destination IP/MAC address
 *
 * @objective The test should check that IP VLAN/MAC VLAN interface receives
 *            packets with correct destination IP/MAC, and check that the
 *            interface does not receive packets with a wrong destination IP.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 * @param use_netns     Whether to create netns and add IP VLAN/MAC VLAN
 *                      interface to it:
 *                      - @c FALSE
 *                      - @c TRUE
 * @param use_macvlan   Whether to create MAC VLAN (or IP VLAN) interface:
 *                      - @c FALSE
 *                      - @c TRUE
 *
 * @par Scenario:
 *
 * @author Boris Shleyfman <bshleyfman@oktet.co.il>
 */

#define TE_TEST_NAME  "basic/diff_ipvlan_macvlan_check"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "sockapi-ts.h"
#include "sockapi-ts_net_conns.h"
#include "vlan_common.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_udp.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_sockaddr.h"
#include "ndn.h"

/* Size of buffer for ASN template */
#define BUFFER_SIZE          1024 * 16
/** Number of datagrams to send */
#define PKT_NUM              3
/* Length of data in each datagram, in bytes */
#define PAYLOAD_LEN          100
/* First IP VLAN/MAC VLAN ID */
#define VLAN1                1
/* Second IP VLAN/MAC VLAN ID */
#define VLAN2                2

/* Name of the created namespace */
#define TEST_NETNS "aux_netns"
/* Name of the created TA */
#define TEST_NETNS_TA "Agt_aux_netns"
/* Name of the created RPC server */
#define TEST_NETNS_RPCS "pco_iut_aux_netns"

/**
 * Remove MAC VLAN or IP VLAN interface in a cleanup part of test.
 *
 * @param _pco          PCO.
 * @param _ifname       Name of master interface on PCO.
 * @param _vlan_ifname  Name of MAC VLAN/IP VLAN interface to be removed.
 * @param _macvlan      If @c TRUE, remove MAC VLAN interface,
                        otherwise IP VLAN interface.
 * @param _created      Whether MAC VLAN/IP VLAN interface was created
                        successfully or not.
 */
#define CLEANUP_REMOVE_MACVLAN_OR_IPVLAN(_pco, _ifname, _vlan_ifname,     \
                                         _macvlan, _created)              \
    do {                                                                  \
        if (_created)                                                     \
        {                                                                 \
            RING("Remove %svlan interface %s on %s interface %s",         \
                 _macvlan ? "mac" : "ip", _vlan_ifname, #_pco, _ifname);  \
            if (_macvlan)                                                 \
            {                                                             \
                CLEANUP_CHECK_RC(                                         \
                    tapi_cfg_base_if_del_macvlan(_pco->ta, _ifname,       \
                                                 _vlan_ifname));          \
            }                                                             \
            else                                                          \
            {                                                             \
                CLEANUP_CHECK_RC(                                         \
                    tapi_cfg_base_if_del_ipvlan(_pco->ta, _ifname,        \
                                                _vlan_ifname));           \
            }                                                             \
        }                                                                 \
    } while (0)

/**
 * Create a new MAC VLAN or IP VLAN interface on IUT and assign an address
 * from a given network to it.
 *
 * @param pco_iut             RPC server on IUT
 * @param iut_if              Base network interface on IUT
 * @param net_handle          Configurator handle of network
 * @param prefix              Network prefix length of IP address
 * @param macvlan             If @c TRUE, create MAC VLAN interface,
                              otherwise IP VLAN interface
 * @param use_netns           Whether the new interface should work inside
 *                            a new net namespace
 * @param if_id               ID to be used in interface name
                              to make it unique
 * @param vlan_if_name        Location for the name of new MAC VLAN/IP VLAN
                              interface
 * @param vlan_addr           Location for the address allocated for the
                              new interface
 * @param vlan_addr_handle    Location for the Configurator handle of
                              the address allocated for the new interface
 * @param vlan_if_configured  Location for boolean value: whether new
                              interface is configured successfully
 */
static void
create_configure_macvlan_or_ipvlan(rcf_rpc_server *pco_iut,
                                   const struct if_nameindex *iut_if,
                                   cfg_handle net_handle,
                                   unsigned int prefix,
                                   te_bool macvlan, te_bool use_netns,
                                   int if_id, char **vlan_if_name,
                                   struct sockaddr **vlan_addr,
                                   cfg_handle *vlan_addr_handle,
                                   te_bool *vlan_if_configured)
{
    te_string if_name = TE_STRING_INIT;
    *vlan_if_configured = FALSE;

    CHECK_RC(te_string_append(&if_name, "%svlan_%d",
                              (macvlan ? "mac" : "ip"), if_id));
    *vlan_if_name = if_name.ptr;
    if (macvlan)
    {
        CHECK_RC(tapi_cfg_base_if_add_macvlan(pco_iut->ta, iut_if->if_name,
                                              *vlan_if_name, NULL));
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 2, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      *vlan_if_name));
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, use_netns ? 0 : 1, NULL,
                                      "net/ipv4/conf:%s/arp_ignore",
                                      *vlan_if_name));

    }
    else
    {
        const char *ipvlan_mode = getenv("SOCKAPI_TS_IPVLAN_MODE");
        const char *ipvlan_flag = getenv("SOCKAPI_TS_IPVLAN_FLAG");

        if (ipvlan_mode == NULL)
            ipvlan_mode = TAPI_CFG_IPVLAN_MODE_L2;
        if (ipvlan_flag == NULL)
            ipvlan_flag = TAPI_CFG_IPVLAN_FLAG_PRIVATE;

        CHECK_RC(tapi_cfg_base_if_add_ipvlan(pco_iut->ta, iut_if->if_name,
                                             *vlan_if_name, ipvlan_mode,
                                             ipvlan_flag));
    }

    *vlan_if_configured = TRUE;
    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, vlan_addr_handle,
                                     vlan_addr));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, *vlan_if_name,
                                           *vlan_addr, prefix, TRUE, NULL));
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, *vlan_if_name));
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *tst_addr = NULL;
    te_bool                      use_netns;
    te_bool                      use_macvlan;

    cfg_handle             vlan_net_handle = CFG_HANDLE_INVALID;
    cfg_handle             iut_vlan1_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle             iut_vlan2_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle             tst_new_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle             tst_new_addr_handle2 = CFG_HANDLE_INVALID;
    struct sockaddr       *tst_new_addr = NULL;
    cfg_handle             netns_vlan1_addr_handle = CFG_HANDLE_INVALID;
    rcf_rpc_server        *rpcs_ns = NULL;

    int                    iut_s = -1;
    int                    iut_if_rp_filter = -1;
    int                    iut_if_arp_ignore = -1;
    int                    num = -1;

    rcf_rpc_server        *rpcs_recv;
    struct sockaddr       *send_addr;
    struct sockaddr        bind_addr;

    te_bool                iut_vlan1_configured = FALSE;
    te_bool                iut_vlan2_configured = FALSE;

    struct sockaddr       *iut_vlan1_addr = NULL;
    struct sockaddr       *iut_vlan2_addr = NULL;
    struct sockaddr       *netns_vlan1_addr = NULL;

    uint8_t                mac_iut[ETHER_ADDR_LEN];
    uint8_t                mac_tst[ETHER_ADDR_LEN];
    uint8_t                mac_vlan1[ETHER_ADDR_LEN];
    uint8_t                mac_vlan2[ETHER_ADDR_LEN];

    char                   oid[RCF_MAX_ID];
    char                  *net_oid = NULL;
    char                  *iut_vlan1_if_name = NULL;
    char                  *iut_vlan2_if_name = NULL;
    cfg_val_type           val_type;
    unsigned int           net_prefix;

    csap_handle_t          csap = CSAP_INVALID_HANDLE;
    int                    sid = -1;
    asn_value             *pkt = NULL;

    char                   buf[BUFFER_SIZE];
    char                   recv_buf[BUFFER_SIZE];

    struct sockaddr       *destination_addrs[] = {send_addr, iut_vlan2_addr,
                                                  iut_addr};
    uint8_t               *destination_macs[] = {mac_vlan1, mac_vlan2,
                                                 mac_iut};
    uint8_t               *mac;

    int                    rcv;
    unsigned int           i;
    unsigned int           j;

    te_errno               errno;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(use_netns);
    TEST_GET_BOOL_PARAM(use_macvlan);

    TEST_STEP("Create two IP VLAN/MAC VLAN interfaces on IUT; allocate IP "
              "addresses for them from a new subnet.");
    CHECK_RC(tapi_cfg_alloc_ip4_net(&vlan_net_handle));
    CHECK_RC(cfg_get_oid_str(vlan_net_handle, &net_oid));
    val_type = CVT_INTEGER;
    CHECK_RC(cfg_get_instance_fmt(&val_type, &net_prefix, "%s/prefix:",
                                  net_oid));
    create_configure_macvlan_or_ipvlan(pco_iut, iut_if, vlan_net_handle,
                                       net_prefix, use_macvlan, use_netns,
                                       VLAN1, &iut_vlan1_if_name,
                                       &iut_vlan1_addr,
                                       &iut_vlan1_addr_handle,
                                       &iut_vlan1_configured);
    create_configure_macvlan_or_ipvlan(pco_iut, iut_if, vlan_net_handle,
                                       net_prefix, use_macvlan, FALSE,
                                       VLAN2, &iut_vlan2_if_name,
                                       &iut_vlan2_addr,
                                       &iut_vlan2_addr_handle,
                                       &iut_vlan2_configured);
    /* This is needed for packets to reach the VLAN interface */
    if (use_macvlan)
    {
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 2, &iut_if_rp_filter,
                                      "net/ipv4/conf:%s/rp_filter",
                                      iut_if->if_name));
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 1, &iut_if_arp_ignore,
                                      "net/ipv4/conf:%s/arp_ignore",
                                      iut_if->if_name));
    }

    TEST_STEP("Allocate an address for the interface on TST from the same "
              "subnet.");
    CHECK_RC(tapi_cfg_alloc_net_addr(vlan_net_handle, &tst_new_addr_handle,
                                     &tst_new_addr));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           tst_new_addr, net_prefix, TRUE,
                                           &tst_new_addr_handle2));
    TAPI_SET_NEW_PORT(pco_tst, tst_new_addr);
    /*
     * ARP entry with another MAC may survive from the previous test run, so it
     * should be removed.
     */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      iut_vlan1_addr));
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      iut_vlan2_addr));
    CFG_WAIT_CHANGES;

    if (!use_netns)
    {
        TEST_STEP("If not @p use_netns: create a socket on IUT and set "
                  "socket option @c SO_BINDTODEVICE to the first IP VLAN/MAC "
                  "VLAN interface's name.");
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        errno = rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                                   iut_vlan1_if_name,
                                   (strlen(iut_vlan1_if_name) + 1));
        if (errno != 0)
        {
            TEST_VERDICT("setsockopt(SOL_SOCKET, SO_BINDTODEVICE) failed "
                         "with errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        rpcs_recv = pco_iut;
        send_addr = iut_vlan1_addr;
    }
    else
    {
        TEST_STEP("If @p use_netns: create a net namespace, add the "
                  "first IP VLAN/MAC VLAN interface there, and create "
                  "socket on RPC server inside netns.");
        sockts_iut_netns_setup(pco_iut, vlan_net_handle, iut_vlan1_if_name,
                               TEST_NETNS, TEST_NETNS_TA, TEST_NETNS_RPCS,
                               &rpcs_ns, &netns_vlan1_addr,
                               &netns_vlan1_addr_handle);
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                          netns_vlan1_addr));
        iut_s = rpc_socket(rpcs_ns, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpcs_recv = rpcs_ns;
        send_addr = netns_vlan1_addr;
        /*
         * There is a problem on some systems: packets can be seen on
         * NIC but socket doesn't receive them. To handle this, the value
         * of rp_filter should be changed. Value 2 doesn't work here well,
         * so 0 should be used.
         */
        CHECK_RC(tapi_cfg_sys_set_int(rpcs_ns->ta, 0, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      iut_vlan1_if_name));
    }

    TEST_STEP("Bind the socket to wildcard address and some new port.");
    memcpy(&bind_addr, send_addr, te_sockaddr_get_size(send_addr));
    te_sockaddr_set_wildcard(SA(&bind_addr));
    TAPI_SET_NEW_PORT(pco_iut, &bind_addr);
    CHECK_RC(rpc_bind(rpcs_recv, iut_s, &bind_addr));

    TEST_STEP("Get MAC addresses of the original interfaces on IUT and "
              "TST, and MAC addresses of IP VLAN/MAC VLAN interfaces.");
    TE_SPRINTF(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_FAIL("Failed to get MAC address of IUT interface");

    TE_SPRINTF(oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_tst) != 0)
        TEST_FAIL("Failed to get MAC address of TST interface");

    TE_SPRINTF(oid, "/agent:%s/interface:%s",
               use_netns ? TEST_NETNS_TA : pco_iut->ta, iut_vlan1_if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_vlan1) != 0)
        TEST_FAIL("Failed to get MAC address of the first VLAN interface");

    TE_SPRINTF(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_vlan2_if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_vlan2) != 0)
        TEST_FAIL("Failed to get MAC address of the second VLAN interface");

    TEST_STEP("Create CSAP to send packets from TST to the first IUT "
              "VLAN interface.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));
    CHECK_RC(tapi_udp_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_tst, mac_vlan1,
                                          SIN(tst_new_addr)->sin_addr.s_addr,
                                          SIN(send_addr)->sin_addr.s_addr,
                                          SIN(tst_new_addr)->sin_port,
                                          te_sockaddr_get_port(&bind_addr),
                                          &csap));

    TEST_STEP("Using CSAP, send @c PKT_NUM packets with IP address (in case IP "
              "VLAN) or MAC address (in case MAC VLAN):\n"
              "1) of the first IP VLAN/MAC VLAN interface,\n"
              "2) of another IP VLAN/MAC VLAN interface,\n"
              "3) of the parent interface on IUT.\n"
              "In case MAC VLAN always use IP address of the first MAC VLAN "
              "interface.");
    if (use_macvlan)
    {
        destination_macs[0] = mac_vlan1;
        destination_macs[1] = mac_vlan2;
        destination_macs[2] = mac_iut;
    }
    else
    {
        destination_addrs[0] = send_addr;
        destination_addrs[1] = iut_vlan2_addr;
        destination_addrs[2] = iut_addr;
    }

    for (i = 0; i < (unsigned int)TE_ARRAY_LEN(destination_addrs); i++)
    {
        if (use_macvlan)
        {
            mac = destination_macs[i];
            RING("Send %u packets to MAC address %02X %02X %02X %02X %02X "
                 "%02X.", PKT_NUM, mac[0], mac[1], mac[2], mac[3], mac[4],
                 mac[5]);
            TE_SPRINTF(buf,
                       "{ arg-sets { simple-for:{begin 1,end %u} }, "
                       "  pdus  { udp:{},                           "
                       "          ip4:{},                           "
                       "          eth:{                             "
                       "                dst-addr plain:'%02X %02X   "
                       "%02X %02X %02X %02X'H                       "
                       "              }                             "
                       "        },                                  "
                       "  payload length:%u }                       ",
                       PKT_NUM, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                       PAYLOAD_LEN);
        }
        else
        {
            RING("Send %u packets to IP address %s.", PKT_NUM,
                 te_sockaddr_get_ipstr(destination_addrs[i]));
            TE_SPRINTF(buf,
                       "{ arg-sets { simple-for:{begin 1,end %u} }, "
                       "  pdus  { udp:{},                           "
                       "          ip4:{                             "
                       "                dst-addr plain:'%X'H        "
                       "              },                            "
                       "          eth:{}                            "
                       "        },                                  "
                       "  payload length:%u }                       ",
                       PKT_NUM,
                       ntohl(SIN(destination_addrs[i])->sin_addr.s_addr),
                       PAYLOAD_LEN);
        }
        CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &pkt, &num));
        CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid, csap, pkt,
                                       RCF_MODE_NONBLOCKING));
        TAPI_WAIT_NETWORK;
        rcf_ta_trsend_stop(pco_tst->ta, sid, csap, &num);

        TEST_STEP("Check:\n"
                  " - number of packets sent;\n"
                  " - whether the socket related to the first IP VLAN/MAC "
                  "VLAN interface has received packets;\n"
                  " - number of received bytes for each packet in case of "
                  "correct IP/MAC address.");
        if (num != PKT_NUM * (i + 1))
        {
            ERROR("CSAP on TST has sent %d packets instead of %d",
                  num, PKT_NUM * (i + 1));
            TEST_VERDICT("Incorrect number of packets sent by CSAP");
        }

        TAPI_WAIT_NETWORK;

        if (i == 0)
        {
            /*
             * Correct destination address, corresponding to the first
             * IP VLAN/MAC VLAN interface
             */
            for (j = 0; j < PKT_NUM; j++)
            {
                RPC_CHECK_READABILITY(rpcs_recv, iut_s, TRUE);
                rcv = rpc_recv(rpcs_recv, iut_s, recv_buf, BUFFER_SIZE, 0);
                if (rcv != PAYLOAD_LEN)
                {
                    TEST_FAIL("Packet %u of %u: %d bytes was received "
                              "instead of %d", j + 1, PKT_NUM, rcv,
                              PAYLOAD_LEN);
                }
            }
        }
        else
        {
            RPC_CHECK_READABILITY(rpcs_recv, iut_s, FALSE);
        }

        asn_free_value(pkt);
        pkt = NULL;
    }

    TEST_SUCCESS;

cleanup:
    asn_free_value(pkt);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    CLEANUP_RPC_CLOSE(rpcs_recv, iut_s);

    if (use_netns)
    {
        sockts_destroy_netns(pco_iut->ta, rpcs_ns, TEST_NETNS,
                             TEST_NETNS_TA);
    }

    CLEANUP_REMOVE_MACVLAN_OR_IPVLAN(pco_iut, iut_if->if_name,
                                     iut_vlan1_if_name, use_macvlan,
                                     iut_vlan1_configured);
    CLEANUP_REMOVE_MACVLAN_OR_IPVLAN(pco_iut, iut_if->if_name,
                                     iut_vlan2_if_name, use_macvlan,
                                     iut_vlan2_configured);
    if (iut_if_rp_filter >= 0)
    {
        CLEANUP_CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta,
                                              iut_if_rp_filter, NULL,
                                              "net/ipv4/conf:%s/rp_filter",
                                              iut_if->if_name));
    }
    if (iut_if_arp_ignore >= 0)
    {
        CLEANUP_CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta,
                                              iut_if_arp_ignore, NULL,
                                              "net/ipv4/conf:%s/arp_ignore",
                                              iut_if->if_name));
    }

    tapi_cfg_free_entry(&vlan_net_handle);
    tapi_cfg_free_entry(&iut_vlan1_addr_handle);
    tapi_cfg_free_entry(&iut_vlan2_addr_handle);
    tapi_cfg_free_entry(&tst_new_addr_handle);
    tapi_cfg_free_entry(&tst_new_addr_handle2);
    tapi_cfg_free_entry(&netns_vlan1_addr_handle);

    free(iut_vlan1_if_name);
    free(iut_vlan2_if_name);
    free(iut_vlan1_addr);
    free(iut_vlan2_addr);
    free(tst_new_addr);
    free(netns_vlan1_addr);
    free(net_oid);

    TEST_END;
}
