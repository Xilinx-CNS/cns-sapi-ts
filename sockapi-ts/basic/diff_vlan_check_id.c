/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2023 Advanced Micro Devices, Inc. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-diff_vlan_check_id Check that received packets have correct VLAN tag
 *
 * @objective The test should check that VLAN interface receives packets with
 *            correct VLAN tag, and check that the interface does not receive
 *            packets with a wrong VLAN tag (or no VLAN tag).
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 * @param use_netns     Whether to create netns and add VLAN interface
 *                      to it:
 *                      - @c FALSE
 *                      - @c TRUE
 * @param vlan1         Identifier of VLAN interface to be created on
 *                      @p pco_iut
 * @param vlan2         Identifier of another VLAN interface to be created
 *                      on @p pco_iut
 *
 * @par Scenario:
 *
 * @author Boris Shleyfman <bshleyfman@oktet.co.il>
 */

#define TE_TEST_NAME  "basic/diff_vlan_check_id"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

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
/* VLAN tag not corresponding to any VLAN */
#define VLAN3                33

/* Name of the created namespace */
#define TEST_NETNS "aux_netns"
/* Name of the created TA */
#define TEST_NETNS_TA "Agt_aux_netns"
/* Name of the created RPC server */
#define TEST_NETNS_RPCS "pco_iut_aux_netns"

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
    uint16_t                     vlan1;
    uint16_t                     vlan2;

    cfg_handle             vlan_net_handle = CFG_HANDLE_INVALID;
    cfg_handle             iut_vlan1_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle             iut_vlan2_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle             netns_vlan1_addr_handle = CFG_HANDLE_INVALID;
    rcf_rpc_server        *rpcs_ns = NULL;

    int                    iut_s = -1;
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

    int                    vlan_tags_sent[] = {vlan1, vlan2, VLAN3, 0, -1};

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
    TEST_GET_INT_PARAM(vlan1);
    TEST_GET_INT_PARAM(vlan2);

    TEST_STEP("Create two VLAN interfaces on IUT.");
    CHECK_RC(tapi_cfg_alloc_ip4_net(&vlan_net_handle));
    CHECK_RC(cfg_get_oid_str(vlan_net_handle, &net_oid));
    val_type = CVT_INTEGER;

    /*
     * There is a problem on some systems: packets can be seen on
     * NIC but socket doesn't receive them. To handle this, the value
     * of rp_filter should be changed.
     */
    if (!use_netns)
    {
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 2, NULL,
                                      "net/ipv4/conf:all/rp_filter"));
    }

    CHECK_RC(cfg_get_instance_fmt(&val_type, &net_prefix, "%s/prefix:",
                                  net_oid));
    CREATE_CONFIGURE_VLAN_EXT(pco_iut, vlan_net_handle,
                              iut_vlan1_addr_handle, iut_vlan1_addr,
                              net_prefix, iut_if, vlan1, iut_vlan1_if_name,
                              iut_vlan1_configured, TRUE);
    CREATE_CONFIGURE_VLAN_EXT(pco_iut, vlan_net_handle,
                              iut_vlan2_addr_handle, iut_vlan2_addr,
                              net_prefix, iut_if, vlan2, iut_vlan2_if_name,
                              iut_vlan2_configured, TRUE);
    CFG_WAIT_CHANGES;

    if (!use_netns)
    {
        TEST_STEP("If not @p use_netns: create a socket on IUT and set "
                  "socket option @c SO_BINDTODEVICE to the first VLAN "
                  "interface's name.");
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
                  "first VLAN interface there, and create socket on RPC "
                  "server inside netns.");
        sockts_iut_netns_setup(pco_iut, vlan_net_handle, iut_vlan1_if_name,
                               TEST_NETNS, TEST_NETNS_TA, TEST_NETNS_RPCS,
                               &rpcs_ns, &netns_vlan1_addr,
                               &netns_vlan1_addr_handle);
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

    TEST_STEP("Get MAC addresses of the interfaces on IUT and TST.");
    TE_SPRINTF(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_FAIL("Failed to get MAC address of IUT interface");

    TE_SPRINTF(oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_tst) != 0)
        TEST_FAIL("Failed to get MAC address of TST interface");

    TEST_STEP("Create CSAP to send packets from TST to the first IUT "
              "VLAN interface.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));
    CHECK_RC(tapi_udp_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_tst, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(send_addr)->sin_addr.s_addr,
                                          SIN(tst_addr)->sin_port,
                                          te_sockaddr_get_port(&bind_addr),
                                          &csap));

    TEST_STEP("Using CSAP, send @c PKT_NUM packets with:\n"
              "1) correct VLAN tag,\n"
              "2) VLAN ID of another interface,\n"
              "3) non-existent VLAN ID,\n"
              "4) VLAN tag = 0,\n"
              "5) without VLAN tag.");
    vlan_tags_sent[0] = vlan1;
    vlan_tags_sent[1] = vlan2;

    for (i = 0; i < (unsigned int)TE_ARRAY_LEN(vlan_tags_sent); i++)
    {
        if (vlan_tags_sent[i] >= 0)
        {
            RING("Send %u packets with VLAN tag = %d.", PKT_NUM,
                 vlan_tags_sent[i]);
            TE_SPRINTF(buf,
                       "{ arg-sets { simple-for:{begin 1,end %u} }, "
                       "  pdus  { udp:{},                           "
                       "          ip4:{},                           "
                       "          eth:{                             "
                       "                tagged tagged:{             "
                       "                  vlan-id plain:%u          "
                       "                }                           "
                       "              }                             "
                       "        },                                  "
                       "  payload length:%u }                       ",
                       PKT_NUM, vlan_tags_sent[i], PAYLOAD_LEN);
        }
        else
        {
            RING("Send %u packets without VLAN tag.", PKT_NUM);
            TE_SPRINTF(buf,
                       "{ arg-sets { simple-for:{begin 1,end %u} }, "
                       "  pdus  { udp:{}, ip4:{}, eth:{} },         "
                       "  payload length:%u }                       ",
                       PKT_NUM, PAYLOAD_LEN);
        }
        CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &pkt, &num));
        CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid, csap, pkt,
                                       RCF_MODE_NONBLOCKING));
        TAPI_WAIT_NETWORK;
        rcf_ta_trsend_stop(pco_tst->ta, sid, csap, &num);

        TEST_STEP("Check:\n"
                  " - number of packets sent;\n"
                  " - whether the socket related to the first VLAN interface "
                  "has received packets;\n"
                  " - number of received bytes for each packet in case of "
                  "correct VLAN tag.");
        if (num != PKT_NUM * (i + 1))
        {
            ERROR("CSAP on TST has sent %d packets instead of %d to IUT VLAN",
                  num, PKT_NUM * (i + 1));
            TEST_VERDICT("Incorrect number of packets sent by CSAP");
        }

        if (vlan_tags_sent[i] == vlan1)
        {
            for (j = 0; j < PKT_NUM; j++)
            {
                RPC_CHECK_READABILITY(rpcs_recv, iut_s, TRUE);
                rcv = rpc_recv(rpcs_recv, iut_s, recv_buf, BUFFER_SIZE, 0);
                if (rcv != PAYLOAD_LEN)
                {
                    TEST_FAIL("Packet %d of %d: %d bytes was received "
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

    CLEANUP_REMOVE_VLAN(pco_iut, iut_if, vlan1, iut_vlan1_configured);
    CLEANUP_REMOVE_VLAN(pco_iut, iut_if, vlan2, iut_vlan2_configured);

    tapi_cfg_free_entry(&vlan_net_handle);
    tapi_cfg_free_entry(&iut_vlan1_addr_handle);
    tapi_cfg_free_entry(&iut_vlan2_addr_handle);
    tapi_cfg_free_entry(&netns_vlan1_addr_handle);

    free(iut_vlan1_if_name);
    free(iut_vlan2_if_name);
    free(iut_vlan1_addr);
    free(iut_vlan2_addr);
    free(netns_vlan1_addr);
    free(net_oid);

    TEST_END;
}
