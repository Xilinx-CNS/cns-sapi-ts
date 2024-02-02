/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2024 Advanced Micro Devices, Inc. */
/*
 * Test attacks/icmp/frag_need
 * Fragmentation needed DOS attack
 */

/** @page icmp-frag_need  Fragmentation needed DOS attack
 *
 * @objective Check that flood of ICMP fragmentation needed packets with
 *            different next-hop MTU does not lead to denial of service.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 * @param sock_type @c SOCK_DGRAM or @c SOCK_STREAM
 * @param limit_mtu Use MTU between @c 576 and @c 1500 in case of @c TRUE, or
 *                  all avaliable values to next-hop MTU field (i.e. @c 0 -
 *                  @c 0xffff) in case of @c FALSE
 *
 * @par Scenario
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@arknetworks.am>
 */

#define TE_TEST_NAME  "attacks/icmp/frag_need"

#include "sockapi-test.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_icmp4.h"
#include "tapi_tcp.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_arp.h"
#include "tapi_cfg_base.h"
#include "ndn.h"

/** Number of packets for flooding */
#define PKT_NUM         (1024 * 256)

#define ICMP_PLD_LEN     28  /**< Original packet length in ICMP error */
#define TIMEOUT          (5 * 1000)  /**< 5 seconds for packet catching */

static char pkt_data[ICMP_PLD_LEN];

/** Callback for catching TCP and UDP packets */
static void
callback(const asn_value *packet, int layer,
         const ndn_eth_header_plain *header,
         const uint8_t *payload, uint16_t plen, void *userdata)
{
    struct tcphdr *tcp_hdr;

    UNUSED(packet);
    UNUSED(layer);
    UNUSED(header);
    UNUSED(userdata);

    switch (((struct iphdr *)payload)->protocol)
    {
        case IPPROTO_UDP:
            memcpy(pkt_data, payload,
                   plen > ICMP_PLD_LEN ? ICMP_PLD_LEN : plen);
            break;

        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr *)(payload + sizeof(struct iphdr));
            if ((tcp_hdr->th_flags & TCP_PSH_FLAG) == 0)
                return;
            memcpy(pkt_data, payload,
                   plen > ICMP_PLD_LEN ? ICMP_PLD_LEN : plen);
            break;
    }
}

/** Construct ICMP message */
static asn_value *
construct_icmp(char *dgram, te_bool limit_mtu)
{
    asn_value *res;
    int        num;
    char       buf[1024];
    int        mtu_min = 0;
    int        mtu_max = 0xffff;

    if (limit_mtu)
    {
        mtu_min = 576;
        mtu_max = 1500;
    }
    sprintf(buf,
             "{ arg-sets { simple-for:{begin 1,end %u} },       "
             "  pdus {                                          "
             "      icmp4:{type plain: %u, code plain: %u,      "
             "             nexthop-mtu script:                  "
             "                 \"expr:((rand() %% %u) + %u)\"}, "
             "      ip4:{protocol plain:%u},                    "
             "      eth:{}}}                                    ",
             PKT_NUM, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
             mtu_max - mtu_min + 1, mtu_min, IPPROTO_ICMP);

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &res, &num));

    /** Fill in payload of ICMP message */
    CHECK_RC(asn_write_value_field(res, dgram, ICMP_PLD_LEN, "payload.#bytes"));

    return res;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;

    uint8_t mac_iut[ETHER_ADDR_LEN];
    uint8_t mac_tst[ETHER_ADDR_LEN];

    int             sid;
    asn_value      *pkt;
    csap_handle_t   csap = CSAP_INVALID_HANDLE;

    int  num;
    int  iut_s = -1;
    int  tst_s = -1;
    int  len = -1;
    char tx_buf[1024];
    char rx_buf[1024];

    rpc_socket_type sock_type = RPC_SOCK_UNSPEC;
    te_bool         limit_mtu = FALSE;

    char oid[RCF_MAX_ID];

    csap_handle_t              csap_eth = CSAP_INVALID_HANDLE;
    int                        sid_eth;
    asn_value                 *pkt_eth = NULL;

    uint16_t ethertype = ETHERTYPE_IP;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(limit_mtu);

    TEST_STEP("Get MAC addresses of the interfaces on IUT and TST.");
    TE_SPRINTF(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_FAIL("Failed to get MAC address of IUT interface");

    TE_SPRINTF(oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_tst) != 0)
        TEST_FAIL("Failed to get MAC address of TST interface");

    TEST_STEP("Generate @p sock_type connetion between IUT and TST.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Generate some traffic between IUT and TST and catch packets "
              "via CSAP for further ICMP sending.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid_eth));

    CHECK_RC(tapi_eth_csap_create(pco_tst->ta, sid_eth,
                                  tst_if->if_name,
                                  TAD_ETH_RECV_DEF |
                                  TAD_ETH_RECV_NO_PROMISC,
                                  mac_tst, mac_iut, NULL, &csap_eth));

    /* Catch TCP or UDP packets */
    CHECK_RC(tapi_eth_add_pdu(&pkt_eth, NULL, TRUE, mac_tst, mac_iut,
                              &ethertype, TE_BOOL3_ANY, TE_BOOL3_ANY));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid_eth, csap_eth, pkt_eth,
                                   TIMEOUT, 100, RCF_TRRECV_PACKETS));
    /* Provoke the traffic */
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid_eth, csap_eth,
                                  tapi_eth_trrecv_cb_data(callback, NULL),
                                  (unsigned int *)&num));

    TEST_STEP("Send flood of ICMP fragmentation needed packets with different "
              "next-hop MTU field according to @p limit_mtu parameter.");
    if (pkt_data[0] == 0)
        TEST_FAIL("Failed to catch TCP/UDP packet");
    pkt = construct_icmp(pkt_data, limit_mtu);

    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));

    CHECK_RC(tapi_icmp_ip4_eth_csap_create(pco_tst->ta, sid,
                                           tst_if->if_name,
                                           (TAD_ETH_RECV_DEF &
                                            ~TAD_ETH_RECV_OTHER) |
                                           TAD_ETH_RECV_NO_PROMISC,
                                           mac_tst, mac_iut,
                                           SIN(tst_addr)->sin_addr.s_addr,
                                           SIN(iut_addr)->sin_addr.s_addr,
                                           &csap));

    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid, csap,
                                   pkt, RCF_MODE_NONBLOCKING));

    VSLEEP(2, "Wait for flooding.");

    TEST_STEP("Check that connection is still alive. In case of @c SOCK_DGRAM "
              "first @b send() could return @c -1 with @c EMSGSIZE errno, "
              "if ICMP was with small next-hop MTU.");
    if (sock_type == RPC_SOCK_DGRAM)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_send(pco_iut, iut_s, tx_buf, sizeof(tx_buf), 0);
        if (rc < 0)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EMSGSIZE,
                            "First send() after ICMP flood returned -1");
            RING("First send() after ICMP flood returned -1 with EMSGSIZE");
        }
        else
        {
            len = rpc_recv(pco_tst, tst_s, rx_buf, sizeof(rx_buf), 0);
            if (len != rc || memcmp(tx_buf, rx_buf, len) != 0)
                TEST_FAIL("Invalid data received after flooding");
        }
    }

    /* Check usability of existing connection */
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    if (csap != CSAP_INVALID_HANDLE)
    {
        rcf_ta_trsend_stop(pco_tst->ta, sid, csap, &num);
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));
    }
    asn_free_value(pkt);

    if (csap_eth != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap_eth));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    asn_free_value(pkt_eth);

    TEST_END;
}
