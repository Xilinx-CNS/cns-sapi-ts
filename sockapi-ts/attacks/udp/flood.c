/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/udp/flood  
 * Flood of UDP packets with different dst/src addresses/ports
 */

/** @page udp-flood  Flood of UDP packets with different dst/src addresses/ports
 *
 * @objective Check that flood of UDP packets with different dst/src
 *            addresses/ports does not lead to denial of service.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *
 * @par Scenario
 * -# Create stream and datagram connections between @p pco_iut and 
 *    @p pco_tst.
 * -# Create several listening datagram sockets.
 * -# Start the task on the @p pco_tst, which sends flood of 
 *    UDP datagrams from different source IP addresses/ports and to
 *    different destination ports (used and unused).
 * -# Check that existing connections may be used to send/receive data.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/udp/flood"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_udp.h"
#include "tapi_cfg_base.h"
#include "ndn.h"

#define PKT_NUM      (1024 * 2048) /**< Number of packets for flooding */

/** Auxiliary buffer */
static char buf[1024];

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    
    int sid;
    int num;
    int iut_s_tcp = -1;
    int iut_s_udp = -1;
    int tst_s_tcp = -1;
    int tst_s_udp = -1;

    uint8_t mac_iut[ETHER_ADDR_LEN], mac_tst[ETHER_ADDR_LEN];
    
    char oid[RCF_MAX_ID];

    csap_handle_t csap = CSAP_INVALID_HANDLE;
    asn_value    *pkt = NULL;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    
    sprintf(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_STOP;

    sprintf(oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_tst) != 0)
        TEST_STOP;

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                   iut_addr, tst_addr, &iut_s_udp, &tst_s_udp);
                   
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s_tcp, &tst_s_tcp); 
  
    /* Start flooding on CSAPs */
    if (rcf_ta_create_session(pco_tst->ta, &sid) != 0)
        TEST_FAIL("Failed to allocate RCF session");

    CHECK_RC(tapi_udp_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                          (TAD_ETH_RECV_DEF &
                                           ~TAD_ETH_RECV_OTHER) |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_tst, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          -1, -1, &csap));

    sprintf(buf, 
             "{ arg-sets { simple-for:{begin 1,end %u} },            "
             "  pdus  {                                              "
             "      udp:{ dst-port script:\"expr:$0\",               "
             "            src-port script:\"expr:(5000+$0)\"},       "
             "      ip4:{src-addr script:\"expr:(($0 %% 255) + 0x%08x)\"}," 
             "      eth:{}},                                         "
             "      payload bytes:'0102030405'H}                     ",
             PKT_NUM, ntohl(SIN(tst_addr)->sin_addr.s_addr) & 0xFFFFFF00);

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &pkt, &num));

    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid, csap, pkt,
                                   RCF_MODE_NONBLOCKING));
    SLEEP(10);

    pco_tst->def_timeout = 30000;
    pco_iut->def_timeout = 30000;
    sockts_test_connection(pco_iut, iut_s_tcp, pco_tst, tst_s_tcp); 
    sockts_test_connection(pco_iut, iut_s_udp, pco_tst, tst_s_udp); 

    TEST_SUCCESS;

cleanup:

    if (csap != CSAP_INVALID_HANDLE)
    {
        if (rcf_ta_trsend_stop(pco_tst->ta, sid, csap, &num) == 0)
            RING("%d UDP packets are sent", num);
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));
    }

    asn_free_value(pkt);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_udp);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_udp);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_tcp);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_tcp);

    TEST_END;
}
