/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/tcp/flood  
 * Flood of TCP packets with fakse SEQN/ACKN
 */

/** @page attacks-tcp-flood  Flood of TCP packets with fake SEQN/ACKN
 *
 * @objective Check that flood of TCP packets with incorrect SEQN/ACKN
 *            does not lead to denial of service.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *
 * @par Scenario
 * -# Create @c CONN_NUM TCP connections between @p pco_iut and @p pco_tst.
 * -# Send/receive data in both directions.
 * -# Start task on the @p pco_tst which sends flood of TCP packets
 *    with incorrect SEQN (less or much more greater than acknowledged before
 *    task starting) and incorrect ACK (less or much more greater than SEQN 
 *    in the last packet received from the parthner before task starting) for
 *    each TCP connection.
 * -# Send/receive data via TCP connections and check that nothing is lost
 *    and/or corrupted.
 *
 * @note As a modification the task sending incorrect SEQN and ACKN may
 *       monitor TCP traffic between @p pco_iut and @p pco_tst and generate 
 *       incorrect SEQN and ACKN basing on observed numbers.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/tcp/flood"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_tcp.h"
#include "ndn_eth.h"
#include "tapi_cfg_base.h"
#include "ndn.h"

#define PKT_NUM         (1024 * 1024) /**< Number of packets for flooding */
#define CONN_NUM        4             /**< Number of connections */
#define TIMEOUT         (2 * 1000)    /**< 2 seconds for packet catching */

/** Auxiliary buffer */
static char buf[1024];

static uint32_t seqn = 0;
static uint32_t ackn = 0;

static void 
callback(asn_value *pkt, void *userdata)
{
    size_t len = sizeof(uint32_t);
    int    rc;
    
    UNUSED(userdata);
    
    if ((rc = asn_read_value_field(pkt, &seqn, &len, 
                                   "pdus.0.#tcp.seqn.#plain")) != 0)
        ERROR("Cannot read seqn: %r", rc);
                                           
    if ((rc = asn_read_value_field(pkt, &ackn, &len, 
                                   "pdus.0.#tcp.ackn.#plain")) != 0)
        ERROR("Cannot read ackn: %r", rc);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    
    int sid1, sid2, sid_watch;
    int num;
    int i;
    int iut_s[CONN_NUM];
    int tst_s[CONN_NUM];
    
    uint8_t mac_iut[ETHER_ADDR_LEN], mac_tst[ETHER_ADDR_LEN];
    
    char oid[RCF_MAX_ID];
    int  saved_klog_level = -1;

    csap_handle_t csap1 = CSAP_INVALID_HANDLE;
    csap_handle_t csap2 = CSAP_INVALID_HANDLE;
    csap_handle_t watch_csap = CSAP_INVALID_HANDLE;
    asn_value    *pkt1 = NULL;
    asn_value    *pkt2 = NULL;
    
    TEST_START;

    for (i = 0; i < CONN_NUM; i++)
        iut_s[i] = tst_s[i] = -1;
    
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

    for (i = 0; i < CONN_NUM; i++)
    {
        struct sockaddr_in src = *SIN(tst_addr);
        struct sockaddr_in dst = *SIN(iut_addr);
        
        if (i > 0)
        {
            TAPI_SET_NEW_PORT(pco_iut, &src);
            TAPI_SET_NEW_PORT(pco_tst, &dst);
        }
                   
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, 
                       RPC_IPPROTO_TCP,
                       (struct sockaddr *)&dst,
                       (struct sockaddr *)&src,
                       iut_s + i, tst_s + i);
    }

    /* Reducing console log level */
    TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &saved_klog_level);

    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid1));
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid2));
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid_watch));

    /* Create CSAP for packet catching on PCO IUT */
    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid_watch,
                                          tst_if->if_name,
                                          TAD_ETH_RECV_OUT |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_tst, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          SIN(tst_addr)->sin_port,
                                          SIN(iut_addr)->sin_port,
                                          &watch_csap));

    /* Start packet listening */
    CHECK_RC(tapi_tcp_ip4_eth_recv_start(pco_tst->ta, sid_watch, watch_csap,
                                         htonl(INADDR_ANY),
                                         htonl(INADDR_ANY),
                                         -1, -1, 
                                         TIMEOUT, 2, RCF_TRRECV_PACKETS));

    /* Provoke the traffic */
    sockts_test_connection(pco_iut, iut_s[0], pco_tst, tst_s[0]); 
    
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid_watch, watch_csap,
                                  tapi_tad_trrecv_make_cb_data(callback,
                                                               NULL),
                                  (unsigned int *)&num));
    
    RING("received %d, Last SEQN from tester: %u; last ACK from tester: %u",
         num, seqn, ackn);
    
    seqn += 1024 * 8;
    ackn += 1024 * 8;

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid1, tst_if->if_name,
                                          (TAD_ETH_RECV_DEF &
                                           ~TAD_ETH_RECV_OTHER) |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_tst, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          SIN(tst_addr)->sin_port,
                                          SIN(iut_addr)->sin_port,
                                          &csap1));

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid2, tst_if->if_name,
                                          (TAD_ETH_RECV_DEF &
                                           ~TAD_ETH_RECV_OTHER) |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_tst, mac_iut,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          SIN(tst_addr)->sin_port,
                                          SIN(iut_addr)->sin_port,
                                          &csap2));

    sprintf(buf, 
             "{ arg-sets { simple-for:{begin 1,end %u} }, "
             "  pdus  {                                   "
             "      tcp:{ flags plain:8,                  "
             "            seqn plain:%u},                 "
             "      ip4:{}, eth:{}},                      "
             "      payload bytes:'0102030405'H}          ",
             PKT_NUM, seqn);

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &pkt1, &num));

    sprintf(buf, 
             "{ arg-sets { simple-for:{begin 1,end %u} }, "
             "  pdus  {                                   "
             "      tcp:{ flags plain:16,                 "
             "            seqn plain:%u,                  "
             "            ackn plain:%u},                 "
             "      ip4:{}, eth:{}}}                      ",
             PKT_NUM, seqn, ackn); 

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &pkt2, &num));

        
    /* Start flooding on CSAPs */
    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid1, csap1, pkt1,
                                   RCF_MODE_NONBLOCKING));
    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid2, csap2, pkt2,
                                   RCF_MODE_NONBLOCKING));
    SLEEP(150);

    for (i = 0; i < CONN_NUM; i++)
        sockts_test_connection(pco_iut, iut_s[i], pco_tst, tst_s[i]); 

    TEST_SUCCESS;

cleanup:

    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, saved_klog_level);

    if (csap1 != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap1));

    if (csap2 != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap2));

    if (watch_csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, sid_watch,
                                             watch_csap));

    asn_free_value(pkt1);
    asn_free_value(pkt2);

    for (i = 0; i < CONN_NUM; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, iut_s[i]);
        CLEANUP_RPC_CLOSE(pco_tst, tst_s[i]);
    }

    TEST_END;
}
