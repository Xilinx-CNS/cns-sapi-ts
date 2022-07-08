/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/icmp/tcp_degrade  
 * Degrade TCP connection using ICMP Source Quench
 */

/** @page icmp-tcp_degrade  Degrade TCP connection using ICMP Source Quench
 *
 * @objective Check that sending of ICMP Source Quench message does not
 *            lead to data transmit speed decreasing.
 *
 * @reference CERT VU#222750 http://www.kb.cert.org/vuls/id/222750
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *
 * @par Scenario
 * -# Establish TCP connection between @p pco_tst and @p pco_iut.
 * -# Send 8 M of data via the connection during time t0.
 * -# Start the task on the @p pco_iut, which sniffs TCP packets corresponding
 *    to the connection and sends ICMP Source Quench Error with this
 *    packet inside.
 * -# Send 8 M of data via the connection during time t1.
 * -# Check that delta between t0 and t1 is less than 20%.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/icmp/tcp_degrade"

#include "sockapi-test.h"

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_tcp.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_cfg_base.h"
#include "ndn.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;

    int iut_s = -1;
    int tst_s = -1;
    int sid;
    int num;

    csap_handle_t csap = CSAP_INVALID_HANDLE;
    
    asn_value *pkt;
    
    uint64_t sent;
    uint64_t received1, received2;
    uint64_t delta;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Measure normal performance */
    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, tst_s, 0, &received1);
    rpc_simple_sender(pco_iut, iut_s, 100, 1000, FALSE,
                      0, 0, TRUE, 20, &sent, FALSE);
    rpc_simple_receiver(pco_tst, tst_s, 0, &received1);


    /* Create CSAP for ICMP Source Quench sending */
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));
    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                          (TAD_ETH_RECV_DEF &
                                           ~TAD_ETH_RECV_OTHER) |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          NULL, NULL,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          SIN(tst_addr)->sin_port,
                                          SIN(iut_addr)->sin_port,
                                          &csap));
    rc = asn_parse_value_text(
                 "{{ pdus {tcp:{}, ip4:{}, eth:{}},"
                 "   actions { function:\"tad_icmp_error:4:0:0:100\" }}}", 
                 ndn_traffic_pattern, &pkt, &num);
    
    /* Start CSAP operation */
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, 
                                   pkt, 0, 0, RCF_TRRECV_COUNT));
    
    /* Measure performance with ICMP Source Quench */
    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, tst_s, 0, &received2);
    pco_iut->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_iut, iut_s, 100, 1000, FALSE,
                      0, 0, TRUE, 20, &sent, FALSE);


    rpc_simple_sender(pco_iut, iut_s, 100, 1000, FALSE,
                      0, 0, TRUE, 20, &sent, FALSE);
    rpc_simple_receiver(pco_tst, tst_s, 0, &received2);
    
    if (received2 > received1)
        TEST_SUCCESS;
    
    delta = received1 - received2;

    if (delta > received1 / 5)
        TEST_FAIL("TCP connection is degraged by ICMP Source Quench");
    
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (csap != CSAP_INVALID_HANDLE)
    {
        rcf_ta_trrecv_stop(pco_tst->ta, sid, csap, NULL, NULL,
                           (unsigned int *)&num);
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));
    }

    TEST_END;
}
