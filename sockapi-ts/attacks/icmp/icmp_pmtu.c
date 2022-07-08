/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/icmp/icmp_pmtu  
 * Degrade TCP connection by PMTU decreasing to illegal value
 */

/** @page icmp-icmp_pmtu  Degrade TCP connection by PMTU decreasing to illegal value
 *
 * @objective Check that it's not possible to decrease PMTU to value less
 *            than 68 bytes.
 *
 * @reference CERT VU#222750 http://www.kb.cert.org/vuls/id/222750
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *
 * @par Scenario
 * -# Choose an IP address @p addr.
 * -# Configure route to address @p addr via @p pco_tst host on the @p pco_iut.
 * -# Create a TCP socket on the @p pco_iut and connect it to @ addr.
 * -# Sniff row TCP packets on the @p pco_iut and send answers emulating
 *    establishing of the connection with @p addr.
 * -# Send big amount of data via socket on the @p pco_iut.
 * -# Sniff TCP packets on the @p pco_tst and create ICMP Destination
 *    Unreachable with code 4 with these packets inside, proposing MTU
 *    67 bytes.
 * -# Check that the client does not decrease PMTU to 67 bytes and
 *    sends IP packets with the length 68 instead.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/icmp/icmp_pmtu"

#include "sockapi-test.h"

#include "ndn.h"
#include "tapi_tcp.h"
#include "tapi_tad.h"

static void
pmtu_tcp_pkt_handler(asn_value *pkt, void *userdata)
{
    int *max_ip_len;
    int  pld_len;
    int  rc;

    if (pkt == NULL || userdata == NULL)
    {
        ERROR("%s(): NULL ptrs passed!", __FUNCTION__);
        return;
    }

    max_ip_len = (int *)userdata;

    pld_len = asn_get_length(pkt, "payload.#bytes");
    if (pld_len > 0)
    {
        int    ip_len;
        size_t ip_len_size = sizeof(ip_len);

        rc = asn_read_value_field(pkt, &ip_len, &ip_len_size,
                                  "pdus.1.#ip4.total-length.#plain");
        if (rc == 0)
        {
            RING("%s(): ip len %d", __FUNCTION__, ip_len);
            if (*max_ip_len < ip_len)
                *max_ip_len = ip_len;
        }
        else
            ERROR("%s(): read IPv4 total-length failed %r",
                  __FUNCTION__, rc);
    } 
    /* otherwise max_ip_len leaved unchanged */
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    const struct if_nameindex *iut_if; 
    const struct if_nameindex *tst_if;

    csap_handle_t              sniff_csap = CSAP_INVALID_HANDLE;
    asn_value                 *sniff_pattern = NULL;


    int iut_s = -1;
    int tst_s = -1;
    int mtu = 100;
    int sid;
    int syms;
    int max_ip_len = 0;
    int i;
    
    unsigned int num;

    uint64_t sent;
    uint64_t received;

    char   icmp_error_method[100]; 
    size_t func_len;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    
    rcf_ta_create_session(pco_tst->ta, &sid);
                   
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          NULL, NULL,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          SIN(tst_addr)->sin_port,
                                          SIN(iut_addr)->sin_port,
                                          &sniff_csap));
    func_len = snprintf(icmp_error_method, sizeof(icmp_error_method), 
                        "tad_icmp_error:3:4:%d:100", mtu);

    CHECK_RC(asn_parse_value_text("{{ pdus {tcp:{}, ip4:{}, eth:{}}}}", 
                                  ndn_traffic_pattern, &sniff_pattern,
                                  &syms));
    CHECK_RC(asn_write_value_field(sniff_pattern, icmp_error_method,
                                   func_len + 1, "0.actions.0.#function")); 


    /* Receive flood data */
    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, tst_s, 5, &received);
    /* Send flood data */ 
    pco_iut->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_iut, iut_s, 100, 140, FALSE,
                      100, 200, TRUE, 3, &sent, TRUE);
    for (i = 0; i < 3; i++)
    { 
        max_ip_len = 0;
        CHECK_RC(tapi_tcp_ip4_eth_recv_start(pco_tst->ta, sid, sniff_csap,
                                             htonl(INADDR_ANY),
                                             htonl(INADDR_ANY),
                                             -1, -1, 
                                             1000, 5, RCF_TRRECV_PACKETS));


        CHECK_RC(tapi_tad_trrecv_wait(pco_tst->ta, sid, sniff_csap,
                                      tapi_tad_trrecv_make_cb_data(
                                          pmtu_tcp_pkt_handler, &max_ip_len),
                                      &num));
        RING("STEP %d max ip len: %d, caught pkts for measure: %d", 
             i, max_ip_len, num);
        max_ip_len = 0;

        CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, sniff_csap, 
                                       sniff_pattern, TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_COUNT));
        MSLEEP(200);
        CHECK_RC(rcf_ta_trrecv_stop(pco_tst->ta, sid, sniff_csap, NULL, NULL,
                                    &num));
        RING("STEP %d caught by CSAP: %d", i, num);
    }



    CHECK_RC(tapi_tcp_ip4_eth_recv_start(pco_tst->ta, sid, sniff_csap,
                                         htonl(INADDR_ANY),
                                         htonl(INADDR_ANY),
                                         -1, -1, 
                                         1000, 5, RCF_TRRECV_PACKETS));


    CHECK_RC(tapi_tad_trrecv_wait(pco_tst->ta, sid, sniff_csap,
                                  tapi_tad_trrecv_make_cb_data(
                                      pmtu_tcp_pkt_handler, &max_ip_len),
                                  &num));

    RING("LAST max ip len: %d, caught pkts for measure: %d", 
         max_ip_len, num);

    pco_iut->op = RCF_RPC_WAIT;
    rpc_simple_sender(pco_iut, iut_s, 100, 140, FALSE,
                      100, 200, TRUE, 3, &sent, TRUE);

    pco_tst->op = RCF_RPC_WAIT;
    rpc_simple_receiver(pco_tst, tst_s, 5, &received);

    RING("sent: %d, received: %d", (int)sent, (int)received);

    if (max_ip_len < 68)
        TEST_FAIL("IP length degraded to very small value %d", max_ip_len);

    if (sent != received)
        TEST_FAIL("Data lost");
    
    TEST_SUCCESS;

cleanup:

    if (sniff_csap != CSAP_INVALID_HANDLE &&
        (rc = tapi_tad_csap_destroy(pco_tst->ta, 0, sniff_csap)) != 0)
    {
        ERROR("csap destroy failed %r", rc);
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
