/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/ip/frag_duplicate  
 * Duplicated fragments
 */

/** @page ip-frag_duplicate  Duplicated fragments
 *
 * @objective Check that duplication of fragments does not lead to packets
 *            loss.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 * @param min_pkt   Minimum packet length (in pairs with @p max_pkt):
 *                  - 100
 *                  - 2000
 * @param max_pkt   Maximum packet length:
 *                  - 300
 *                  - 4000
 * @param frag_len  Fragment length:
 *                  - 64
 *
 * @par Scenario
 * -# Create datagram connection between @p pco_iut and @p pco_tst.
 * -# Start the task on the @p pco_tst, which sends flood of 
 *    UDP datagrams splitted to fragments; random number of random
 *    fragments of each datagram should be duplicated.
 * -# Start the task on the @p pco_iut, which receives datagrams and
 *    calculates number of received datagrams and received bytes.
 * -# Stop tasks and check that number of sent datagrams and bytes
 *    on the @p pco_tst is equalto number of received datagrams and
 *    bytes on the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/ip/frag_duplicate"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_tcp.h"
#include "tapi_cfg_base.h"

/**< Maximum number of fragments in the packet */
#define MAX_FRAG_NUM   1024         
/**< Maximum number of duplicated fragments for one packet */
#define MAX_DUP        16           
#define PKT_NUM        (1024 * 32)  /**< Number of packets for flooding */
#define UDP_HDR_LEN    8            /**< UDP header length in bytes */
#define IP_HDR_LEN     20           /**< IP header length in bytes */

/* Test parameters */

static int min_pkt;
static int max_pkt;
static int frag_len;

static const struct sockaddr *iut_addr;
static const struct sockaddr *tst_addr;

/**
 * Create template for packet with specified payload.
 *
 * @return Template which may be sent to CSAP
 */
static asn_value *
create_template(int *payload_len)
{
    uint8_t buf[UDP_HDR_LEN];

    int  len;
    int  n, i, k;
    int  rc;
    
    unsigned int unique_offset; /* Offset of the fragment, which 
                                   should be sent once */
    
    asn_value *result = NULL;
    
    tapi_ip_frag_spec  frags[MAX_FRAG_NUM + MAX_DUP];
    tapi_ip_frag_spec *tmp = frags;
    tapi_ip_frag_spec  dup;

    tapi_ip_frag_specs_init(frags, TE_ARRAY_LEN(frags));
    len = rand_range(min_pkt, max_pkt);
    
    *(uint16_t *)buf = SIN(tst_addr)->sin_port;
    *(uint16_t *)(buf + 2) = SIN(iut_addr)->sin_port;
    buf[4] = len >> 8;
    buf[5] = len & 0xFF;
    buf[6] = buf[7] = 0;
    
    n = (len / frag_len) + 1 - !(len % frag_len);

    for (i = 0; i < n; i++)
    {
        tmp->hdr_offset = tmp->real_offset = i * frag_len;
        tmp->real_offset = i * frag_len;
        tmp->real_length = 
            (i < n - 1) ? frag_len : 
            (len % frag_len == 0) ? frag_len : len % frag_len;
        tmp->hdr_length = tmp->real_length + IP_HDR_LEN;
            
        tmp->more_frags = i < (n - 1);
        tmp->dont_frag = FALSE; 
        
        tmp++;
    }
    unique_offset = frags[rand_range(0, n - 1)].real_offset;
    
    for (k = 0; k < rand_range(1, MAX_DUP); k++)
    {
        dup = frags[rand_range(0, n - 1)];
        if (dup.real_offset == unique_offset)
            continue;
        i = rand_range(0, n);
        memmove(frags + i + 1, frags + i, (n - i) * sizeof(frags[0]));
        frags[i] = dup;
        n++;
    }
    
    rc = tapi_ip4_template(frags, n, 1, IPPROTO_UDP, buf, UDP_HDR_LEN,
                           &result);
    if (rc != 0)
        TEST_FAIL("tapi_ip4_template() failed; rc %r", rc);
        
    rc = tapi_tad_add_iterator_for(result, 1, PKT_NUM, 1);
    if (rc != 0)
        TEST_FAIL("tapi_tad_add_iterator_for() failed; rc %r", rc);

    rc = asn_write_value_field(result, NULL, 0,
                               "pdus.0.#ip4.pld-checksum.#disable");
    if (rc != 0)
        TEST_FAIL("Disable UDP checksum calculation failed %r", rc);
        
    *payload_len = len - 8;
        
    return result;
}                

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    
    int iut_s = -1;
    int len;
    int sid;

    uint64_t received, expected;
    
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
    TEST_GET_INT_PARAM(min_pkt);
    TEST_GET_INT_PARAM(max_pkt);
    TEST_GET_INT_PARAM(frag_len);
    
    if (max_pkt > frag_len * MAX_FRAG_NUM)
        TEST_FAIL("Incorrect parameter max_pkt/frag_len ratio");
    
    sprintf(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_STOP;

    sprintf(oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_tst) != 0)
        TEST_STOP;

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, 
                       RPC_IPPROTO_UDP);
    rpc_bind(pco_iut, iut_s, iut_addr);
        
    if (rcf_ta_create_session(pco_tst->ta, &sid) != 0)
        TEST_FAIL("Failed to allocate RCF session");

    /* Create CSAP for sending UDP packets with lost fragments */
    CHECK_RC(tapi_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                      (TAD_ETH_RECV_DEF &
                                       ~TAD_ETH_RECV_OTHER) |
                                      TAD_ETH_RECV_NO_PROMISC,
                                      mac_tst, mac_iut,
                                      SIN(tst_addr)->sin_addr.s_addr,
                                      SIN(iut_addr)->sin_addr.s_addr,
                                      IPPROTO_UDP, &csap));

    /* Start receiver */
    pco_iut->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_iut, iut_s, 0, &received);
    
    /* Start flooding on CSAPs */
    pkt = create_template(&len);
    expected = len * PKT_NUM;
    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid, csap, pkt,
                                   RCF_MODE_BLOCKING));

    /* Wait for receiver finishing */
    RING("Traffic is sent");
    pco_iut->timeout = 10000;
    rpc_simple_receiver(pco_iut, iut_s, 0, &received);
    
    if (expected / 2 > received)
    {
        WARN("Unexpected number of bytes is received: %d instead %d",
             (int)received, (int)expected); 
    }
    
    if (received == 0)
        TEST_FAIL("No data are received");          
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    asn_free_value(pkt);

    TEST_END;
}
