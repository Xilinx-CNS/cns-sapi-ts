/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-mcast_bcast_port_unreach ICMP Unreachable for multicast/broadcast packets.
 *
 * @objective Check that ICMP messages are sent in case of sending unicast
 *            datagram and are not sent in case of broad- or multicast ones.
 *
 * @type Conformance.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param tst_addr      Address on Tester
 * @param iut_addr      Address on IUT
 * @param mcast_addr    Multicast group address
 * @param data_len      Size of datagram                     
 * @param packet_number Number of datagrams to send for reliability.
 * @param sock_func     Socket creation function.
 *
 * @par Scenario:
 *
 * -# Create a socket @p tst_s on @p pco_tst.
 * -# Bind() @p iut_s to @c INADDR_ANY with some unused port.
 * -# Send datagram from @p tst_s to IUT unicast address.
 * -# Check that port unreachable ICMP message is sent from IUT.
 *   
 * -# Create a socket @p iut_s on @p pco_iut and make it join 
 *    some @p mcast_addr multicast group.
 * -# Send datagram to @p mcast_addr via @p tst_s.
 * -# Check that no port unreachable message is sent. 
 *  
 * -# Send broadcast datagram via @p tst_s.
 * -# Check that no port unreachable message is sent.
 *  
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_bcast_port_unreach"

#include <netinet/ip_icmp.h>
#include "sockapi-test.h"
#include "tapi_ip4.h"
#include "multicast.h"
#include "mcast_lib.h"

/** How long to wait for ICMP message, milliseconds. */
#define ICMP_TIMEOUT 500

/** Quantity of ICMP "port unreachable" messages received. */
static int icmp_packets_received = 0;

/**
 * Callback function to proceed received ICMP datagrams. 
 *
 * @param pkt       Pointer to packet received
 * @param userdata  User data; unused 
 *
 * @return          NULL
 */
static void 
callback(const tapi_ip4_packet_t *pkt, void *userdata)
{
    UNUSED(userdata);
    if ((pkt->ip_proto == IPPROTO_ICMP) &&
        ((struct icmphdr *)(pkt->payload))->code == ICMP_PORT_UNREACH)
    {
        icmp_packets_received++;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_tst;       /* Test host */    
    rcf_rpc_server            *pco_iut;       /* Server under testing */
    int                        s_tst;          /* Session on Tester */
    int                        tst_s = -1;     /* Socket on Tester */
    int                        iut_s = -1;     /* Socket on IUT */ 
    csap_handle_t              tst_csap =      /* CSAP on Tester */     
                               CSAP_INVALID_HANDLE;   
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *mcast_addr = NULL;
    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    struct sockaddr_storage    any_addr;    
    tarpc_joining_method       method;
    sockts_socket_func         sock_func;

    int     option_on = 1;              /* Flag for turning option on */
    char   *data;                       /* Data to send */
    int     data_len;
    int     i;
    int     packet_number;

    unsigned int     num;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    data = te_make_buf_by_len(data_len);

    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut, pco_tst, iut_if, tst_addr,
                                           mcast_addr);

    /* Create CSAP that controls packets from IUT to Tester */
    rcf_ta_create_session(pco_tst->ta, &s_tst);
    if (tapi_ip4_eth_csap_create(pco_tst->ta, s_tst, tst_if->if_name,
                                 TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                                 NULL, NULL,
                                 SIN(tst_addr)->sin_addr.s_addr,
                                 SIN(iut_addr)->sin_addr.s_addr,
                                 IPPROTO_ICMP, &tst_csap) != 0)
    {
        TEST_FAIL("Cannot create CSAP");
    }

    /* Open and bind socket on Tester */
    tst_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_DGRAM, 
                       RPC_IPPROTO_UDP);

    te_fill_buf(data, sizeof(data));                            

    /* 
     * Start listening to ICMP "Port unreachable" 
     * messages from IUT to Tester 
     */   
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, s_tst, tst_csap, NULL,
                                   TAD_TIMEOUT_INF, 10,
                                   RCF_TRRECV_PACKETS));


    /* Send unicast datagram from Tester to IUT */    
    for (i = 0; i < packet_number; i++)
    {
        rpc_sendto(pco_tst, tst_s, data, sizeof(data), 0, iut_addr);
        MSLEEP(ICMP_TIMEOUT);
        CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, s_tst, tst_csap,
                                      tapi_ip4_eth_trrecv_cb_data(
                                          callback, NULL),
                                      &num));
        if (icmp_packets_received == 0)
        {
            TEST_FAIL("No ICMP message answered unicast datagram");
        }
        else
        {
            if (icmp_packets_received > 1)
            {
                TEST_FAIL("Two or more ICMP messages answered unicast "
                          "datagram");
            }
        }
        icmp_packets_received = 0;
        CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, s_tst, tst_csap, 
                                   NULL, TAD_TIMEOUT_INF, 10,
                                   RCF_TRRECV_PACKETS));
    }
        
    /* Add IUT to multicast group */
    iut_s = sockts_socket(sock_func, pco_iut, RPC_AF_INET, RPC_SOCK_DGRAM,
                          RPC_IPPROTO_UDP);
    memcpy(&any_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    TAPI_SET_NEW_PORT(pco_iut, &any_addr);
    te_sockaddr_set_wildcard(SA(&any_addr));
    rpc_bind(pco_iut, iut_s, SA(&any_addr));

    rpc_common_mcast_join(pco_iut, iut_s, mcast_addr, tst_addr,
                          iut_if->if_index, method);

    /* Start listening for ICMP message from IUT to Tester */
    rpc_sendto(pco_tst, tst_s, data, sizeof(data), 0, mcast_addr);
    MSLEEP(ICMP_TIMEOUT);
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, s_tst, tst_csap,
                                  tapi_ip4_eth_trrecv_cb_data(
                                      callback, NULL),
                                  &num));
    if (icmp_packets_received > 0)
    {
        TEST_FAIL("Unexpected ICMP message answered multicast datagram");
    }
    
    /* Send broadcast datagram. */
    SIN(iut_addr)->sin_addr.s_addr = htonl(INADDR_BROADCAST);
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_BROADCAST, &option_on);
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, s_tst, tst_csap, NULL,
                                   TAD_TIMEOUT_INF, 1,
                                   RCF_TRRECV_PACKETS));
    rpc_sendto(pco_tst, tst_s, data, sizeof(data), 0, iut_addr);
    MSLEEP(ICMP_TIMEOUT);
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, s_tst, tst_csap,
                                  tapi_ip4_eth_trrecv_cb_data(
                                      callback, NULL),
                                  &num));
    if (icmp_packets_received > 0)
    {
        TEST_FAIL("Unexpected ICMP message answered broadcast datagram");
    }    
    TEST_SUCCESS;
    
cleanup:
    if (tst_csap != CSAP_INVALID_HANDLE)
    {
        if ((rc = tapi_tad_csap_destroy(pco_tst->ta, 
                                      s_tst, tst_csap)) != 0)
        {
            ERROR("tapi_tad_csap_destroy() failed: %r", rc);
            result = -1;
        }
    }
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

