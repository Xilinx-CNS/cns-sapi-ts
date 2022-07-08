/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * ARP table
 * 
 * $Id$
 */

/** @page arp-arp_packet_pool_empty ARP packet pool empty
 *
 * @objective ARP packet pool empty. 
 *            The ARP code maintains its own buffer pool. 
 *            Empty this pool by sending IP traffic 
 *            to many different hosts.
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param pco1_iut        PCO on IUT on @p host1
 * @param pco2_iut        PCO on IUT on @p host1
 * @param pco_tst         PCO on TESTER on @p host2
 * @param conn_num        Number of hosts the traffic is sent to
 * @param sock_type       @c SOCK_DGRAM or @c SOCK_STREAM
 *
 * @par Test sequence:
 * -# Create @p addr_list - @p conn_num IP addresses;
 *    These addresses should be from the network @p host1-host2;
 * -# Create @p conn_num sockets of type @c SOCK_DGRAM on @p pco1_iut 
 *    to send traffic to different hosts;
 * -# Initiate @p sock_type connection between @p pco2_iut and @p pco_tst,
 *    using @p pco2_iut as client and send traffic from @p pco2_iut to
 *    @p pco_tst in background;
 * -# For each address from @p addr_list and created socket on @p pco1_iut
 *    call @b sendto() using these socket 
 *    and address as destination address;
 * -# Stop sending traffic using TCP/UDP connection;
 *    Check that number of bytes sent is equal to number of bytes received.
 * -# Once again send traffic using TCP/UDP connection;
 *    Check that number of bytes sent is equal to them of received and
 *    that it is not equal to zero.
 *    This step is requered because traffic sending/receiving using 
 *    @p sock_type connection may finish before something bad happens 
 *    while traffic is sending to many different hosts.
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "arp/arp_packet_pool_empty"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"

#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
#define ARP_PKT_POOL_EMPTY_PORT    1709
    tapi_env_net   *net     = NULL;
    rcf_rpc_server *pco1_iut = NULL;
    rcf_rpc_server *pco2_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    struct sockaddr_in  *sockaddr_list = NULL;
    proto2hw_addr_map   *addr_list = NULL;
    int                 *sock_list = NULL; 
    
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    const struct if_nameindex   *iut_if;

    void   *tx_buf     = NULL;
    size_t  tx_buf_len = 1024;
    
    int       conn_num = 0;
    int       i;
    uint64_t  received = 0;
    uint64_t  sent = 0;
    int       iut_s = -1;
    int       tst_s = -1;
    
    int     sock_type;
    
    /* Preambule */
    TEST_START;
    
    TEST_GET_NET(net);
    TEST_GET_PCO(pco1_iut);
    TEST_GET_PCO(pco2_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_IF(iut_if);

    TEST_GET_INT_PARAM(conn_num);
    TEST_GET_SOCK_TYPE(sock_type);
    
    TEST_GET_ADDR(pco1_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    /* Generate list of clients addresses */
    GENERATE_MAP_LIST(net, conn_num, addr_list, TRUE, FALSE);
    
    /* Create socket list */
    sock_list = (int *)calloc(conn_num, sizeof(int));
    if (sock_list == NULL)
    {
        TEST_FAIL("Memory allocation failure");
    }
    for (i = 0; i < conn_num; i++)
        *(sock_list + i) = -1;
    
    for (i = 0; i < conn_num; i++)
        *(sock_list + i) = rpc_socket(pco1_iut, 
                   RPC_AF_INET, SOCK_DGRAM, RPC_PROTO_DEF);
    
    /* Create sockaddr list */
    sockaddr_list = 
       (struct sockaddr_in *)calloc(conn_num, sizeof(struct sockaddr_in));
    if (sockaddr_list == NULL)
        TEST_FAIL("%d: Memory allocation failure", __LINE__);

    for (i = 0; i < conn_num; i++)
    {
        SIN(sockaddr_list + i)->sin_family = AF_INET;
        SIN(sockaddr_list + i)->sin_port = ARP_PKT_POOL_EMPTY_PORT;
        SIN(sockaddr_list + i)->sin_addr.s_addr = 
            *(uint32_t *)((addr_list + i)->proto_addr);
    }
    /* Prepare tx buffer */
    tx_buf = te_make_buf_by_len(tx_buf_len);
    
    GEN_CONNECTION(pco_tst, pco2_iut, sock_type, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);
    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, tst_s, 0, &received);
    pco2_iut->op = RCF_RPC_CALL;
    rpc_simple_sender(pco2_iut, iut_s, 1, 10, 0, 0, 10000, 1, 20, &sent, 0);
    
    /* Send traffic to many different host */
    rpc_send_traffic(pco1_iut, conn_num, sock_list, 
                     tx_buf, tx_buf_len, 0, 
                     (struct sockaddr *)sockaddr_list);

    rpc_simple_sender(pco2_iut, iut_s, 1, 10, 0, 0, 10000, 1, 20, &sent, 0);
    rpc_simple_receiver(pco_tst, tst_s, 0, &received);
    TEST_CHECK_PKTS_LOST((sock_type == SOCK_DGRAM) ? TRUE : FALSE, 
                         sent, received);

    /* Call once again sender and receiver */
    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, tst_s, 0, &received);
    rpc_simple_sender(pco2_iut, iut_s, 1, 10, 0, 0, 10000, 1, 20, &sent, 0);
    rpc_simple_receiver(pco_tst, tst_s, 0, &received);
    TEST_CHECK_PKTS_LOST((sock_type == SOCK_DGRAM) ? TRUE : FALSE, 
                         sent, received);
    if (sent == 0)
        TEST_FAIL("%u: Number of bytes sent = 0", __LINE__);
                               
    TEST_SUCCESS;

cleanup:
    for (i = 0; i < conn_num; i++)
       CLEANUP_RPC_CLOSE(pco1_iut, *(sock_list + i));

    free(sock_list);
    free(sockaddr_list);
    free(addr_list);

    CLEANUP_RPC_CLOSE(pco2_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);   

    free(tx_buf);

    sockts_restart_if(pco1_iut, iut_if->if_name);

    TEST_END;
}
