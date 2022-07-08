/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/ip/frag_flood  
 * Flood of fragmented packets
 */

/** @page ip-frag_flood  Flood of fragmented packets
 *
 * @objective Check that flood of fragmented packets on the one connection
 *            does not lead to denial of service on other connections. 
 *
 * @reference CERT VU#35958 http://www.kb.cert.org/vuls/id/35958
 *
 * @param env   Private testing environment similar to
 *              @ref arg_types_env_peer2peer
 *
 * @par Scenario
 * -# Create stream connection between @p pco_iut and @p pco_tst.
 * -# Create datagram connection between @p pco_iut and @p pco_tst.
 * -# Obtain @p mtu of @p pco_iut host interface connected to @p pco_tst host.
 * -# Start the task receiving traffic from the datagram connection
 *    on the @p pco_iut.
 * -# Start the task sending datagrams with length greater than @p mtu and
 *    less than @p mtu * 100 via datagram connection on the @p pco_tst.
 * -# Send/receive correct data via stream connection in both directions.
 * -# Stop traffic sender and receiver and close all sockets created during
 *    the test. Check that at least part of fragmented data is received
 *    on the @p pco_iut.
 * -# Send/receive correct data via stream and datagram connections
 *    in both directions.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/ip/frag_flood"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_flooder = NULL;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    const struct if_nameindex *iut_if;

    int iut_s_tcp = -1;
    int tst_s_tcp = -1;
    int iut_s_udp = -1;
    int tst_s_udp = -1;
    int mtu;
    
    uint64_t sent;
    uint64_t received;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_flooder);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                   iut_addr, tst_addr, &iut_s_udp, &tst_s_udp);
                   
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s_tcp, &tst_s_tcp);
                   
    /* Retrieve MTU */

    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name,
                                        &mtu));
                   
    /* Start flooder */
    pco_flooder->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_flooder, tst_s_udp, mtu, mtu * 100, FALSE,
                      0, 0, TRUE, 10, &sent, TRUE);
    
    /* Check TCP connection */
    sockts_test_connection(pco_iut, iut_s_tcp, pco_tst, tst_s_tcp);
    
    /* Receive flood data */
    rpc_simple_receiver(pco_iut, iut_s_udp, 15, &received);
                               
    /* Wait flooder to stop */
    rpc_simple_sender(pco_flooder, tst_s_udp, mtu, mtu * 100, FALSE,
                      0, 0, TRUE, 10, &sent, TRUE);
    
    if (sent == 0)
        TEST_FAIL("Flooder did not sent data");
        
    if (received == 0)
        TEST_FAIL("All fragmented data are lost");
    
    /* Check connections */
    sockts_test_connection(pco_iut, iut_s_tcp, pco_tst, tst_s_tcp);
    sockts_test_connection(pco_iut, iut_s_udp, pco_tst, tst_s_udp);
    
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_udp);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_udp);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_tcp);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_tcp);

    TEST_END;
}
