/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Level5-specific test for Onload Extension API
 * 
 * $Id$
 */

/** @page ext_stackname-problematic_rxq_move_fd Try to call @b onload_move_fd() on a socket with problematic RXQ
 *
 * @objective Check that onload_move_fd() succeeds after a TCP socket
 *            received data with abnormalities such as loss,
 *            reordering or retransmitting of packets.
 *
 * @type use case
 *
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on TESTER
 * @param iut_addr             IP address on IUT
 * @param iut_lladdr           Ethernet address on IUT
 * @param tst_addr             Alien IP address to be used for TESTER
 * @param alien_link_address   Alien ethernet address to be used for TESTER
 * @param iut_if               Network interface on IUT
 * @param tst_if               Network interface on TESTER
 * @param existing_stack       Whether Onload stack should already exist
 *                             or not when we try to move a socket fd to it
 *                             firstly
 * @param rxq_problem          Which kind of problem occur in RXQ (lost,
 *                             reordered or retransmitted packets)
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/problematic_rxq_move_fd"

#include "sockapi-test.h"

#include "onload.h"
#include "extensions.h"

#include "move_fd_helpers.h"

#include "tapi_tcp.h"
#include "tapi_route_gw.h"

#define STACK_NAME "foo"

enum {
    RXQ_PACKETS_LOST,
    RXQ_PACKETS_REORDER,
    RXQ_PACKETS_RETRANSMIT,
};

#define RXQ_PROBLEM \
    { "lost", RXQ_PACKETS_LOST }, \
    { "reorder", RXQ_PACKETS_REORDER }, \
    { "retransmit", RXQ_PACKETS_RETRANSMIT }

#define DATA_SIZE 1024

#define PACKETS_NUM 20

/*
 * How often abnormalities occur in received packages
 * (each ABNORMALITY_RATEth packet)
 */
#define ABNORMALITY_RATE 3

typedef struct tcp_packet {
    uint8_t data[DATA_SIZE];
    tapi_tcp_pos_t seqn;
} tcp_packet;

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *tst_addr = NULL;
    const struct sockaddr       *iut_lladdr = NULL;
    const struct sockaddr       *alien_link_addr = NULL;
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;

    int                     iut_s = -1;
    int                     iut_s_listening = -1;
    int                     iut_s_aux = -1;
    tapi_tcp_handler_t      csap_tst_s = -1;
    te_bool                 alien_neigh_added = FALSE;
    cfg_handle              alien_ip_route = CFG_HANDLE_INVALID;

    te_bool                 existing_stack = FALSE;

    int rxq_problem = 0;

    tcp_packet      pkts[PACKETS_NUM];
    int             i; 
    tapi_tcp_pos_t  next_seqn;
    int             sent_pkt_idxs[PACKETS_NUM * 2];
    int             sent_pkts_num = 0;
    char            received_data[PACKETS_NUM * DATA_SIZE]; 
    ssize_t         received;
    te_bool         restore_stack_name = FALSE;
    char           *init_stack_name;
    int             tst_addr_family;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_lladdr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, alien_link_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(existing_stack);
    TEST_GET_ENUM_PARAM(rxq_problem, RXQ_PROBLEM);

    init_stack_name = tapi_onload_get_cur_stackname(pco_iut);

    TEST_STEP("Add a route and an ARP entry on IUT to make possible "
              "connecting with CSAP using fake TESTER addresses.");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    alien_neigh_added = TRUE;
    tst_addr_family = addr_family_rpc2h(sockts_domain2family(
                                          rpc_socket_domain_by_addr(tst_addr)));
    CHECK_RC(tapi_cfg_add_route(pco_iut->ta,
                                tst_addr_family,
                                te_sockaddr_get_netaddr(tst_addr),
                                8 * te_netaddr_get_size(tst_addr_family),
                                NULL, iut_if->if_name,
                                NULL, 0, 0, 0, 0, 0, 0,
                                &alien_ip_route));

    TEST_STEP("Open passively TCP connection on IUT with a CSAP emulating "
              "TCP socket on TESTER side.");
    iut_s_listening = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                                 RPC_PROTO_DEF,
                                                 FALSE, FALSE,
                                                 iut_addr);
    rpc_listen(pco_iut, iut_s_listening, SOCKTS_BACKLOG_DEF);

    CHECK_RC(tapi_tcp_init_connection(pco_tst->ta, TAPI_TCP_CLIENT,
                                      tst_addr, iut_addr,
                                      tst_if->if_name,
                                      (const uint8_t *)
                                                  alien_link_addr->sa_data,
                                      (const uint8_t *)iut_lladdr->sa_data,
                                      0, &csap_tst_s));
    CHECK_RC(tapi_tcp_wait_open(csap_tst_s, 5000));

    iut_s = rpc_accept(pco_iut, iut_s_listening, NULL, NULL);

    TEST_STEP("Prepare a sequence of TCP packets to be sent with required "
              "abnormalities.");
    next_seqn = tapi_tcp_next_seqn(csap_tst_s);
    for (i = 0; i < PACKETS_NUM; i++)
    {
        te_fill_buf(pkts[i].data, DATA_SIZE);
        pkts[i].seqn = next_seqn;
        next_seqn += DATA_SIZE;
    }

    for (i = 0; i < PACKETS_NUM; i++)
    {
        int j = i;

        if (i > 0 && i % ABNORMALITY_RATE == 0)
        {
            switch (rxq_problem)
            {
                case RXQ_PACKETS_LOST:
                    i++;
                    j = i;
                    break;

                case RXQ_PACKETS_REORDER:
                    sent_pkt_idxs[sent_pkts_num - 1] = i;
                    j = i - 1;
                    break;

                case RXQ_PACKETS_RETRANSMIT:
                    sent_pkt_idxs[sent_pkts_num] = i - ABNORMALITY_RATE;
                    sent_pkts_num++;
                    break;
            }
        }

        if (i >= PACKETS_NUM)
            break;
        sent_pkt_idxs[sent_pkts_num] = j;
        sent_pkts_num++;
    }

    TEST_STEP("Send prepared packets from TESTSER.");
    for (i = 0; i < sent_pkts_num; i++)
        CHECK_RC(tapi_tcp_send_msg(csap_tst_s,
                                   pkts[sent_pkt_idxs[i]].data,
                                   DATA_SIZE,
                                   TAPI_TCP_EXPLICIT,
                                   pkts[sent_pkt_idxs[i]].seqn,
                                   TAPI_TCP_AUTO, 0,
                                   NULL, 0));

    TEST_STEP("Check that moving connected IUT socket after that succeeds.");
    tapi_rpc_onload_set_stackname_create(pco_iut, ONLOAD_ALL_THREADS,
                                         ONLOAD_SCOPE_PROCESS, STACK_NAME,
                                         existing_stack, &iut_s_aux);

    restore_stack_name = TRUE;

    if (!tapi_rpc_onload_move_fd_check(pco_iut, iut_s,
                                       TAPI_MOVE_FD_SUCCESS_EXPECTED,
                                       STACK_NAME,
                                       "Calling onload_move_fd() on "
                                       "a socket with problematic RXQ"))
        TEST_STOP;

    TEST_STEP("Check that connected IUT socket received expected data.");
    received = rpc_recv(pco_iut, iut_s, received_data,
                        PACKETS_NUM * DATA_SIZE, 0);
    if ((rxq_problem == RXQ_PACKETS_LOST &&
         received != ABNORMALITY_RATE * DATA_SIZE) ||
        (rxq_problem != RXQ_PACKETS_LOST &&
         received != PACKETS_NUM * DATA_SIZE))
        RING_VERDICT("Unexpected number of bytes was received from "
                     "the peer");

    for (i = 0; i * DATA_SIZE < received; i++)
    {
        if (memcmp(received_data + i * DATA_SIZE,
                   pkts[i].data,
                   received - i * DATA_SIZE > DATA_SIZE ?
                      DATA_SIZE : received - i * DATA_SIZE) != 0)
            TEST_VERDICT("Corrupted data was received from the peer");
    }

    TEST_SUCCESS;

cleanup:

    if (restore_stack_name)
        rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL, init_stack_name);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_aux);
    if (csap_tst_s >= 0)
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(csap_tst_s));

    if (alien_neigh_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                                  iut_if->if_name,
                                                  tst_addr));
    if (alien_ip_route != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&alien_ip_route));

    TEST_END;
}
