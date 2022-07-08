/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/tcp/reorder  
 * Reordered TCP fragments
 */

/** @page attacks-tcp-reorder  Reordered TCP fragments
 *
 * @objective Check that reordering of TCP packets does
 *            not lead to loss or corruption of data.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_gw
 *
 * @par Scenario
 * -# Create TCP socket @p iut_s on the @p pco_iut and try to connect it to
 *    @p pco_iut address a port @p P.
 * -# Receive and send TCP/IP packets on @p pco_tst to emulate 
 *    establishing of the connection to the port @p P.
 * -# Create several correct TCP data packets, reorder them and send
 *    to @p pco_iut. Receive acknowledgement(s).
 * -# Receive data via @p iut_s socket and check that nothing is lost
 *    or corrupted.
 * -# Close @p iut_s.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "attacks/tcp/reorder"

#include "sockapi-test.h"

#define ETHER_ADDR_LEN (6)

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_tcp.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"
#include "ndn.h"

#define PROLOG_DATA_LEN 0x1000

#define REORDER_DATA_LEN 0x1000

#define MIN_SEGM_SIZE    500
#define MAX_SEGM_SIZE   1400

#define EPILOG_DATA_LEN 0x1000

#define NUM_REORDER 10

struct data_portion {
    size_t offset;
    size_t len;
};

static uint8_t *send_data;



int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    const struct sockaddr *gw_tst_lladdr = NULL;

    tapi_tcp_handler_t         tcp_conn = 0;

    int iut_srv = -1;
    int iut_acc = -1;

    size_t    sent = 0;

    int       i;
    int       num_fragments;
    size_t    prev_end;

    struct data_portion *fragments;
    tapi_tcp_pos_t       start_of_reordered_block;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_LINK_ADDR(gw_tst_lladdr);

    /* Configure connection between IUT and Tester through gateway host. */
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    CHECK_RC(tapi_route_gateway_configure(&gateway));
    CHECK_RC(tapi_route_gateway_break_gw_tst(&gateway));
    CFG_WAIT_CHANGES;

    send_data = malloc(REORDER_DATA_LEN);
    te_fill_buf(send_data, REORDER_DATA_LEN);

    num_fragments = REORDER_DATA_LEN / MIN_SEGM_SIZE + 1;
    fragments = calloc(num_fragments, sizeof(fragments[0]));

    /* Establish TCP connection */
    iut_srv = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_srv, SOCKTS_BACKLOG_DEF);

    CHECK_RC(tapi_tcp_init_connection(pco_tst->ta, TAPI_TCP_CLIENT,
                                  tst_addr, iut_addr, tst_if->if_name,
                                  (const uint8_t *)alien_link_addr->sa_data,
                                  (const uint8_t *)gw_tst_lladdr->sa_data,
                                  0, &tcp_conn));

    CHECK_RC(tapi_tcp_wait_open(tcp_conn, 3000));
    iut_acc = rpc_accept(pco_iut, iut_srv, NULL, NULL);

    sent = 0;
    while (sent < PROLOG_DATA_LEN)
    {
        size_t msg_len = 1024;

        if (msg_len > PROLOG_DATA_LEN - sent)
            msg_len = PROLOG_DATA_LEN - sent;

        CHECK_RC(tapi_tcp_send_msg(tcp_conn, send_data + sent, msg_len,
                                   TAPI_TCP_AUTO, 0, 
                                   TAPI_TCP_AUTO, 0,
                                   NULL, 0)); 

        rc = rpc_recv_verify(pco_iut, iut_acc, "aaa", 0);
        if (rc < 0)
            TEST_FAIL("recv_verify failed"); 

        sent += msg_len;
    }

    start_of_reordered_block = tapi_tcp_next_seqn(tcp_conn);

    prev_end = 0;
    for (i = 0; i < num_fragments; i++)
    {
        fragments[i].offset = prev_end; 
        fragments[i].len = rand_range(MIN_SEGM_SIZE, MAX_SEGM_SIZE);

        prev_end += fragments[i].len; 

        if (prev_end > REORDER_DATA_LEN)
        {
            fragments[i].len = REORDER_DATA_LEN - fragments[i].offset;
            prev_end = REORDER_DATA_LEN;
        }

        if (prev_end == REORDER_DATA_LEN)
            break;
    }

    num_fragments = i + 1; /*save real number of initialized fragments */

    for (i = 0; i < num_fragments - 1; i++)
    {
        struct data_portion tmp;
        int j = rand_range(i + 1, num_fragments - 1); 

        tmp = fragments[i];
        fragments[i] = fragments[j];
        fragments[j] = tmp;
    } 


    for (i = 0; i < num_fragments; i++)
    {
        RING("send %d-th fragment, offset %d, len %d", 
             i, fragments[i].offset, fragments[i].len);

        rc = tapi_tcp_send_msg(tcp_conn, send_data + fragments[i].offset, 
                               fragments[i].len, TAPI_TCP_EXPLICIT, 
                               start_of_reordered_block +
                                   fragments[i].offset, 
                                   TAPI_TCP_AUTO, 0,
                                   NULL, 0); 
        if (rc != 0)
            TEST_FAIL("send %d msg failured, %r", i, rc);
    }

    tapi_tcp_update_sent_seq(tcp_conn, REORDER_DATA_LEN);

    rc = rpc_recv_verify(pco_iut, iut_acc, "aaa", 0);
    if (rc < 0)
        TEST_FAIL("recv_verify failed"); 

    sent = 0;
    while (sent < EPILOG_DATA_LEN)
    {
        size_t msg_len = 1024;

        if (msg_len > EPILOG_DATA_LEN - sent)
            msg_len = EPILOG_DATA_LEN - sent;

        CHECK_RC(tapi_tcp_send_msg(tcp_conn, send_data + sent, msg_len,
                                   TAPI_TCP_AUTO, 0, 
                                   TAPI_TCP_AUTO, 0,
                                   NULL, 0)); 
        rc = rpc_recv_verify(pco_iut, iut_acc, "aaa", 0);
        if (rc < 0)
            TEST_FAIL("recv_verify failed"); 

        sent += msg_len;
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc);
    CLEANUP_RPC_CLOSE(pco_iut, iut_srv);

    if (tcp_conn != 0)
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));

    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
