/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-od_no_ack  OD send without ACK
 *
 * @objective  Check that OD send API retransmits data if no ACK is received.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param nonblock      Non-blocking send
 * @param raw_send      Use @b oo_raw_send() function to transmit data
 * @param small_portion Determines data portion size to attempt send with
 *                      OD send API
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/od_no_ack"

#include "sockapi-test.h"
#include "onload_rpc.h"
#include "od_send.h"
#include "te_ethernet.h"
#include "tapi_tcp.h"
#include "tapi_route_gw.h"

/** Data amount to be passed in one portion with OD send API if
 * @p small_portion is @c FALSE. */
#define BIG_PORTION 10000

/** Data amount to be passed in one portion with OD send API if
 * @p small_portion is @c TRUE. */
#define SMALL_PORTION 1000

/* Array length to keep received packets sequence numbers.  */
#define MAX_SEQN_ITER 100

/**
 * Check segment with such sequence number is not received yet.
 * 
 * @param seqn_got      Sequence number
 * @param seqn_got_list Sequence numbers list
 * 
 * @return @c FALSE if segment with such sequence number is already
 *         received.
 */
static te_bool
seqn_check(tapi_tcp_pos_t seqn_got, tapi_tcp_pos_t *seqn_got_list)
{
    static int seqn_iter = 0;
    int i;

    for (i = 0; i <= seqn_iter; i++)
        if (seqn_got_list[i] == seqn_got)
            return FALSE;

    seqn_iter++;
    if (seqn_iter == MAX_SEQN_ITER)
        TEST_FAIL("Sequence numbers list is overfilled");

    seqn_got_list[seqn_iter] = seqn_got;

    return TRUE;
}

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;
    const struct sockaddr     *tst_fake_addr = NULL;

    te_bool raw_send = TRUE;
    te_bool small_portion = TRUE;
    te_bool nonblock = TRUE;

    uint8_t   *sendbuf   = NULL;
    uint8_t   *recvbuf   = NULL;
    int        iut_s     = -1;
    int        iut_srv_s = -1;
    int        raw_socket = -1;
    int        recvbuf_len;
    int        length;
    int        counter;
    int        offt;
    int        sent;
    size_t     len;

    const struct sockaddr     *alien_link_addr = NULL;
    struct sockaddr            iut_mac;
    tapi_tcp_handler_t         tcp_conn = 0;
    tapi_tcp_pos_t             seqn_got;
    tapi_tcp_pos_t             seqn_got_list[MAX_SEQN_ITER];
    uint8_t                    flags = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);

    TEST_GET_BOOL_PARAM(raw_send);
    TEST_GET_BOOL_PARAM(small_portion);
    TEST_GET_BOOL_PARAM(nonblock);

    length = small_portion ? SMALL_PORTION : BIG_PORTION;
    sendbuf = te_make_buf_by_len(length);
    recvbuf_len = length * 2;
    recvbuf = te_make_buf_by_len(recvbuf_len);
    memset(seqn_got_list, 0, sizeof(seqn_got_list));

    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_fake_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    CFG_WAIT_CHANGES;

    if (raw_send)
    {
        raw_socket = rpc_socket(pco_iut, RPC_AF_PACKET, RPC_SOCK_RAW,
                                RPC_IPPROTO_RAW);
    }

    CHECK_RC(tapi_cfg_base_if_get_link_addr(pco_iut->ta, iut_if->if_name,
                                            &iut_mac));

    TEST_STEP("Create TCP CSAP on tester.");
    CHECK_RC(tapi_tcp_create_conn(pco_tst->ta,
                                  (struct sockaddr *)tst_fake_addr,
                                  (struct sockaddr *)iut_addr,
                                  tst_if->if_name,
                                  (const uint8_t *)alien_link_addr->sa_data,
                                  (uint8_t *)iut_mac.sa_data,
                                  0, &tcp_conn));
    /* Wait for the interface to switch to promisuous mode. */
    TAPI_WAIT_NETWORK;

    TEST_STEP("Create listener TCP socket on IUT.");
    iut_srv_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_srv_s, iut_addr);
    rpc_listen(pco_iut, iut_srv_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Imitate TCP connection establishment with the IUT "
              "listening socket.");
    CHECK_RC(tapi_tcp_start_conn(tcp_conn, TAPI_TCP_CLIENT));

    CHECK_RC(tapi_tcp_wait_open(tcp_conn, 3000));

    TEST_STEP("Accept connection on IUT.");
    iut_s = rpc_accept(pco_iut, iut_srv_s, NULL, NULL); 

    TEST_STEP("Send data packet from IUT using OD send API.");
    if (!nonblock && !small_portion)
        pco_iut->op = RCF_RPC_CALL;
    sent = od_send(pco_iut, iut_s, sendbuf, length,
                   nonblock ? RPC_MSG_DONTWAIT : 0, raw_send,
                   iut_if->if_index, raw_socket);

    TEST_STEP("Wait a bit to make sure that data packets are delivered.");
    TAPI_WAIT_NETWORK;

    TEST_STEP("Read all data on tester.");
    counter = 0;
    offt = 0;
    do {
        len = recvbuf_len - offt;
        
        rc = tapi_tcp_recv_msg(tcp_conn, 0, TAPI_TCP_AUTO, recvbuf + offt,
                               &len, &seqn_got, NULL, &flags);
        if (rc == 0 && len > 0 && seqn_check(seqn_got, seqn_got_list) &&
            flags != (TCP_ACK_FLAG | TCP_SYN_FLAG))
            offt += len;

        if (rc != 0 && rc != TE_RC(TE_TAPI, TE_ETIMEDOUT))
            TEST_VERDICT("Receiving failed with unexpected error %r", rc);

        TEST_STEP("Wait two seconds for possible packets.");
        if (counter < 20 && rc != 0)
        {
            counter++;
            MSLEEP(100);
            rc = 0;
        }
        else
            counter = 0;
    } while (rc == 0);

    if (!nonblock && !small_portion)
    {
        sent = od_send(pco_iut, iut_s, sendbuf, length, 0, raw_send,
                       iut_if->if_index, raw_socket);
    }

    TEST_STEP("Sent and received data must be equal.");
    if (sent != offt || memcmp(sendbuf, recvbuf, sent) != 0)
    {
        ERROR("Data mismatch: sent=%d received=%d memcmp=%d", sent, offt,
              memcmp(sendbuf, recvbuf, sent));
        TEST_VERDICT("Received and sent data are different");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_srv_s);

    if (raw_send)
        CLEANUP_RPC_CLOSE(pco_iut, raw_socket);

    free(sendbuf);
    free(recvbuf);

    if (tcp_conn != 0)
    {
        CLEANUP_CHECK_RC(tapi_tcp_send_ack(tcp_conn,
                                           tapi_tcp_next_ackn(tcp_conn)));
        CLEANUP_CHECK_RC(tapi_tcp_send_fin_ack(tcp_conn, 2000));
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));
    }
    if (pco_iut != NULL)
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_iut->ta, 
                                                    iut_if->if_name));

    TEST_END;
}
