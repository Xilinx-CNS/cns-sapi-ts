/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page basic-mtu_usage Checking MTU usage and jumbo frames
 *
 * @objective Check that packets of full MTU size are sent
 *            and that jumbo frames are processed correctly
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param mtu_size  MTU to be set:
 *                  - 576
 *                  - 1280
 *                  - 1500
 *                  - 6500
 *                  - 7000
 *                  - 9000
 * @param data_len   Data length to be sent (in terms of MTUs):
 *                  - 0.8
 *                  - 1.5
 * @param iut_send  Whether IUT or Tester should send data:
 *                  - TRUE: send from IUT
 *                  - FALSE: send from tester, iteration is disabled as
 *                           useless for Onload.
 *
 * @par Test sequence:
 * -# Set MTU to @p mtu_size on both @p iut_if and @p tst_if.
 * -# Set @p pco_snd (sending data RPC server) and @p pco_rcv
 *    (RPC server receiving data) according to @p iut_send.
 * -# Create a pair of connected sockets @p snd_s on @p pco_snd
 *    and @p rcv_s on @p pco_rcv of type @p sock_type.
 * -# Send some data from @p snd_s.
 * -# Check that ethernet frames with payload of @p mtu_size
 *    length are sent (except the last one possibly).
 * -# Check that data was received correctly.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/mtu_usage"

#include "sockapi-test.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "te_ethtool.h"

/* Next header field offset within IPv6 header */
#define NEXTHDR_OFFS    6

/* Next header field value for ICMPv6 */
#define NEXTHDR_ICMP    58

#define MAX_MTU 9000

static int      mtu_size;
static int      too_big_cnt = 0;
static int      too_small_cnt = 0;
static double   total_size = 0;
static double   small_total_size = 0;
static double   big_total_size = 0;
static te_bool  last_packet = FALSE;
static uint32_t last_small_length = 0;
te_bool         is_failed = FALSE;
int             pkt_num = 0;
uint32_t       *payload_seq = NULL;
int             max_num = 0;
rpc_socket_type sock_type;

static void
eth_callback(const asn_value *packet, int layer,
             const ndn_eth_header_plain *header,
             const uint8_t *payload, uint16_t plen, void *userdata)
{
    int      i;
    uint32_t ip_hdr_len = 0;
    int      ip_ver = 0;

    UNUSED(packet);
    UNUSED(layer);
    UNUSED(header);
    UNUSED(userdata);

    /* CSAP may catch ICMPv6 packet, so we have to ignore it. */
    if (header->len_type == ETHERTYPE_IPV6 &&
        payload[NEXTHDR_OFFS] == NEXTHDR_ICMP)
    {
        RING("ICMPv6 packet was catched.");
        return;
    }

    if (sock_type == RPC_SOCK_STREAM && pkt_num >= max_num)
    {
        max_num = (max_num + 1) * 2;
        payload_seq = realloc(payload_seq, max_num * sizeof(*payload_seq));
    }

    pkt_num++;

    if (sock_type == RPC_SOCK_STREAM)
    {
        ip_ver = payload[0] >> 4;
        ip_hdr_len = ip_ver == 4 ? (payload[0] & 0xF) * 4 :
                                   SOCKTS_IPV6_HDR_LEN;
        if (plen < ip_hdr_len + 8)
            TEST_FAIL("Too small payload length");

        payload_seq[pkt_num - 1] =
                      (((int)payload[ip_hdr_len + 4]) << 24) +
                      (((int)payload[ip_hdr_len + 5]) << 16) +
                      (((int)payload[ip_hdr_len + 6]) << 8) +
                      (((int)payload[ip_hdr_len + 7]));

        for (i = 0; i < pkt_num - 1; i++)
            if (payload_seq[i] == payload_seq[pkt_num - 1])
            {
                RING("Retransmitted packet was encountered and ignored");
                pkt_num--;
                return;
            }
    }

    total_size += plen;
    RING("Packet %d: length %d", pkt_num, plen);

    last_packet = FALSE;

    if (plen != (unsigned int)mtu_size)
    {
        if (plen < (unsigned int)mtu_size)
        {
            too_small_cnt++;
            small_total_size += plen;
            last_small_length = plen;
            last_packet = TRUE;
        }
        else
        {
            too_big_cnt++;
            big_total_size += plen;
        }
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *tst_addr = NULL;
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;
    const struct sockaddr       *iut_lladdr;
    const struct sockaddr       *tst_lladdr;

    rcf_rpc_server              *pco_snd = NULL;
    rcf_rpc_server              *pco_rcv = NULL;
    const struct sockaddr       *snd_addr = NULL;
    const struct sockaddr       *rcv_addr = NULL;
    int                          csap_recv_mode = 0;
    const uint8_t               *csap_local_addr = NULL;
    const uint8_t               *csap_remote_addr = NULL;

    int                 snd_s;
    int                 rcv_s;
    int                 accept_s      = -1;
    char               *rcv_buf = NULL; 
    char               *snd_buf = NULL; 
    int                 received;
    int                 sent;
    te_saved_mtus       iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus       tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);
    csap_handle_t       csap = CSAP_INVALID_HANDLE;
    int                 sid;
    unsigned int        received_packets;
    te_bool             readable = FALSE;
    int                 opt_val;
    int                 buf_len;
    double              data_len = 0;
    te_bool             iut_send = FALSE;
    uint16_t            ether_type;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_IF(tst_if);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_INT_PARAM(mtu_size);
    TEST_GET_DOUBLE_PARAM(data_len);
    TEST_GET_BOOL_PARAM(iut_send);
    TEST_GET_SOCK_TYPE(sock_type);

    buf_len = mtu_size * data_len;
    snd_buf = te_make_buf_by_len(buf_len);
    rcv_buf = te_make_buf_by_len(buf_len);

    ether_type = rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET6 ?
                 ETHERTYPE_IPV6 : ETHERTYPE_IP;

    /* Reset ARP dynamic entries */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr));
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      iut_addr));

    CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                    mtu_size, &iut_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                    mtu_size, &tst_mtus));

    CFG_WAIT_CHANGES;

    if (iut_send)
    {
        pco_snd = pco_iut;
        pco_rcv = pco_tst;
        snd_addr = iut_addr;
        rcv_addr = tst_addr;
        csap_recv_mode = TAD_ETH_RECV_HOST | TAD_ETH_RECV_NO_PROMISC;
        csap_remote_addr = (const uint8_t *)iut_lladdr->sa_data;
        csap_local_addr = (const uint8_t *)tst_lladdr->sa_data;
    }
    else
    {
        pco_snd = pco_tst;
        pco_rcv = pco_iut;
        snd_addr = tst_addr;
        rcv_addr = iut_addr;
        csap_recv_mode = TAD_ETH_RECV_OUT | TAD_ETH_RECV_NO_PROMISC;
        csap_remote_addr = (const uint8_t *)tst_lladdr->sa_data;
        csap_local_addr = (const uint8_t *)iut_lladdr->sa_data;
    }

    /*
     * Offload should be disabled.
     */
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                          pco_tst->ta, tst_if->if_name,
                                          "tx-tcp-segmentation", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                          pco_tst->ta, tst_if->if_name,
                                          "tx-generic-segmentation", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                          pco_tst->ta, tst_if->if_name,
                                          "rx-gro", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                          pco_tst->ta, tst_if->if_name,
                                          "rx-lro", 0));

    snd_s = rpc_socket(pco_snd, rpc_socket_domain_by_addr(snd_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_snd, snd_s, snd_addr);
    rcv_s = rpc_socket(pco_rcv, rpc_socket_domain_by_addr(rcv_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_rcv, rcv_s, rcv_addr);

    rpc_getsockopt(pco_rcv, rcv_s, RPC_SO_RCVBUF, &opt_val);
    if (opt_val < buf_len * 2)
    {
        opt_val = buf_len;
        rpc_setsockopt(pco_rcv, rcv_s, RPC_SO_RCVBUF, &opt_val);
    }

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_snd, snd_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_rcv, rcv_s, snd_addr);
        accept_s = rpc_accept(pco_snd, snd_s, NULL, NULL);
        RPC_CLOSE(pco_snd, snd_s);
        snd_s = accept_s;
    }
    else
    {
        rpc_connect(pco_rcv, rcv_s, snd_addr);
        rpc_connect(pco_snd, snd_s, rcv_addr);
    }

    TAPI_WAIT_NETWORK;

    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));
    CHECK_RC(
        tapi_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                             csap_recv_mode, csap_remote_addr,
                             csap_local_addr, &ether_type, &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));

    pco_snd->op = RCF_RPC_CALL;
    rpc_send(pco_snd, snd_s, snd_buf, buf_len, 0);
    received = 0;

    RPC_GET_READABILITY(readable, pco_rcv, rcv_s,
                        pco_rcv->def_timeout / 2);
    
    rc = 0;
    do {
        received += rc;
        TAPI_WAIT_NETWORK;
        RPC_AWAIT_IUT_ERROR(pco_rcv);
        rc = rpc_recv(pco_rcv, rcv_s, rcv_buf, buf_len,
                      RPC_MSG_DONTWAIT);
    } while (rc >= 0);

    pco_snd->op = RCF_RPC_WAIT;
    sent = rpc_send(pco_snd, snd_s, snd_buf, buf_len, 0);

    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid, csap,
                                  tapi_eth_trrecv_cb_data(eth_callback,
                                                          NULL),
                                  &received_packets));

    if (last_packet)
    {
        too_small_cnt--;
        small_total_size -= last_small_length;
    }

    if (too_big_cnt > 0 || too_small_cnt > 0)
    {
        is_failed = TRUE;

        if (too_big_cnt > 0)
        {
            ERROR_VERDICT("%s part of ethernet packets is too big: "
                          "they are %s more than MTU in average",
                          (double)too_big_cnt /
                            (double)received_packets < 0.3 ?
                                            "Small" : "Large",
                          ((double)big_total_size / (double)too_big_cnt -
                            (double)mtu_size) / (double)mtu_size < 0.3 ?
                                            "a bit" : "significantly");

            RING("Too big ethernet packets were encountered:"
                 "count is %d (%.f%%), medium size is %.2f "
                 "more than MTU",
                 too_big_cnt,
                 (double)too_big_cnt /
                            (double)received_packets * 100.0,
                  big_total_size / too_big_cnt - mtu_size);

        }

        if (too_small_cnt > 0)
        {
            ERROR_VERDICT("%s part of ethernet packets is too small: "
                          "they are %s less than MTU in average",
                          (double)too_small_cnt /
                            (double)received_packets < 0.3 ?
                                            "Small" : "Large",
                          ((double)mtu_size -
                           (double)small_total_size /
                                        (double)too_small_cnt) /
                                            (double)mtu_size < 0.3 ?
                                            "a bit" : "significantly");

            RING("Too small ethernet packets were encountered:"
                 "count is %d (%.f%%), medium size is %.2f "
                 "less than MTU",
                 too_small_cnt,
                 (double)too_small_cnt /
                            (double)received_packets * 100.0,
                  mtu_size - small_total_size / too_small_cnt);
        }
    }

    if (sent == 0)
        TEST_VERDICT("Data was not sent");
    if (sent < buf_len)
        TEST_VERDICT("Not all data was sent");
    else if (received == 0)
        TEST_VERDICT("Data was not received");
    else if (received < sent)
        TEST_VERDICT("Not all data was received");
    else if (received > sent)
        TEST_FAIL("Impossible is possible...");

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    free(payload_seq);

    free(snd_buf);
    free(rcv_buf);

    tapi_tad_csap_destroy(pco_tst->ta, sid, csap);

    CLEANUP_RPC_CLOSE(pco_snd, snd_s);
    CLEANUP_RPC_CLOSE(pco_rcv, rcv_s);

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    TEST_END;
}
