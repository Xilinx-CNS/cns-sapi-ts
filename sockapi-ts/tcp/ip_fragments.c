/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Test attacks/ip/frag_lost
 * Flood of large packets with lost fragments
 */

/** @page tcp-ip_fragments TCP message splitted to IP fragments
 *
 * @objective Check that TCP messages splitted to more then one
 *            IP fragment will be processed by IUT TCP stack.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param frag_len      Length of IPv6 fragment payload,
 *                      in bytes
 *
 * @par Scenario
 * -# Create stream connection between @p pco_iut and @p pco_tst.
 * -# Send from @p pco_tst sinble IP packet with TCP message,
 *    check that respective data are received from socket on IUT.
 * -# Send from @p pco_tst TCP message in more then one IP fragments,
 *    check that respective data are received from socket on IUT.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/ip_fragments"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "te_time.h"
#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_tcp.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"

/*
 * Note: fragment length must be divisible by 8, because
 * fragment offset in IP header is specified in 8-octet units,
 * not in bytes.
 */
#define FRAG_LEN          64            /**< Length of fragment payload */
#define TCP_HDR_LEN       20            /**< TCP header length in bytes */
#define IP_HDR_LEN        20            /**< IP header length in bytes */
#define IP6_FRAG_HDR_LEN  8             /**< Length of IPv6 Fragment
                                             extension header in bytes */

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_fake_addr = NULL;
    const struct sockaddr *alien_link_addr = NULL;

    int iut_srv = -1;
    int iut_acc = -1;
    int num;
    int retries = 3;

    uint8_t mac_iut[ETHER_ADDR_LEN];

    char *tx_buf = NULL;
    char *rx_buf = NULL;

    tapi_tcp_pos_t seqn;
    int            frag_len;
    size_t         full_size;
    size_t         single_size;
    size_t         buf_size;

    tapi_ip_frag_spec frags[2] = { {0, }, };

    char oid[RCF_MAX_ID];

    tapi_tcp_handler_t tcp_conn = 0;
    struct timeval     tv;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_INT_PARAM(frag_len);

    tapi_ip_frag_specs_init(frags, TE_ARRAY_LEN(frags));
    frags[0].more_frags = TRUE;
    frags[1].more_frags = FALSE;
    frags[0].real_length = frag_len;
    frags[1].real_length = frag_len;
    frags[1].hdr_offset = frag_len;
    frags[1].real_offset = frag_len;
    if (iut_addr->sa_family == AF_INET)
    {
        frags[0].hdr_length = frag_len + IP_HDR_LEN;
        frags[1].hdr_length = frag_len + IP_HDR_LEN;
    }
    else
    {
        frags[0].hdr_length = frag_len + IP6_FRAG_HDR_LEN;
        frags[1].hdr_length = frag_len + IP6_FRAG_HDR_LEN;
    }

    /*
     * This is done to ensure that in each iteration of this
     * test fragments have different ID, so that iterations
     * do not interfere with each other.
     */
    CHECK_RC(te_gettimeofday(&tv, NULL));
    frags[0].id = frags[1].id = (tv.tv_sec % 100) * 100 +
                                (tv.tv_usec / 10000);

    full_size = frag_len * TE_ARRAY_LEN(frags) - TCP_HDR_LEN;
    buf_size = full_size * 2;
    tx_buf = te_make_buf_by_len(buf_size);
    rx_buf = te_make_buf_by_len(buf_size);
    single_size = MIN(full_size, SOCKTS_MSG_STREAM_MAX);

    sprintf(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, mac_iut) != 0)
        TEST_STOP;

    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_fake_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    CFG_WAIT_CHANGES;

    /* Establish TCP connection */
    iut_srv = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                         RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_srv, iut_addr);
    rpc_listen(pco_iut, iut_srv, SOCKTS_BACKLOG_DEF);

    CHECK_RC(tapi_tcp_init_connection(pco_tst->ta, TAPI_TCP_CLIENT,
                                      tst_fake_addr, iut_addr,
                                      tst_if->if_name,
                                      (const uint8_t *)alien_link_addr->sa_data,
                                      mac_iut,
                                      0, &tcp_conn));
    CHECK_RC(tapi_tcp_wait_open(tcp_conn, 10000));
    iut_acc = rpc_accept(pco_iut, iut_srv, NULL, NULL);

    CHECK_RC(tapi_tcp_send_msg(tcp_conn, (uint8_t *)tx_buf,
                               single_size,
                               TAPI_TCP_AUTO, 0,
                               TAPI_TCP_AUTO, 0,
                               NULL, 0));
    num = rpc_recv(pco_iut, iut_acc, rx_buf, buf_size, 0);
    if (num != (int)single_size ||
        memcmp(rx_buf, tx_buf, num) != 0)
    {
        TEST_VERDICT("Unexpected data is received after sending "
                     "non-fragmented TCP packet");
    }

    te_fill_buf(tx_buf, buf_size);
    seqn = tapi_tcp_next_seqn(tcp_conn);
    do {
        CHECK_RC(tapi_tcp_send_msg(tcp_conn, (uint8_t *)tx_buf,
                                   full_size,
                                   TAPI_TCP_EXPLICIT, seqn,
                                   TAPI_TCP_AUTO, 0,
                                   frags, TE_ARRAY_LEN(frags)));
        memset(rx_buf, 0, buf_size);
        TAPI_WAIT_NETWORK;

        RPC_AWAIT_IUT_ERROR(pco_iut);
        num = rpc_recv(pco_iut, iut_acc, rx_buf, buf_size,
                       RPC_MSG_DONTWAIT);
        if (num < 0)
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "recv() failed");
        retries--;
    } while (num < 0 && retries > 0);

    if (retries == 0 && num < 0)
    {
        TEST_VERDICT("Fragmented TCP packet was not received after "
                     "a number of retransmissions");
    }

    /* data was sent and acked. */
    tapi_tcp_update_sent_seq(tcp_conn, full_size);

    if (num != (int)full_size)
    {
        TEST_VERDICT("Unexpected number of bytes is received after "
                     "sending fragmented TCP packet");
    }

    if (memcmp(rx_buf, tx_buf, full_size) != 0)
    {
        TEST_VERDICT("Unexpected data is received after "
                     "sending fragmented TCP packet");
    }

    TEST_SUCCESS;

cleanup:
    if (tcp_conn != 0)
    {
        CLEANUP_CHECK_RC(tapi_tcp_send_fin(tcp_conn, 5000));
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_srv);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc);

    CLEANUP_CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name,
                                     pco_tst->ta, tst_if->if_name,
                                     tst_fake_addr, NULL, FALSE));
    CFG_WAIT_CHANGES;

    if (pco_iut != NULL && tst_fake_addr != NULL)
    {
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                                  iut_if->if_name,
                                                  tst_fake_addr));
    }

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
