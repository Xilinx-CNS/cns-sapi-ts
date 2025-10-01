/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * Source address in the first resolution of ARP request
 */

/**
 * @page arp-sa_first_arp_request Source address in the first resolution of ARP request
 *
 * @objective Check source address and destination MAC in ARP request
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_two_nets.iut_first
 * @param sock_type Socket type:
 *      - @c udp
 *      - @c udp_notconn
 *      - @c tcp_active
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "arp/sa_first_arp_request"

#include "sockapi-test.h"
#include "tapi_arp.h"

static const uint8_t mac_broadcast[ETHER_ADDR_LEN] =
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/**
 * Structure used to store results of processing
 * packets sent from IUT and captured by a CSAP.
 */
typedef struct arp_handler_ctx {
    struct sockaddr *source_addr;
    te_bool failed;
    te_bool correct;
} arp_handler_ctx;

/**
 * Process ARP packets sent by IUT.
 *
 * @param pkt         Captured packet.
 * @param userdata    Pointer to arp_handler_ctx structure.
 */
static void
arp_handler(asn_value *pkt, void *userdata)
{
    arp_handler_ctx *ctx = (arp_handler_ctx *)userdata;
    te_errno rc;
    size_t eth_len = ETHER_ADDR_LEN;
    uint8_t dst_mac[ETHER_ADDR_LEN];
    uint8_t *source_addr;
    uint32_t proto_size;
    size_t addr_len;
    int rv;

    rc = asn_read_uint32(pkt, &proto_size,
                         "pdus.0.#arp.proto-size.#plain");
    if (rc != 0)
    {
        ERROR("Failed to read ARP PROTO-SIZE");
        ctx->failed = TRUE;
        goto cleanup;
    }

    addr_len = te_netaddr_get_size(ctx->source_addr->sa_family);
    if (proto_size != (uint32_t)addr_len)
    {
        ERROR("ARP PROTO-SIZE does't match with the size of the source address");
        ctx->failed = TRUE;
        goto cleanup;
    }

    source_addr = tapi_calloc(1, addr_len);
    rc = asn_read_value_field(pkt, source_addr, &addr_len,
                              "pdus.0.#arp.snd-proto-addr.#plain");
    if (rc != 0)
    {
        ERROR("Failed to read ARP SND-PROTO-ADDR");
        ctx->failed = TRUE;
        goto cleanup;
    }

    rc = asn_read_value_field(pkt, dst_mac, &eth_len,
                              "pdus.1.#eth.dst-addr.#plain");
    if (rc != 0)
    {
        ERROR("Failed to read ETH DST-ADDR");
        ctx->failed = TRUE;
        goto cleanup;
    }

    rv = memcmp(te_sockaddr_get_netaddr(ctx->source_addr), source_addr, addr_len);
    if (rv != 0)
    {
        ERROR_VERDICT("Incorrect source IP address");
        ctx->correct = FALSE;
        goto cleanup;
    }

    rv = memcmp(dst_mac, mac_broadcast, ETHER_ADDR_LEN);
    if (rv != 0)
    {
        ERROR_VERDICT("Destination MAC address must be broadcast");
        ctx->correct = FALSE;
        goto cleanup;
    }

cleanup:
    free(source_addr);
    asn_free_value(pkt);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *iut_if2 = NULL;
    const struct if_nameindex *tst1_if = NULL;
    sockts_socket_type sock_type;

    int iut_s = -1;
    int tst_s = -1;
    int accept_sock = -1;
    csap_handle_t tst_csap;
    void *tx_buf = NULL;
    size_t tx_buf_len = 128;
    uint16_t opcode = ARPOP_REQUEST;
    asn_value *pkt_pattern = NULL;
    int pkt_nums;

    tapi_tad_trrecv_cb_data cb;
    arp_handler_ctx arp_ctx;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    tx_buf = te_make_buf_by_len(tx_buf_len);

    TEST_STEP("Remove ARP entries on @p iut_if1 iterface about @p tst1_addr "
              "to provoke ARP resolution.");
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if1->if_name,
                                      tst1_addr));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create CSAP on Tester for ARP packets.");
    CHECK_RC(tapi_arp_eth_csap_create_ip4(pco_tst1->ta, 0, tst1_if->if_name,
                                          (TAD_ETH_RECV_DEF &
                                           ~TAD_ETH_RECV_OTHER) |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          NULL, NULL, &tst_csap));

    CHECK_RC(tapi_arp_add_pdu_eth_ip4(&pkt_pattern, TRUE,
                                      &opcode, NULL, NULL, NULL,
                                      te_sockaddr_get_netaddr(tst1_addr)));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst1->ta, 0, tst_csap, pkt_pattern,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Create socket @b iut_s of type @p sock_type "
              "and bind it to @p iut_addr2");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr2),
                       sock_type_sockts2rpc(sock_type), RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr2);

    TEST_STEP("On Tester add a route to @p iut_addr2 over @p tst1_if "
              "with gateway @p iut_addr1");
    CHECK_RC(tapi_cfg_add_route(pco_tst1->ta, iut_addr1->sa_family,
                                te_sockaddr_get_netaddr(iut_addr2),
                                te_netaddr_get_bitsize(iut_addr1->sa_family),
                                te_sockaddr_get_netaddr(iut_addr1),
                                tst1_if->if_name,
                                NULL,
                                0, 0, 0, 0, 0, 0, NULL));
    CFG_WAIT_CHANGES;

    TEST_STEP("Provoke ARP resolution. Create connection or send packet "
              "from @p iut_addr2 to @p tst1_addr");
    switch(sock_type)
    {
        case SOCKTS_SOCK_UDP_NOTCONN:
            TEST_SUBSTEP("If @p sock_type is @c SOCKTS_SOCK_UDP_NOTCONN "
                         "call sendto()");
            rpc_sendto(pco_iut, iut_s, tx_buf, tx_buf_len, 0, tst1_addr);
            break;

        case SOCKTS_SOCK_UDP:
            TEST_SUBSTEP("If @p sock_type is @c SOCKTS_SOCK_UDP "
                         "call connect() and send()");
            rpc_connect(pco_iut, iut_s, tst1_addr);
            rpc_send(pco_iut, iut_s, tx_buf, tx_buf_len, 0);
            break;

        case SOCKTS_SOCK_TCP_ACTIVE:
        {
            TEST_SUBSTEP("If @p sock_type is @c SOCKTS_SOCK_TCP_ACTIVE "
                         "establish TCP connection");
            tst_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                               sock_type_sockts2rpc(sock_type), RPC_PROTO_DEF);
            rpc_bind(pco_tst1, tst_s, tst1_addr);
            rpc_listen(pco_tst1, tst_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_iut, iut_s, tst1_addr);
            accept_sock = rpc_accept(pco_tst1, tst_s, NULL, NULL);
            break;
        }
    }
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that source IP from ARP request corresponds @p iut_addr2 "
              "and destination MAC address corresponds broadcast MAC address.");

    memset(&arp_ctx, 0, sizeof(arp_ctx));
    arp_ctx.source_addr = iut_addr2;
    arp_ctx.failed = FALSE;
    arp_ctx.correct = TRUE;

    cb.callback = &arp_handler;
    cb.user_data = &arp_ctx;
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst1->ta, 0, tst_csap, &cb,
                                  &pkt_nums));
    if (pkt_nums < 1)
        TEST_VERDICT("No ARP requests was received");
    else if (pkt_nums > 1)
        TEST_VERDICT("Multiple ARP requests were received");

    if (arp_ctx.failed)
        TEST_FAIL("Failed to parse ARP packets sent from IUT");
    if (!arp_ctx.correct)
        /* Some sensible verdict have already been printed in CSAP callback function */
        TEST_FAIL("The package does not contain the expected data");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, accept_sock);
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0, tst_csap));
    free(tx_buf);
    TEST_END;
}
