/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP protocol special cases
 */

/**
 * @page tcp-syn_bad_addr Receiving SYN with incorrect source address
 *
 * @objective Send from tester SYN with incorrect source address and check that
 *            IUT drops it
 *
 * @param env     Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param tst_src_addr_type Type of source address to use:
 *      - dest (Source address is the same as destination)
 *      - all0 (Source address contains all zeros)
 *      - all1 (Source address contains all non-zeros)
 *      - loopback (Source address is loopback address)
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/syn_bad_addr"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

/* Values of tester source address type */
typedef enum {
    ADDR_TYPE_DEST,         /*< Source address is the same as destination */
    ADDR_TYPE_ALL0,         /*< Source address contains all zeros */
    ADDR_TYPE_ALL1,         /*< Source address contains all non-zeros */
    ADDR_TYPE_LOOPBACK,     /*< Source address is loopback address */
} address_type;

#define ADDR_TYPE_VALUES   \
    { "dest",       ADDR_TYPE_DEST },     \
    { "all0",       ADDR_TYPE_ALL0 },     \
    { "all1",       ADDR_TYPE_ALL1 },     \
    { "loopback",   ADDR_TYPE_LOOPBACK }

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *tst_addr = NULL;
    const struct sockaddr       *alien_link_addr = NULL;
    const struct sockaddr       *iut_lladdr = NULL;
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;
    int                          iut_s = -1;
    int                          acc_s = -1;
    int                          tst_s = -1;
    tapi_tcp_handler_t           tcp_conn = 0;
    struct sockaddr             *tst_src_addr = NULL;
    csap_handle_t                tst_recv_csap = CSAP_INVALID_HANDLE;
    unsigned int                 num_rx_packets = 0;
    address_type                 tst_src_addr_type;
    char                         addr_all1[sizeof(struct in6_addr)];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_ENUM_PARAM(tst_src_addr_type, ADDR_TYPE_VALUES);

    memset(addr_all1, 0xFF, sizeof(addr_all1));

    CHECK_RC(tapi_sockaddr_clone2(tst_addr, &tst_src_addr));

    switch (tst_src_addr_type)
    {
        case ADDR_TYPE_DEST:
            tapi_sockaddr_clone_exact(iut_addr, SS(tst_src_addr));
            break;
        case ADDR_TYPE_ALL0:
            te_sockaddr_set_wildcard(tst_src_addr);
            break;
        case ADDR_TYPE_ALL1:
            te_sockaddr_set_netaddr(tst_src_addr, addr_all1);
            break;
        case ADDR_TYPE_LOOPBACK:
            te_sockaddr_set_loopback(tst_src_addr);
            break;
    }

    TEST_STEP("Create IUT socket, bind it and listen.");
    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, FALSE, iut_addr);

    TEST_STEP("Create CSAP on tester to receive TCP packets, "
              "start listening.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name,
        TAD_ETH_RECV_DEF, NULL,
        (const uint8_t *)iut_lladdr->sa_data, tst_addr->sa_family,
        TAD_SA2ARGS(tst_src_addr, NULL), &tst_recv_csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, tst_recv_csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Create CSAP on tester to send TCP packets.");
    CHECK_RC(tapi_tcp_create_conn(pco_tst->ta, tst_src_addr, iut_addr,
                                  tst_if->if_name,
                                  (const uint8_t *)alien_link_addr->sa_data,
                                  (const uint8_t *)iut_lladdr->sa_data,
                                  TAPI_TCP_DEF_WINDOW, &tcp_conn));

    TEST_STEP("Send SYN segment to IUT with a source address "
              "according to @p address.");
    /*
     * In case of IPv4 we cannot use all-zero local address in CSAP -
     * tapi_tcp_ip4_eth_csap_create() does not allow it. So, we perform
     * it by generating corresponding template by hands.
     */
    if (tst_src_addr_type == ADDR_TYPE_ALL0 && iut_addr->sa_family == AF_INET)
    {
        asn_value *syn_template = NULL;
        int        rc = 0;

        CHECK_RC(tapi_tcp_template(false, tapi_tcp_first_seqn_sent(tcp_conn),
                                   0, TRUE, FALSE, NULL, 0, &syn_template));

        rc = asn_write_int32(syn_template, 0,
                             "pdus.1.#ip4.src-addr.#plain");
        if (rc != 0)
        {
            asn_free_value(syn_template);
            TEST_FAIL("Failed to write source address to template "
                      "(%r)", rc);
        }

        rc = tapi_tcp_send_template(tcp_conn, syn_template,
                                    RCF_MODE_BLOCKING);
        if (rc != 0)
        {
            asn_free_value(syn_template);
            TEST_FAIL("Failed to send template (%r)", rc);
        }
    }
    else
    {
        CHECK_RC(tapi_tcp_start_conn(tcp_conn, TAPI_TCP_CLIENT));
    }

    TEST_STEP("Check that receiver CSAP on tester catches nothing back "
              "from IUT.");
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, tst_recv_csap, NULL,
                                  &num_rx_packets));
    if (num_rx_packets != 0)
        TEST_VERDICT("A packet from IUT was received");

    TEST_STEP("Establish a new connection and check it "
              "by sending/receiving data.");
    tst_s = rpc_stream_client(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                              RPC_PROTO_DEF, tst_addr);
    rpc_connect(pco_tst, tst_s, iut_addr);
    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
    sockts_test_connection(pco_iut, acc_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (tst_recv_csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                               tst_recv_csap));

    if (tcp_conn != 0)
        CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));

    free(tst_src_addr);

    TEST_END;
}
