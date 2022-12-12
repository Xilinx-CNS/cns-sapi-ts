/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP protocol special cases
 */

/**
 * @page tcp-syn_resend Passive connection establishment with broken connectivity
 *
 * @objective Check that listening socket accepts a re-send of a SYN segment
 *
 * @param env Testing environment:
 *      - @ref arg_types_env_peer2peer_gw
 *      - @ref arg_types_env_peer2peer_gw_ipv6
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/syn_resend"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

/* Tester SYN segments waiting timeout in seconds.*/
#define WAIT_TST_SYN_TIMEOUT   10

/* Number of retransmitted SYN segments to wait.*/
#define TST_SYNS_NUM           1

/* Type of user data to pass to SYN-ACKs capturing CSAP callback.*/
typedef enum csap_cb_retval {
    CSAP_CB_SUCCESS = 0,
    CSAP_CB_ERROR,
    CSAP_CB_SEQN_INVALID,
} csap_cb_retval;

static void
synack_csap_callback(asn_value *pkt, void *user_data)
{
    static te_bool  first_synack = TRUE;
    static uint32_t initial_seqn = 0;
    uint32_t        got_seqn = 0;
    int             rc = 0;
    csap_cb_retval *retval = (csap_cb_retval *)user_data;

    if (*retval != CSAP_CB_SUCCESS)
        goto exit;

    if ((rc = asn_read_uint32(pkt, &got_seqn, "pdus.0.#tcp.seqn")) != 0)
    {
        ERROR("Cannot read seqn: %r", rc);
        *retval = CSAP_CB_ERROR;
        goto exit;
    }

    if (first_synack)
    {
        initial_seqn = got_seqn;
        first_synack = FALSE;
    }
    else if (initial_seqn != got_seqn)
    {
        *retval = CSAP_CB_SEQN_INVALID;
    }
    else
    {
        *retval = CSAP_CB_SUCCESS;
    }

exit:
    asn_free_value(pkt);
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    tapi_route_gateway      gateway;
    const struct sockaddr  *gw_tst_lladdr = NULL;
    const struct sockaddr  *tst_lladdr = NULL;
    csap_handle_t           syn_csap = CSAP_INVALID_HANDLE;
    csap_handle_t           synack_csap = CSAP_INVALID_HANDLE;
    asn_value              *syn_pattern = NULL;
    asn_value              *synack_pattern = NULL;
    te_bool                 force_ip6 = FALSE;
    int                     iut_s = -1;
    int                     iut_l = -1;
    int                     tst_s = -1;

    unsigned int                synack_recv_num = 0;
    csap_cb_retval              synack_csap_rc = CSAP_CB_SUCCESS;
    tapi_tad_trrecv_cb_data    *synack_csap_cb_data = NULL;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_LINK_ADDR(gw_tst_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    if (rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET6)
        force_ip6 = TRUE;

    TEST_STEP("Create IUT listener socket. Create tester socket.");
    iut_l = rpc_stream_server(pco_iut, RPC_PROTO_DEF, FALSE, iut_addr);
    if (iut_l < 0)
        TEST_FAIL("Failed to create IUT listener socket");

    tst_s = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                                       FALSE, FALSE, tst_addr);
    if (tst_s < 0)
        TEST_FAIL("Failed to create tester socket");

    TEST_STEP("Create CSAP on Tester to catch outgoing packets.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name, TAD_ETH_RECV_OUT,
        (const uint8_t *)gw_tst_lladdr->sa_data,
        (const uint8_t *)tst_lladdr->sa_data,
        tst_addr->sa_family,
        TAD_SA2ARGS(iut_addr, tst_addr), &syn_csap));

    TEST_STEP("Create and start CSAP on Tester to catch incoming "
              "SYNACK packets.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name, TAD_ETH_RECV_DEF,
        NULL,
        NULL,
        tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &synack_csap));
    CHECK_RC(tapi_tcp_ip_segment_pattern(force_ip6, 0, 0,
                                         FALSE, TRUE,
                                         FALSE, FALSE,
                                         TRUE, FALSE,
                                         &synack_pattern));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, synack_csap, synack_pattern,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Break channel IUT->tester using gateway.");
    CHECK_RC(tapi_route_gateway_break_gw_tst(&gateway));

    TEST_STEP("Start connection establishment from tester.");
    pco_tst->op = RCF_RPC_CALL;
    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Start CSAP to catch outgoing retransmitted @c SYN segments.");
    CHECK_RC(tapi_tcp_ip_segment_pattern(force_ip6, 0, 0,
                                         FALSE, FALSE,
                                         FALSE, FALSE,
                                         TRUE, FALSE,
                                         &syn_pattern));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, syn_csap, syn_pattern,
                                   TE_SEC2MS(WAIT_TST_SYN_TIMEOUT),
                                   TST_SYNS_NUM,
                                   RCF_TRRECV_PACKETS));

    TEST_STEP("Wait for resending @c SYN segment by tester.");
    rc = tapi_tad_trrecv_wait(pco_tst->ta, 0, syn_csap, NULL, NULL);
    if (rc != 0)
        TEST_FAIL("Tester did not retransmit SYN");

    TEST_STEP("Repair the channel IUT->tester and finish connection "
              "establishment.");
    CHECK_RC(tapi_route_gateway_repair_gw_tst(&gateway));

    pco_tst->op = RCF_RPC_WAIT;
    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst_s, iut_addr);
    if (rc != 0)
    {
        TEST_VERDICT("Fail to finish connection establishment after "
                     "repairing the connectivity");
    }

    RPC_AWAIT_ERROR(pco_iut);
    iut_s = rpc_accept(pco_iut, iut_l, NULL, NULL);
    if (iut_s < 0)
    {
        TEST_VERDICT("IUT failed to accept the connection after repairing "
                     "the connectivity");
    }

    TEST_STEP("Check that all IUT SYNACK segments have the same "
              "sequence number.");
    synack_csap_cb_data = tapi_tad_trrecv_make_cb_data(synack_csap_callback,
                                                       &synack_csap_rc);
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, synack_csap,
                                  synack_csap_cb_data,
                                  &synack_recv_num));

    if (synack_recv_num == 0)
        TEST_VERDICT("No SYN-ACK segments were received from IUT");

    switch (synack_csap_rc)
    {
        case CSAP_CB_SEQN_INVALID:
            TEST_VERDICT("SYN-ACK segments sent by IUT have different "
                         "sequence numbers");
            break;

        case CSAP_CB_ERROR:
            TEST_VERDICT("Failed to process SYN-ACKs from IUT");
            break;

        default:
            break;
    }

    /*
     * Disabling promiscuous mode on virtual hosts can cause problems with
     * receiving of packates. Let's wait for a while. See ST-2675.
     */
    VSLEEP(1, "Wait after disabling promiscuous mode.");

    TEST_STEP("Pass traffic between IUT and Tester.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    free(synack_csap_cb_data);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, syn_csap));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, synack_csap));
    TEST_END;
}
