/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * TCP
 * 
 * $Id$
 */

/** @page tcp-syn_ack_distrib  Check SYN-ACK retransmits distribution
 *
 * @objective  Check that SYN-ACK retransmits are not bursty
 *
 * @type conformance
 *
 * @param pco_iut  PCO on IUT
 * @param pco_tst  PCO on TESTER
 * 
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/syn_ack_distrib"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_tcp.h"
#include "tapi_route_gw.h"

#include "ndn_ipstack.h"
#include "ndn_eth.h"

/** Period to get SYN-ACK replies */
#define TESTING_TIME 60000

/**
 * Wait @p delay milliseconds in the loop like a sleep(), but check offset
 * from the @p start time value. It's to avoid cumulative shift in absolute
 * time.
 * 
 * @param start  Timestamp of the countdown beginning
 * @param delay  Delay to wait on each iteration
 * @param iter   Iteration number
 * @param offt   Iteration offset
 * 
 * @return Difference from the start timestamp
 */
static int
tst_wait(struct timeval *start, int delay, int iter, int offt)
{
    struct timeval tv;
    int diff;

    do {
        usleep(1000);
        gettimeofday(&tv, NULL);
        diff = TE_US2MS(TIMEVAL_SUB(tv, *start));
    } while (diff < (delay * iter + offt));

    if (diff > (delay * (iter + 1) + offt))
        WARN("'diff' is too big, results can be unexpected. "
             "diff: %d, delay: %d, iter: %d, offt: %d",
             diff, delay, iter, offt);

    return diff;
}

int
main(int argc, char *argv[])
{
    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_fake_addr;
    const struct sockaddr     *alien_link_addr = NULL;

    uint8_t     iut_link_addr[IFHWADDRLEN];
    size_t      link_addr_len;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             syn_num;

    int                 iut_s = -1;
    csap_handle_t       csap_send = CSAP_INVALID_HANDLE;
    csap_handle_t       csap_recv = CSAP_INVALID_HANDLE;

    asn_value      *syn_templ = NULL;
    asn_value      *repl_patt = NULL;
    uint16_t        port = htons(20000);
    int             i;
    int             delay;
    unsigned int    num;
    unsigned int    total_num;
    struct timeval  tv1;
    int             max_intersects;
    te_bool         force_ip6 = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_INT_PARAM(syn_num);
    TEST_GET_INT_PARAM(delay);
    TEST_GET_INT_PARAM(max_intersects);

    if (rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET6)
        force_ip6 = TRUE;

    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_fake_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    CFG_WAIT_CHANGES;

    link_addr_len = sizeof(iut_link_addr);
    CHECK_RC(tapi_cfg_get_hwaddr(pco_iut->ta, iut_if->if_name,
                                 iut_link_addr, &link_addr_len));

    te_sockaddr_set_port(SA(tst_fake_addr), port);

    TEST_STEP("Create a listener TCP socket on IUT and sending CSAP on tester.");

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_s, syn_num);

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name, TAD_ETH_RECV_HOST,
        (uint8_t *)alien_link_addr->sa_data, iut_link_addr,
        iut_addr->sa_family,
        te_sockaddr_get_netaddr(tst_fake_addr),
        te_sockaddr_get_netaddr(iut_addr),
        -1, te_sockaddr_get_port(iut_addr),
        &csap_send));

    TEST_STEP("Create receiver CSAP on tester.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0, tst_if->if_name, TAD_ETH_RECV_DEF,
        (uint8_t *)alien_link_addr->sa_data, iut_link_addr,
        iut_addr->sa_family,
        te_sockaddr_get_netaddr(tst_fake_addr),
        te_sockaddr_get_netaddr(iut_addr),
        -1, te_sockaddr_get_port(iut_addr),
        &csap_recv));

    CHECK_RC(tapi_tcp_ip_segment_pattern(force_ip6, 0, 0,
                                         FALSE, TRUE,
                                         FALSE, FALSE,
                                         TRUE, FALSE,
                                         &repl_patt));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_recv,
                                   repl_patt, -1, 0,
                                   RCF_TRRECV_NO_PAYLOAD));

    CHECK_RC(tapi_tcp_template(force_ip6, 0, 0, TRUE, FALSE,
                               NULL, 0, &syn_templ));

    gettimeofday(&tv1, NULL);

    TEST_STEP("Send @p syn_num SYN packets to IUT from tester.");
    for (i = 0; i < syn_num; i++)
    {
        port++;
        CHECK_RC(asn_write_int32(syn_templ, port,
                                 "pdus.0.#tcp.src-port.#plain"));
        CHECK_RC(asn_write_int32(syn_templ, rand_range(0, INT_MAX),
                                 "pdus.0.#tcp.seqn.#plain"));

        tst_wait(&tv1, delay, i, 0);
        CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, 0, csap_send,
                                       syn_templ, RCF_MODE_BLOCKING));
    }
    CHECK_RC(rcf_ta_trrecv_get(pco_tst->ta, 0, csap_recv,
                               NULL, NULL, &num));

    total_num = 0;

    TEST_STEP("Receive SYN-ACK retransmits from IUT and check that they are not "
              "bursty.");
    for (;tst_wait(&tv1, delay, i, delay / 2) <
          TESTING_TIME + syn_num * delay; i++)
    {
        CHECK_RC(rcf_ta_trrecv_get(pco_tst->ta, 0, csap_recv,
                                   NULL, NULL, &num));
        RING("Retransmitted SYN-ACKs number %d", num);
        if (i != syn_num && (int)num > max_intersects)
            TEST_VERDICT("More then %d packet was received during %d "
                         "milliseconds", max_intersects, delay);

        total_num += num;
    }

    RING("Total retransmitted SYN-ACKs number %d", total_num);
    if (total_num < (unsigned int)syn_num)
        TEST_VERDICT("Too few SYN-ACKs was retransmitted");

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name,
                                     pco_tst->ta, tst_if->if_name,
                                     tst_fake_addr, NULL, FALSE));
    CFG_WAIT_CHANGES;

    if (csap_recv != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap_recv));
    if (csap_send != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap_send));

    asn_free_value(syn_templ);
    asn_free_value(repl_patt);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
