/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 */

/** @page arp-tcp_udp_reinforce TCP/UDP connection reinforces ARP entry
 *
 * @objective Check that outgoing TCP or UDP traffic to a given
 *            IP address prevents ARP table entry for that
 *            address from removal due to timeout.
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param pco_iut         PCO on IUT
 * @param pco_tst         PCO on TESTER
 * @param iut_addr        Network address on IUT
 * @param tst_addr        Network address on Tester
 * @param iut_lladdr      Ethernet address on IUT
 * @param iut_if          Network interface on IUT
 * @param tst_if          Network interface on Tester
 * @param period          Period of time to wait before the
 *                        next packet should be sent, in seconds
 * @param repetitions     How many times to send a packet from IUT
 * @param sock_type       Socket type
 *
 * @par Test sequence:
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME "arp/tcp_udp_reinforce"

#include "sockapi-test.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"
#include "tapi_route_gw.h"

/**
 * Send a packet from IUT, receive it on Tester.
 */
#define IUT_SEND_TST_RECV \
    do {                                                                \
        if (sock_type == SOCKTS_SOCK_UDP_NOTCONN)                       \
            RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, tx_len, flags,       \
                       tst_addr);                                       \
        else                                                            \
            RPC_SEND(rc, pco_iut, iut_s, tx_buf, tx_len, flags);        \
                                                                        \
        rc = rpc_recv(pco_tst, tst_s, rx_buf, rx_len, 0);               \
        if (rc != (int)tx_len || memcmp(tx_buf, rx_buf, tx_len) != 0)   \
            TEST_FAIL("Data received on Tester does not match "         \
                      "data sent from IUT");                            \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct sockaddr  *iut_lladdr = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    int period;
    int repetitions;

    csap_handle_t filter_handle = CSAP_INVALID_HANDLE;
    unsigned int  frames_caught = 0;

    int iut_s = -1;
    int tst_s = -1;

    void           *tx_buf = NULL;
    size_t          tx_len;
    void           *rx_buf = NULL;
    size_t          rx_len;
    unsigned int    flags;

    sockts_socket_type sock_type;

    /* Preambule */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    SOCKTS_GET_SOCK_TYPE(sock_type);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_LINK_ADDR(iut_lladdr);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_INT_PARAM(period);
    TEST_GET_INT_PARAM(repetitions);

    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)
        flags = RPC_MSG_CONFIRM;
    else
        flags = 0;

    /* Scenario */
    TEST_STEP("Add static ARP entry on Tester for @p iut_addr to avoid "
              "ARP requests from Tester.");
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL,
                             NULL, iut_addr, CVT_HW_ADDR(iut_lladdr), TRUE));

    TEST_STEP("Add dinamic ARP entry on IUT for @p tst_addr.");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name,
                             pco_tst->ta, tst_if->if_name,
                             tst_addr, NULL, FALSE));

    CFG_WAIT_CHANGES;

    /* Prepare buffer to send */
    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&tx_len)));
    rx_buf = te_make_buf_min(tx_len, &rx_len);

    TEST_STEP("Create a pair of sockets on IUT and Tester, "
              "connect them if required according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, &iut_s, &tst_s, NULL);

    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)
    {
        TEST_STEP("If UDP sockets are tested, send data from IUT, "
                  "so that IUT will send ARP request.");
        IUT_SEND_TST_RECV;
    }

    CHECK_RC(cfg_touch_instance("/agent:%s/interface:%s/neigh_dynamic:",
                                pco_iut->ta, iut_if->if_name));
    CHECK_RC(cfg_touch_instance("/agent:%s/interface:%s/neigh_dynamic:",
                                pco_tst->ta, tst_if->if_name));
    CFG_WAIT_CHANGES;

    /* Launch Ethernet filter for ARP requests from host1 */
    START_ARP_FILTER_WITH_HDR(pco_tst->ta, tst_if->if_name,
                              CVT_HW_ADDR(iut_lladdr), NULL /* eth dst */,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              NULL /* sender protocol address doesn't matter */,
                              NULL /* sender hw address doesn't matter */,
                              CVT_PROTO_ADDR(tst_addr),
                              NULL /* target hw address doesn't matter */,
                              0 /* any number of packets */, filter_handle);


    TEST_STEP("Repeat @p repetitions times sending data from IUT and "
              "receiving it on Tester. Wait for @p period seconds "
              "before sending each time. Each send should reinforce ARP "
              "entry for @p tst_addr in IUT ARP table.");
    while (repetitions--)
    {
        SLEEP(period);
        IUT_SEND_TST_RECV;

        TEST_STEP("Check that no additional ARP requests were sent from IUT.");
        CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, filter_handle, NULL,
                                     &frames_caught));
        if (frames_caught != 0)
            TEST_VERDICT("Ethernet filter caught ARP request from IUT");
    }


    STOP_ETH_FILTER(pco_tst->ta, filter_handle, frames_caught);

    if (frames_caught != 0)
        TEST_VERDICT("Ethernet filter caught ARP request from IUT");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (filter_handle != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                               filter_handle));

    TEST_END;
}

