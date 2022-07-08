/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * ARP table
 * 
 * $Id$
 */

/** @page arp-common_broadcast Resolution of broadcast addresses
 *
 * @objective Check that broadcast packet to be sent towards 255.255.255.255 
 *            go out through the right interface and MAC address is broadcast
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst1          PCO on TESTER
 * @param pco_tst2          PCO on TESTER (may be on a different host)
 * @param iut_to_tst1_addr  Address on an interface connecting @p pco_iut
 *                          and @p pco_tst1
 * @param iut_to_tst1_if    Interface connecting @p pco_iut and
 *                          @p pco_tst1.
 * @param iut_to_tst2_if    Interface connecting @p pco_iut and
 *                          @p pco_tst2.
 * @param tst1_if           Interface to be used by @p pco_tst1
 * @param tst2_if           Interface to be used by @p pco_tst2
 * @param hw_broadcast      Broadcast interface hardware address
 *
 * @par Test sequence:
 * -# Set socket option SO_BROADCAST to UDP socket on pco_iut through
 *    which UDP datagrams are sent. Bind it to @p iut_to_tst1_addr.
 *    Send UDP datagram towards 255.255.255.255;
 *    Check that UDP datagram sent out through @p iut_to_tst1_if,
 *    and not through @p iut_to_tst2_if,
 *    and has @p hw_broadcast MAC address as Ethernet destination address;
 * -# Set socket option @c SO_BROADCAST to UDP socket on pco_iut through
 *    which UDP datagrams are sent. Bind it to @p iut_to_tst2_addr.
 *    Send UDP datagram towards 255.255.255.255;
 *    Check that UDP datagram sent out through @p iut_to_tst2_if,
 *    and not through @p iut_to_tst1_if,
 *    and has broadcast MAC address as Ethernet destination address;
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "arp/common_broadcast"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"


static void
set_bcast_hwaddr(const char *ta, const char *ifname,
                 const uint8_t *new_bcast, uint8_t *old_bcast)
{
    uint8_t hwaddr[ETHER_ADDR_LEN] = { 0, };
    size_t  hwaddr_len = sizeof(hwaddr);

    CHECK_RC(tapi_cfg_get_bcast_hwaddr(ta, ifname, hwaddr, &hwaddr_len));
    if (hwaddr_len != ETHER_ADDR_LEN)
        TEST_FAIL("Unexpected hardware broadcast address length - %u",
                  (unsigned)hwaddr_len);

    RING("Returned interface broadcast hardware address: "
         "%02x:%02x:%02x:%02x:%02x:%02x",
         hwaddr[0], hwaddr[1], hwaddr[2],
         hwaddr[3], hwaddr[4], hwaddr[5]);

    if (old_bcast != NULL)
        memcpy(old_bcast, hwaddr, ETHER_ADDR_LEN);

    if (memcmp(hwaddr, new_bcast, ETHER_ADDR_LEN) != 0)
    {
         /*
         * Set new link layer broadcast address to
         * interface iut_to_tst1_if of pco_iut
         */
        CHECK_RC(tapi_cfg_base_if_down(ta, ifname));
        CHECK_RC(tapi_cfg_set_bcast_hwaddr(ta, ifname,
                                           new_bcast, ETHER_ADDR_LEN));
        CHECK_RC(tapi_cfg_base_if_up(ta, ifname));
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst1 = NULL;
    rcf_rpc_server            *pco_tst2 = NULL;

    const struct if_nameindex *iut_to_tst1_if = NULL;
    const struct if_nameindex *iut_to_tst2_if = NULL;
    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;

    const struct sockaddr  *iut_to_tst1_addr = NULL;
    const struct sockaddr  *iut_to_tst2_addr = NULL;

    struct sockaddr_in     tst_wildcard_addr;
    struct sockaddr_in     inaddr_broadcast;
    struct sockaddr_in     peer_addr;
    socklen_t              peer_addrlen = sizeof(struct sockaddr_in);

    const char            *hw_broadcast = NULL;

    uint8_t hwaddr_iut_tst1[ETHER_ADDR_LEN] = { 0, };
    uint8_t hwaddr_iut_tst2[ETHER_ADDR_LEN] = { 0, };
    uint8_t hwaddr_tst_tst1[ETHER_ADDR_LEN] = { 0, };
    uint8_t hwaddr_tst_tst2[ETHER_ADDR_LEN] = { 0, };

    csap_handle_t          iut_to_tst1_if_handle = CSAP_INVALID_HANDLE;
    csap_handle_t          iut_to_tst2_if_handle = CSAP_INVALID_HANDLE;

    unsigned int           iut_to_tst1_if_pkts;
    unsigned int           iut_to_tst2_if_pkts;

    int                    iut_s = -1;
    int                    tst1_s = -1;
    int                    tst2_s = -1;
    int                    opt_val;

    void                  *tx_buf = NULL;
    size_t                 tx_buflen = 256;
    void                  *rx_buf = NULL;
    size_t                 rx_buflen = 256;

    te_bool                op_done;
    te_bool                test_failed = FALSE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_ADDR(pco_iut, iut_to_tst1_addr);
    TEST_GET_ADDR(pco_iut, iut_to_tst2_addr);
    TEST_GET_IF(iut_to_tst1_if);
    TEST_GET_IF(iut_to_tst2_if);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_STRING_PARAM(hw_broadcast);

    tx_buf = te_make_buf_by_len(tx_buflen);
    rx_buf = te_make_buf_by_len(rx_buflen);

    /*
     * Convert hardware address from ascii (XX:XX:XX:XX:XX:XX) to
     * binary presentation
     */
    rc = lladdr_a2n(hw_broadcast, mac_broadcast, ETHER_ADDR_LEN);
    if (rc == -1)
        TEST_FAIL("%s():%u: lladdr_a2n failed", __FUNCTION__,
                  __LINE__);

    set_bcast_hwaddr(pco_iut->ta, iut_to_tst1_if->if_name,
                     mac_broadcast, hwaddr_iut_tst1);
    set_bcast_hwaddr(pco_iut->ta, iut_to_tst2_if->if_name,
                     mac_broadcast, hwaddr_iut_tst2);
    set_bcast_hwaddr(pco_tst1->ta, tst1_if->if_name,
                     mac_broadcast, hwaddr_tst_tst1);
    set_bcast_hwaddr(pco_tst2->ta, tst2_if->if_name,
                     mac_broadcast, hwaddr_tst_tst2);

    CFG_WAIT_CHANGES;

    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);
    rpc_bind(pco_iut, iut_s, iut_to_tst1_addr);

    /* Send datagram toward 255.255.255.255 through each interface */
    inaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    inaddr_broadcast.sin_family = AF_INET;
    TAPI_SET_NEW_PORT(pco_tst1, &inaddr_broadcast);

    tst1_s = rpc_socket(pco_tst1, RPC_AF_INET,
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_wildcard_addr.sin_family = AF_INET;
    tst_wildcard_addr.sin_port = inaddr_broadcast.sin_port;
    te_sockaddr_set_wildcard(SA(&tst_wildcard_addr));
    rpc_bind(pco_tst1, tst1_s, CONST_SA(&tst_wildcard_addr));

    /* Launch Ethernet sniffer for UDP datagram */
    START_ETH_FILTER(pco_tst1->ta, tst1_if->if_name, 
                     TAD_ETH_RECV_DEF,
                     NULL, mac_broadcast,
                     ETHERTYPE_IP, 0, iut_to_tst1_if_handle);

    START_ETH_FILTER(pco_tst2->ta, tst2_if->if_name, 
                     TAD_ETH_RECV_DEF,
                     NULL, mac_broadcast,
                     ETHERTYPE_IP, 0, iut_to_tst2_if_handle);

    RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, tx_buflen, 0, 
               CONST_SA(&inaddr_broadcast)); 
    rc = rpc_recvfrom(pco_tst1, tst1_s, rx_buf, rx_buflen, 0, 
                      (struct sockaddr *)&peer_addr,
                      &peer_addrlen);

    STOP_ETH_FILTER(pco_tst1->ta, iut_to_tst1_if_handle, 
                    iut_to_tst1_if_pkts);
    if (iut_to_tst1_if_pkts != 1)
    {
        ERROR("%d: IP filter caught %d packets, expected to catch 1",
              __LINE__, iut_to_tst1_if_pkts);
        if (iut_to_tst1_if_pkts == 0)
            ERROR_VERDICT("No IP packets was catched on the first "
                          "peer interface but there should be one");
        else
            ERROR_VERDICT("Unexpected number of IP packets was "
                          "catched on the first peer interface "
                          "but there should be one");
        test_failed = TRUE;
    }

    STOP_ETH_FILTER(pco_tst2->ta, iut_to_tst2_if_handle, 
                    iut_to_tst2_if_pkts);
    if (iut_to_tst2_if_pkts != 0)
    {
        ERROR("%d: IP filter caught %d packets, expected to catch 0",
              __LINE__, iut_to_tst2_if_pkts);
        ERROR_VERDICT("Socket is bound to the first interface, "
                      "but datagram toward 255.255.255.255 is sent through "
                      "the second one involved in environment");
        test_failed = TRUE;
    }

    rpc_close(pco_iut, iut_s);

    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);
    rpc_bind(pco_iut, iut_s, iut_to_tst2_addr);

    inaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    inaddr_broadcast.sin_family = AF_INET;
    TAPI_SET_NEW_PORT(pco_tst2, &inaddr_broadcast);

    tst2_s = rpc_socket(pco_tst2, RPC_AF_INET, RPC_SOCK_DGRAM,
                        RPC_PROTO_DEF);
    tst_wildcard_addr.sin_family = AF_INET;
    tst_wildcard_addr.sin_port = inaddr_broadcast.sin_port;
    te_sockaddr_set_wildcard(SA(&tst_wildcard_addr));
    rpc_bind(pco_tst2, tst2_s, CONST_SA(&tst_wildcard_addr));

    /* Launch Ethernet sniffer for UDP datagram */
    START_ETH_FILTER(pco_tst1->ta, tst1_if->if_name, 
                     TAD_ETH_RECV_DEF,
                     NULL, mac_broadcast,
                     ETHERTYPE_IP, 0, iut_to_tst1_if_handle);

    START_ETH_FILTER(pco_tst2->ta, tst2_if->if_name, 
                     TAD_ETH_RECV_DEF,
                     NULL, mac_broadcast,
                     ETHERTYPE_IP, 0, iut_to_tst2_if_handle);

    RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, tx_buflen, 0, 
               CONST_SA(&inaddr_broadcast)); 
    TAPI_WAIT_NETWORK;

    pco_tst2->op = RCF_RPC_CALL;
    rpc_recvfrom(pco_tst2, tst2_s, rx_buf, rx_buflen, 0, 
                 (struct sockaddr *)&peer_addr,
                 &peer_addrlen);
    rcf_rpc_server_is_op_done(pco_tst2, &op_done);
    if (!op_done)
    {
        SLEEP(1);    
        rcf_rpc_server_is_op_done(pco_tst2, &op_done);
        if (!op_done)
        {
            rcf_rpc_server_restart(pco_tst2);
            tst2_s = -1;
            ERROR_VERDICT("recvfrom() on the second socket timed out");
        }
    }

    STOP_ETH_FILTER(pco_tst2->ta, iut_to_tst2_if_handle, 
                    iut_to_tst2_if_pkts);
    if (iut_to_tst2_if_pkts != 1)
    {
        ERROR("%d, IP filter caught %d packets, expected to catch 1",
              __LINE__, iut_to_tst2_if_pkts);

        if (iut_to_tst2_if_pkts == 0)
            ERROR_VERDICT("No IP packets was catched on the second "
                          "peer interface but there should be one");
        else
            ERROR_VERDICT("Unexpected number of IP packets was "
                          "catched on the second peer interface "
                          "but there should be one");
        test_failed = TRUE;
    }

    STOP_ETH_FILTER(pco_tst1->ta, iut_to_tst1_if_handle,
                    iut_to_tst1_if_pkts);
    if (iut_to_tst1_if_pkts != 0)
    {
        ERROR("%d, IP filter caught %d packets, expected to catch 0",
              __LINE__, iut_to_tst1_if_pkts);

        ERROR_VERDICT("Socket is bound to the second interface, "
                      "but datagram toward 255.255.255.255 is sent through "
                      "the first one involved in environment");
        test_failed = TRUE;
    }

    if (!op_done)
        TEST_STOP;

    pco_tst2->op = RCF_RPC_WAIT;
    rc = rpc_recvfrom(pco_tst2, tst2_s, rx_buf, rx_buflen, 0, 
                      (struct sockaddr *)&peer_addr,
                      &peer_addrlen);

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (pco_tst1 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0,
                                               iut_to_tst1_if_handle));
    if (pco_tst2 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst2->ta, 0,
                                               iut_to_tst2_if_handle));
    free(tx_buf);

    set_bcast_hwaddr(pco_iut->ta, iut_to_tst1_if->if_name,
                     hwaddr_iut_tst1, NULL);
    set_bcast_hwaddr(pco_iut->ta, iut_to_tst2_if->if_name,
                     hwaddr_iut_tst2, NULL);
    set_bcast_hwaddr(pco_tst1->ta, tst1_if->if_name,
                     hwaddr_tst_tst1, NULL);
    set_bcast_hwaddr(pco_tst2->ta, tst2_if->if_name,
                     hwaddr_tst_tst2, NULL);

    TEST_END;
}
