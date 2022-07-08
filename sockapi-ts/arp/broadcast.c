/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id$
 */

/** @page arp-broadcast Resolution of broadcast addresses
 *
 * @objective Check that broadcast packet to be sent go out through
 *            the right interface and MAC address is broadcast
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param iut_host        host on which IUT resides
 * @param tester_1        host on which TESTER resides
 * @param tester_2        host on which TESTER resides
 * @param pco_iut         PCO on IUT on @p iut_host
 * @param pco_tst1        PCO on TESTER on @p tester_1
 * @param pco_tst2        PCO on TESTER on @p tester_2
 * @param net1            network connecting @p iut_host and @p tester_1.
 *                        @p iut_host attached to @p net1 through
 *                        @p iut_if1 interface,
 *                        @p tester_1 attached to @p net1 through
 *                        @p tst1_if interface
 * @param net2            netwotk connecting @p iut_host and @p tester_2.
 *                        @p iut_host attached to @p net2 through
 *                        @p iut_if2 interface,
 *                        @p tester_2 attached to @p net1 through
 *                        @p tst2_if interface
 *
 * @par Test sequence:
 * -# Assign additional network @p net3 connecting @p iut_host and @p tester_1
 *    through @p iut_if1 and @p tst1_if;
 * -# If network prefixes of @p net1 and @p net3 are equal,
 *    make them different;
 * -# Create @p iut_s socket of type @c SOCK_DGRAM.
 *    Call @b setsockopt() on @p iut_s to set SO_BROADCAST;
 * -# Create @p tst1_s socket of type @c SOCK_DGRAM on @p pco_tst1.
 *    Bind it to @p net1 broadcast;
 * -# Create @p tst2_s socket of type @c SOCK_DGRAM on @p pco_tst2.
 *    Bind it to @p net2 broadcast;
 * -# Create @p tst3_s socket of type @c SOCK_DGRAM on @p pco_tst1.
 *    Bind it to @p net3 broadcast;
 * -# Launch ARP filter to catch ARP requests from @p iut_host
 *    to resolve @p @p net1 broadcast;
 * -# Send UDP datagram from @p pco_iut towards @p net1 broadcast
 *    through @p iut_s;
 * -# Call @b recv() on @p tst1_s, check that it succeed;
 * -# Call non-blocking @b recv() on @p tst3_s,
 *    check that it returns -1 and errno is set to EAGAIN;
 * -# Call non-blocking @b recv() on @p tst2_s,
 *    check that it returns -1 and errno is set to EAGAIN;
 * -# Stop ARP filter and check that there were no ARP requests
 *    issued by @p iut_host;
 * -# Launch ARP filter to catch ARP requests from @p iut_host
 *    to resolve @p @p net3 broadcast;
 * -# Send UDP datagram from @p pco_iut towards @p net3 broadcast
 *    through @p iut_s;
 * -# Call @b recv() on @p tst3_s, check that it succeed;
 * -# Call non-blocking @b recv() on @p tst1_s,
 *    check that it returns -1 and errno is set to EAGAIN;
 * -# Call non-blocking @b recv() on @p tst2_s,
 *    check that it returns -1 and errno is set to EAGAIN;
 * -# Stop ARP filter and check that there were no ARP requests
 *    issued by @p iut_host;
 * -# Launch ARP filter to catch ARP requests from @p iut_host
 *    to resolve @p @p net2 broadcast;
 * -# Send UDP datagram from @p pco_iut towards @p net2 broadcast
 *    through @p iut_s;
 * -# Call @b recv() on @p tst2_s, check that it succeed;
 * -# Call non-blocking @b recv() on @p tst1_s,
 *    check that it returns -1 and errno is set to EAGAIN;
 * -# Call non-blocking @b recv() on @p tst3_s,
 *    check that it returns -1 and errno is set to EAGAIN;
 * -# Stop ARP filter and check that there were no ARP requests
 *    issued by @p iut_host;
 * -# Send UDP datagram from @p pco_iut towards @p net3 broadcast;
 *    Check that datagram sent through @p iut_if1,
 *    and not through @p iut_if2, and has
 *    broadcast MAC address as Ethernet destination address,
 *    and no ARP requests were issued;
 * -# Send UDP datagram from @p pco_iut towards @p net2 broadcast;
 *    Check that datagram sent through @p iut_if2,
 *    and not through @p iut_if1, and has
 *    broadcast MAC address as Ethernet destination address,
 *    and no ARP requests were issued;
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "arp/broadcast"

#include "sockapi-test.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"

#include "tapi_cfg_base.h"

#define ATTEMPTS_MAX_NUM 5


static void
set_bcast_hwaddr(const char *ta, const char *ifname,
                 const uint8_t *new_bcast)
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

    if (memcmp(hwaddr, new_bcast, ETHER_ADDR_LEN) != 0)
    {
         /*
         * Set new link layer broadcast address to
         * interface iut_if1 of pco_iut
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
    rcf_rpc_server            *pco_iut  = NULL;
    rcf_rpc_server            *pco_tst1 = NULL;
    rcf_rpc_server            *pco_tst2 = NULL;

    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *iut_if2 = NULL;
    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;

    tapi_env_host         *iut_host;

    tapi_env_net          *net1;
    tapi_env_net          *net2;

    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;
    struct sockaddr       *iut_alias_addr = NULL;

    const char            *hw_broadcast = NULL;
    uint8_t                hw_bcast[ETHER_ADDR_LEN] = { 0, };

    tapi_cfg_net_assigned  net_handle = {CFG_HANDLE_INVALID, NULL};

    csap_handle_t          arp2_handle = CSAP_INVALID_HANDLE;
    csap_handle_t          arp3_handle = CSAP_INVALID_HANDLE;

    unsigned int           arp_packets;

    cfg_val_type           type;
    uint32_t               nmask;
    unsigned int           prefix;
    struct sockaddr_in     iut_to_tst1_bcast;
    struct sockaddr_in     iut_to_tst2_bcast;
    struct sockaddr_in     iut_alias_bcast;
    char                   buf[INET6_ADDRSTRLEN];

    int                    iut_s = -1;
    int                    tst1_s = -1;
    int                    tst2_s = -1;
    int                    tst3_s = -1;
    int                    opt_val;

    void                  *tx_buf = NULL;
    size_t                 tx_buflen = 256;
    void                  *rx_buf = NULL;
    size_t                 rx_buflen = 256;

    te_bool                answer;
    int                    attempts;


    uint8_t                iut_to_tst1_mac[ETHER_ADDR_LEN];
    size_t                 iut_to_tst1_mac_len = ETHER_ADDR_LEN;
    uint8_t                iut_to_tst2_mac[ETHER_ADDR_LEN];
    size_t                 iut_to_tst2_mac_len = ETHER_ADDR_LEN;

    uint8_t               *src_hwaddr = NULL;
    uint8_t               *dst_hwaddr = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_NET(net1);
    TEST_GET_NET(net2);

    TEST_GET_HOST(iut_host);

    TEST_GET_ADDR_NO_PORT(iut_addr1);
    TEST_GET_ADDR_NO_PORT(iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_STRING_PARAM(hw_broadcast);

    /*
     * Convert hardware address from ascii (XX:XX:XX:XX:XX:XX) to
     * binary presentation
     */
    rc = lladdr_a2n(hw_broadcast, hw_bcast, ETHER_ADDR_LEN);
    if (rc == -1)
        TEST_FAIL("%s():%u: lladdr_a2n failed", __FUNCTION__, __LINE__);

    /* Get hardware adderss of tst_if interface */
    CHECK_RC(tapi_cfg_get_hwaddr(pco_iut->ta,
                                 iut_if1->if_name,
                                 iut_to_tst1_mac,
                                 &iut_to_tst1_mac_len));

    /* Get hardware adderss of tst_if interface */
    CHECK_RC(tapi_cfg_get_hwaddr(pco_iut->ta,
                                 iut_if2->if_name,
                                 iut_to_tst2_mac,
                                 &iut_to_tst2_mac_len));

    set_bcast_hwaddr(pco_iut->ta, iut_if1->if_name, hw_bcast);
    set_bcast_hwaddr(pco_iut->ta, iut_if2->if_name, hw_bcast);
    set_bcast_hwaddr(pco_tst1->ta, tst1_if->if_name, hw_bcast);
    set_bcast_hwaddr(pco_tst2->ta, tst2_if->if_name, hw_bcast);

    CFG_WAIT_CHANGES;

    /* Assign alias address on iut_host*/
    CHECK_RC(tapi_cfg_net_assign_ip(AF_INET, net1->cfg_net, &net_handle));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net1, iut_host, AF_INET,
                                        &net_handle, &iut_alias_addr, NULL));
    /*
     * Now there are two nets interface iut_if1 is attached to.
     * If their subnet id lenghts are equal, make them different.
     */
    /* Get prefix and broadcast of the new assigned net */
    type = CVT_INTEGER;
    CHECK_RC(cfg_get_instance_fmt(&type, &prefix,
                 "/agent:%s/interface:%s/net_addr:%s",
                 pco_iut->ta, iut_if1->if_name,
                 inet_ntop((iut_alias_addr)->sa_family,
                           &SIN(iut_alias_addr)->sin_addr,
                           buf, sizeof(buf))));
    nmask = (1 << ((sizeof(struct in_addr) << 3) - prefix)) - 1;
    memcpy(&iut_alias_bcast, iut_alias_addr, sizeof(iut_alias_bcast));
    iut_alias_bcast.sin_addr.s_addr |= htonl(nmask);
    /*
     * If prefixes of assigned nets are equal,
     * make prefix of net1 bigger
     */
    if (prefix == net1->ip4pfx)
    {
        net1->ip4pfx += 4;
        prefix = net1->ip4pfx;

        nmask = (1 << ((sizeof(struct in_addr) << 3) - prefix)) - 1;
        memcpy(&iut_to_tst1_bcast, iut_addr1,
               sizeof(iut_to_tst1_bcast));
        iut_to_tst1_bcast.sin_addr.s_addr |= htonl(nmask);

        CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, prefix),
                     "/agent:%s/interface:%s/net_addr:%s",
                     pco_iut->ta, iut_if1->if_name,
                     inet_ntop((iut_addr1)->sa_family,
                               &SIN(iut_addr1)->sin_addr,
                               buf, sizeof(buf))));

        CHECK_RC(cfg_set_instance_fmt(CFG_VAL(ADDRESS, &iut_to_tst1_bcast),
                     "/agent:%s/interface:%s/net_addr:%s/broadcast:",
                      pco_iut->ta, iut_if1->if_name,
                      inet_ntop(iut_addr1->sa_family,
                                &SIN(iut_addr1)->sin_addr,
                                buf, sizeof(buf))));

        CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, prefix),
                     "/agent:%s/interface:%s/net_addr:%s",
                     pco_tst1->ta, tst1_if->if_name,
                     inet_ntop((tst1_addr)->sa_family,
                               &SIN(tst1_addr)->sin_addr,
                               buf, sizeof(buf))));

        CHECK_RC(cfg_set_instance_fmt(CFG_VAL(ADDRESS, &iut_to_tst1_bcast),
                     "/agent:%s/interface:%s/net_addr:%s/broadcast:",
                     pco_tst1->ta, tst1_if->if_name,
                     inet_ntop(tst1_addr->sa_family,
                               &SIN(tst1_addr)->sin_addr,
                               buf, sizeof(buf))));

        tapi_cfg_del_neigh_dynamic(pco_iut->ta,
                                   iut_if1->if_name);
        CFG_WAIT_CHANGES;
    }
    /* Get broadcast of net2 */
    memcpy(&iut_to_tst2_bcast, &(net2->ip4bcast),
           sizeof(struct sockaddr_in));
    /*
     * Configuration is prepared. Create tx and rx buffers.
     * Create sockets.
     */
    tx_buf = te_make_buf_by_len(tx_buflen);
    rx_buf = te_make_buf_by_len(rx_buflen);

    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);

    tst1_s = rpc_socket(pco_tst1, RPC_AF_INET,
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    TAPI_SET_NEW_PORT(pco_tst1, &iut_to_tst1_bcast);
    rpc_bind(pco_tst1, tst1_s, CONST_SA(&iut_to_tst1_bcast));

    tst2_s = rpc_socket(pco_tst2, RPC_AF_INET,
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    TAPI_SET_NEW_PORT(pco_tst2, &iut_to_tst2_bcast);
    rpc_bind(pco_tst2, tst2_s, CONST_SA(&iut_to_tst2_bcast));

    tst3_s = rpc_socket(pco_tst1, RPC_AF_INET,
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    TAPI_SET_NEW_PORT(pco_tst1, &iut_alias_bcast);
    rpc_bind(pco_tst1, tst3_s, CONST_SA(&iut_alias_bcast));

    /* Send datagram toward iut_to_tst1_bcast */

    /* Launch ARP filter for ARP packets */
    src_hwaddr = iut_to_tst1_mac;
    dst_hwaddr = hw_bcast;

    START_ARP_FILTER_WITH_HDR(pco_tst1->ta, tst1_if->if_name,
                              src_hwaddr, dst_hwaddr,
                              ARPOP_REQUEST, TAD_ETH_RECV_DEF,
                              CVT_PROTO_ADDR(iut_addr1), src_hwaddr,
                              CVT_PROTO_ADDR(&iut_to_tst1_bcast),  NULL,
                              0, arp2_handle);

    INFO("Sending towards broadcast %s",
        inet_ntoa(SIN(&iut_to_tst1_bcast)->sin_addr));

    for (attempts = 0, answer = FALSE;
         (attempts < ATTEMPTS_MAX_NUM) && (answer == FALSE);
         attempts++)
    {
        RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, tx_buflen, 0,
                   CONST_SA(&iut_to_tst1_bcast));
        RPC_GET_READABILITY(answer, pco_tst1, tst1_s, 5);
    }

    if (answer == FALSE)
    {
        STOP_ETH_FILTER(pco_tst1->ta, arp2_handle, arp_packets);
        if (arp_packets != 0)
            ERROR("%d: ARP filter caught %d packets, "
                  "expected to catch none of them",
                               __LINE__, arp_packets);
        TEST_FAIL("%u: Tester cannot receive broadcast datagram",
                  __LINE__);
    }

    rc = rpc_recv(pco_tst1, tst1_s, rx_buf, rx_buflen, 0);
    RPC_AWAIT_IUT_ERROR(pco_tst1);
    rc = rpc_recv(pco_tst1, tst3_s,
                  rx_buf, rx_buflen, RPC_MSG_DONTWAIT);
    if (rc != -1)
        TEST_FAIL("%d: recv() returns %d, "
                  "but it is expected to return -1",
                  __LINE__, rc);
    CHECK_RPC_ERRNO(pco_tst1, RPC_EAGAIN,
                    "%d: recv() returns -1, but", __LINE__);

    RPC_AWAIT_IUT_ERROR(pco_tst2);
    rc = rpc_recv(pco_tst2, tst2_s,
                  rx_buf, rx_buflen, RPC_MSG_DONTWAIT);
    if (rc != -1)
        TEST_FAIL("%d: recv() returns %d, "
                  "but it is expected to return -1",
                  __LINE__, rc);
    CHECK_RPC_ERRNO(pco_tst2, RPC_EAGAIN,
                    "%d: recv() returns -1, but", __LINE__);

    STOP_ETH_FILTER(pco_tst1->ta, arp2_handle, arp_packets);
    if (arp_packets != 0)
        TEST_FAIL("%d: ARP filter caught %d packets, "
                  "expected to catch none of them",
                  __LINE__, arp_packets);
    /* Send datagram toward iut_alias_bcast */

    /* Launch ARP filter for ARP packets */
    src_hwaddr = iut_to_tst1_mac;
    dst_hwaddr = hw_bcast;

    START_ARP_FILTER_WITH_HDR(pco_tst1->ta, tst1_if->if_name,
                              src_hwaddr, dst_hwaddr,
                              ARPOP_REQUEST, TAD_ETH_RECV_DEF,
                              CVT_PROTO_ADDR(iut_alias_addr), src_hwaddr,
                              CVT_PROTO_ADDR(&iut_alias_bcast),  NULL,
                              0, arp2_handle);

    INFO("Sending towards broadcast %s",
         inet_ntoa(SIN(&iut_alias_bcast)->sin_addr));

    for (attempts = 0, answer = FALSE;
         (attempts < ATTEMPTS_MAX_NUM) && (answer == FALSE);
         attempts++)
    {
        RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, tx_buflen, 0,
                   CONST_SA(&iut_alias_bcast));
        RPC_GET_READABILITY(answer, pco_tst1, tst3_s, 5);
    }

    if (answer == FALSE)
    {
        STOP_ETH_FILTER(pco_tst1->ta, arp2_handle, arp_packets);
        if (arp_packets != 0)
            ERROR("ARP filter caught %d packets, "
                  "expected to catch none of them",
                        arp_packets);
        TEST_FAIL("%u: Tester cannot receive broadcast datagram",
                  __LINE__);
    }
    rc = rpc_recv(pco_tst1, tst3_s, rx_buf, rx_buflen, 0);
    RPC_AWAIT_IUT_ERROR(pco_tst1);
    rc = rpc_recv(pco_tst1, tst1_s,
                  rx_buf, rx_buflen, RPC_MSG_DONTWAIT);
    if (rc != -1)
        TEST_FAIL("%d: recv() returns %d, "
                  "but it is expected to return -1",
                  __LINE__, rc);
    CHECK_RPC_ERRNO(pco_tst1, RPC_EAGAIN,
                    "%d: recv() returns -1, but", __LINE__);

    RPC_AWAIT_IUT_ERROR(pco_tst2);
    rc = rpc_recv(pco_tst2, tst2_s,
                  rx_buf, rx_buflen, RPC_MSG_DONTWAIT);
    if (rc != -1)
        TEST_FAIL("%d: recv() returns %d, "
                  "but it is expected to return -1",
                  __LINE__, rc);
    CHECK_RPC_ERRNO(pco_tst2, RPC_EAGAIN,
                    "%d: recv() returns -1, but", __LINE__);

    STOP_ETH_FILTER(pco_tst1->ta, arp2_handle, arp_packets);
    if (arp_packets != 0)
        TEST_FAIL("ARP filter caught %d packets, "
                  "expected to catch none of them",
                  arp_packets);

    /* Send datagram toward iut_to_tst2_bcast */

    /* Launch ARP filter for ARP packets */
    src_hwaddr = iut_to_tst2_mac;
    dst_hwaddr = hw_bcast;

    START_ARP_FILTER_WITH_HDR(pco_tst2->ta, tst2_if->if_name,
                              src_hwaddr, dst_hwaddr,
                              ARPOP_REQUEST, TAD_ETH_RECV_DEF,
                              CVT_PROTO_ADDR(iut_addr2), NULL,
                              CVT_PROTO_ADDR(&iut_to_tst2_bcast),  NULL,
                              0, arp3_handle);

    INFO("Sending towards broadcast %s",
         inet_ntoa(SIN(&iut_to_tst2_bcast)->sin_addr));

    for (attempts = 0, answer = FALSE;
         (attempts < ATTEMPTS_MAX_NUM) && (answer == FALSE);
         attempts++)
    {
        RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, tx_buflen, 0,
                   CONST_SA(&iut_to_tst2_bcast));
        RPC_GET_READABILITY(answer, pco_tst2, tst2_s, 5);
    }

    rc = rpc_recv(pco_tst2, tst2_s, rx_buf, rx_buflen, 0);
    RPC_AWAIT_IUT_ERROR(pco_tst1);
    rc = rpc_recv(pco_tst1, tst1_s,
                  rx_buf, rx_buflen, RPC_MSG_DONTWAIT);
    if (rc != -1)
        TEST_FAIL("%d: recv() returns %d, "
                  "but it is expected to return -1",
                  __LINE__, rc);
    CHECK_RPC_ERRNO(pco_tst1, RPC_EAGAIN,
                    "%d: recv() returns -1, but", __LINE__);

    RPC_AWAIT_IUT_ERROR(pco_tst1);
    rc = rpc_recv(pco_tst1, tst3_s,
                  rx_buf, rx_buflen, RPC_MSG_DONTWAIT);
    if (rc != -1)
        TEST_FAIL("%d: recv() returns %d, "
                  "but it is expected to return -1",
                  __LINE__, rc);
    CHECK_RPC_ERRNO(pco_tst1, RPC_EAGAIN,
                    "%d: recv() returns -1, but", __LINE__);

    STOP_ETH_FILTER(pco_tst2->ta, arp3_handle, arp_packets);
    if (arp_packets != 0)
        TEST_FAIL("ARP filter caught %d packets, "
                  "expected to catch none of them",
                  arp_packets);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst3_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    if (pco_tst1 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0,
                                             arp2_handle));
    if (pco_tst2 != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0,
                                             arp3_handle));
    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
