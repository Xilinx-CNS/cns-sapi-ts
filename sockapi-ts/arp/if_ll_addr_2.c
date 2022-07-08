/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id$
 */

/** @page arp-if_ll_addr_2 Change MAC address after connection establishment
 *
 * @objective Create a socket and connect it. Change MAC address.
 *            Check that the new MAC address is used by the traffic
 *            originated from the socket.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param iut_addr      Network address on IUT
 * @param tst_addr      Network address on Tester
 * @param iut_lladdr    Ethernet address on IUT
 * @param tst_lladdr    Ethernet address on Tester
 * @param iut_if        Network interface name on IUT
 * @param tst_if        Network interface name on Tester
 * @param sock_type     @c SOCK_DGRAM or @c SOCK_STREAM
 * @param local_server  TRUE/FALSE - server should be on local/peer host
 *
 * @par Test sequence:
 *
 * -# Create network connection of sockets of @p sock_type by means of
 *    @c GEN_CONNECTION, obtain sockets @p iut_s on @p pco_iut and
 *    @p tst_s on @p pco_tst.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Change @p iut_if interface link layer address to new one;
 * -# Add valid arp entry to access TST side through @p iut_if
 *    on IUT side (To exclude IUT side's ARP resolution);
 * -# Delete arp entry to access IUT side through @p tst_if
 *    on TST side;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Run ARP filter on TST side to catch IUT side's ARP reply;
 * -# Run Ether filter on TST side to catch IUT side's IP packets;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# In case @p local_server is @c TRUE:
 *      - @b sendto() some data through @p tst_s to @p iut_s;
 *      - @b sendto() some data through @p iut_s to @p tst_s;
 * -# In case @p local_server is @c FALSE:
 *     - @b sendto() some data through @p iut_s to @p tst_s;
 *     - @b sendto() some data through @p tst_s to @p iut_s;
 * -# Stop both ARP and Ether filters;
 * -# Check that both filters have detected appropriate ARP and IP
 *    packets with changed link layer interface address;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close opened sockets and frees allocated resources.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "arp/if_ll_addr_2"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"

int
main(int argc, char *argv[])
{
    rpc_socket_type             sock_type;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    const struct sockaddr  *iut_lladdr = NULL;
    const struct sockaddr  *tst_lladdr = NULL;
    const struct sockaddr  *alien_link_addr = NULL;
    struct sockaddr        cache_hwaddr;

    int                    iut_s = -1;
    int                    tst_s = -1;

    void                  *tx1_buf = NULL;
    size_t                 tx1_buflen = 1024;
    void                  *tx2_buf = NULL;
    size_t                 tx2_buflen = 1024;

    void                  *rx1_buf = NULL;
    size_t                 rx1_buflen = 1024;
    void                  *rx2_buf = NULL;
    size_t                 rx2_buflen = 1024;

    char                   opt_ifname[IFNAMSIZ];

    int                    arp_flags;
    te_bool                arp_entry_exist;

    csap_handle_t          arp_catcher = CSAP_INVALID_HANDLE;
    csap_handle_t          ip_catcher = CSAP_INVALID_HANDLE;
    unsigned int           arp_frames = 0;
    unsigned int           ip_frames = 0;
    te_bool                local_server;

    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_BOOL_PARAM(local_server);

    strncpy(opt_ifname, iut_if->if_name, IFNAMSIZ);

    /* Prepare buffers */
    tx1_buf = te_make_buf_by_len(tx1_buflen);
    rx1_buf = te_make_buf_by_len(rx1_buflen);
    tx2_buf = te_make_buf_by_len(tx2_buflen);
    rx2_buf = te_make_buf_by_len(rx2_buflen);

    GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    /* Set new link layer address to interface */
    if ((rc = tapi_cfg_set_hwaddr(pco_iut->ta, iut_if->if_name,
                                  CVT_HW_ADDR(alien_link_addr),
                                  ETHER_ADDR_LEN)) != 0)
    {
        TEST_VERDICT("Failed to set HW address on IUT interface: %r", rc);
    }

    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;

    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(tst_lladdr), FALSE));
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      iut_addr));

    /* ARP response catcher */
    START_ARP_FILTER_WITH_HDR(pco_tst->ta,
                              tst_if->if_name,
                              CVT_HW_ADDR(alien_link_addr),
                              CVT_HW_ADDR(tst_lladdr),
                              ARPOP_REPLY,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              CVT_PROTO_ADDR(iut_addr),
                              CVT_HW_ADDR(alien_link_addr),
                              CVT_PROTO_ADDR(tst_addr),
                              CVT_HW_ADDR(tst_lladdr), 0, arp_catcher);

    /* IP packet catcher */
    START_ETH_FILTER(pco_tst->ta,
                     tst_if->if_name,
                     TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                     CVT_HW_ADDR(alien_link_addr),
                     CVT_HW_ADDR(tst_lladdr),
                     ETHERTYPE_IP,
                     0, ip_catcher);

    if (local_server == TRUE)
    {
        rc = rpc_send(pco_tst, tst_s, tx1_buf, tx1_buflen, 0);
        if (rc != (int)tx1_buflen)
            TEST_FAIL("Unexpectedly send(tst_s) returns %d instead of %d",
                      rc, tx1_buflen);

        rc = rpc_send(pco_iut, iut_s, tx2_buf, tx2_buflen, 0);
        if (rc != (int)tx2_buflen)
            TEST_FAIL("Unexpectedly sendto(iut) returns %d instead of %d",
                      rc, tx2_buflen);
    }
    else
    {
        rc = rpc_send(pco_iut, iut_s, tx2_buf, tx2_buflen, 0);
        if (rc != (int)tx2_buflen)
            TEST_FAIL("Unexpectedly sendto(iut) returns %d instead of %d",
                      rc, tx2_buflen);

        rc = rpc_send(pco_tst, tst_s, tx1_buf, tx1_buflen, 0);
        if (rc != (int)tx1_buflen)
            TEST_FAIL("Unexpectedly send(tst_s) returns %d instead of %d",
                      rc, tx1_buflen);
    }

    TAPI_WAIT_NETWORK;

    /* Stop ARP catcher on TST side */
    STOP_ETH_FILTER(pco_tst->ta, arp_catcher, arp_frames);

    /* Check ARP requests absence */
    if (arp_frames == 0)
        TEST_FAIL("Test waits for IUT side ARP reply with new LL "
                  "interface address but it is absent");

    /* Stop IP catcher on TST side */
    STOP_ETH_FILTER(pco_tst->ta, ip_catcher, ip_frames);
    if (ip_frames == 0)
        TEST_FAIL("Test waits for IUT side IP packets with new LL "
                  "interface address but these are absent");

    TEST_GET_ARP_ENTRY(pco_tst, iut_addr, tst_if->if_name,
                       &cache_hwaddr, arp_flags, arp_entry_exist);
    if ((arp_entry_exist == FALSE) || !(arp_flags & ATF_COM))
    {
        TEST_FAIL("Failed to get ARP entry on TST "
                  "(it's expected to have got dynamic ARP entry)");
    }

    if (memcmp(CVT_HW_ADDR(alien_link_addr), cache_hwaddr.sa_data,
               ETHER_ADDR_LEN) != 0)
        TEST_FAIL("ARP cache entry with unexpected LL address");

    rc = rpc_recv(pco_tst, tst_s, rx2_buf, rx2_buflen, 0);
    if (rc != (int)rx2_buflen)
    {
        TEST_FAIL("Only part of data received");
    }
    if (memcmp(tx2_buf, rx2_buf, tx2_buflen) != 0)
    {
        TEST_FAIL("Invalid data received via tst_s socket");
    }

    rc = rpc_recv(pco_iut, iut_s, rx1_buf, rx1_buflen, 0);
    if (rc != (int)rx1_buflen)
    {
        TEST_FAIL("Only part of data received");
    }
    if (memcmp(tx1_buf, rx1_buf, tx1_buflen) != 0)
    {
        TEST_FAIL("Invalid data received via iut_s socket");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (pco_iut != NULL && iut_if != NULL)
    {
        CLEANUP_CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta,
                                               iut_if->if_name));
        /* Restore original link layer interface address */
        CLEANUP_CHECK_RC(tapi_cfg_set_hwaddr(pco_iut->ta, iut_if->if_name,
                         CVT_HW_ADDR(iut_lladdr), ETHER_ADDR_LEN));
        CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
        CFG_WAIT_CHANGES;
    }

    if (pco_tst != NULL)
    {
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, arp_catcher));
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, ip_catcher));
    }

    free(tx1_buf);
    free(rx1_buf);
    free(tx2_buf);
    free(rx2_buf);

    TEST_END;
}
