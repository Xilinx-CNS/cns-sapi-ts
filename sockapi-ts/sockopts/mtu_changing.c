/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-mtu_changing Checking TCP behaviour in the case of mtu changing on the next hop
 *
 * @objective Check correctness of TCP processing in the case of decreasing next
 *            hop MTU. This test checks correctness of retransmit queue
 *            processing by transmitting TCP.
 *
 * @type conformance
 *
 * @reference @ref XNS5, @ref STEVENS
 *
 * @param pco_iut    PCO on IUT
 * @param pco_gw     PCO on host in the tested network
 *                   that is able to forward incoming packets (router)
 * @param pco_tst    PCO on TESTER
 * @param retr_queue Check retransmission queue
 *
 * @par Test sequence:
 *
 * -# Add route on @p pco_iut: @p tst_addr via gateway @p gw1_addr;
 * -# Add route on @p pco_tst: @p iut_addr via gateway @p gw2_addr;
 * -# Turn on forwarding on router host;
 * -# Establish connection of the @c SOCK_STREAM type between @p pco_iut and
 *    @p pco_tst by means of @c GEN_CONNECTION;
 * -# Turn on unblocking mode on @p iut_s socket;
 * -# Fill in the receive/send buffer of the @p tst_s/iut_s by means of
 *    @c iomux_fill_io_buffers();
 * -# Set new MTU on @p gw2_if and check that new value is set;
 * -# If @p retr_queue is TRUE add a new static ARP entry for moving traffic
 *    to the bad path (from @p iut_s to the incorrect path to create needed
 *    conditions for processing new MTU on @p iut_s);
 * -# @c recv() part of data on @p tst_s to free some receive buffer space and
 *    force transmissions on @p iut_s;
 * -# If @p retr_queue is TRUE delete a static ARP entry for moving traffic 
 *    to the normal path;
 * -# @c recv() the rest of data sent on @p iut_s;
 * -# Check the data correctness sent from @p iut_s to @p tst_s;
 * -# Close crated sockets, return to the original configuration.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/mtu_changing"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"
#include "iomux.h"

#define FULL_BUFF_LEN       10240
#define PART_BUFF_LEN       6144

/* timeout in millisecs used as last arg of the iomux_call() */
#define TST_IOMUX_TIMEOUT  60000

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_gw  = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    tapi_env_host         *iut_host = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *gw1_addr = NULL;
    const struct sockaddr *gw2_addr = NULL;
    uint8_t                rx_buf[FULL_BUFF_LEN];
    ssize_t                total_sent = 0;
    ssize_t                total_recv = 0;
    ssize_t                recv_bytes = 0;

    te_bool                retr_queue;
    te_bool                route_dst_added = FALSE;
    te_bool                route_src_added = FALSE;
    te_bool                arp_entry_added = FALSE;
    te_bool                first_reading = TRUE;

    const void            *alien_link_addr;

    int                    saved_mtu;
    int                    new_mtu;
    int                    req_val;

    iomux_evt              revt = 0;

    const struct if_nameindex   *gw2_if = NULL;

    int32_t       i = 0;
    int32_t       j = 1;
    uint8_t       *m = (uint8_t *)&j;

    te_saved_mtus   gw_mtus = LIST_HEAD_INITIALIZER(gw_mtus);
    
    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_HOST(iut_host);
    TEST_GET_BOOL_PARAM(retr_queue);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(gw1_addr);
    TEST_GET_ADDR_NO_PORT(gw2_addr);

    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(gw2_if);
    
    domain = rpc_socket_domain_by_addr(iut_addr);

    /* Add route on 'pco_iut': 'tst_addr' via gateway 'gw1_addr' */
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw1_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the dst");
    }
    route_dst_added = TRUE;

    /* Add route on 'pco_tst': 'iut_addr' via gateway 'gw2_addr' */
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw2_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the src");
    }
    route_src_added = TRUE;

    /* Turn on forwarding on router host */
    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));
    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_gw->ta, gw2_if->if_name,
                                            &saved_mtu));

    CFG_WAIT_CHANGES;


    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (iomux_fill_io_buffers(pco_iut, iut_s, IC_DEFAULT, &total_sent) != 0)
    {
        TEST_FAIL("Failed to fill in iut_s->tst_s connection");
    }

    /* Turn on FIONBIO request on 'iut_s' socket */
    req_val = TRUE;
    rpc_ioctl(pco_tst, tst_s, RPC_FIONBIO, &req_val);

    do {
        rc = iomux_call_default_simple(pco_tst, tst_s, EVT_RD, &revt,
                                       TST_IOMUX_TIMEOUT);
        if (rc == 0)
               break;
        if (rc < 0)
        {
            TEST_FAIL("'tst_s' socket returns error when data "
                      "from 'iut_s' socket wanted");
        }

        if (revt != EVT_RD)
        {
            TEST_FAIL("iomux_call() returns 1, but does not set 'tst_s' "
                      "as readable");
        }

        do {
            rpc_errno   err;
            int32_t      ii;

            if (first_reading)
            {

                new_mtu = 600;
                CHECK_RC(tapi_set_if_mtu_smart2(pco_gw->ta, gw2_if->if_name,
                                                new_mtu, &gw_mtus));

                if (retr_queue)
                {
                    /*
                     * Add a new static ARP entry for moving traffic to the
                     * bad path
                     */
                    if (tapi_update_arp(pco_gw->ta, gw2_if->if_name,
                                        NULL, NULL, tst_addr,
                                        CVT_HW_ADDR(alien_link_addr),
                                        TRUE) != 0)
                    {
                        TEST_FAIL("Cannot add a new ARP entry");
                    }
                    arp_entry_added = TRUE;
                }

                pco_tst->op = RCF_RPC_CALL_WAIT;
                recv_bytes = rpc_recv(pco_tst, tst_s, rx_buf, PART_BUFF_LEN, 0);
                if (recv_bytes != PART_BUFF_LEN)
                {
                    TEST_FAIL("tst_s received bytes differ than "
                              "from pco_iut wanted");
                }
                total_recv = recv_bytes;

                first_reading = FALSE;

                if (retr_queue)
                {
                    /* Delete a static ARP entry for moving traffic to the
                     * normal path */
                    if (tapi_cfg_del_neigh_entry(pco_gw->ta, gw2_if->if_name,
                                                 tst_addr) != 0)
                    {
                        ERROR("Cannot delete ARP entry");
                        result = EXIT_FAILURE;
                    }
                    arp_entry_added = FALSE;
                }
            }
            else
            {
                pco_tst->op = RCF_RPC_CALL_WAIT;
                RPC_AWAIT_IUT_ERROR(pco_tst);
                recv_bytes = rpc_recv(pco_tst, tst_s, rx_buf, FULL_BUFF_LEN, 0);
                if (recv_bytes == -1)
                {
                    err = RPC_ERRNO(pco_tst);
                    if (err != RPC_EAGAIN)
                    {
                        TEST_FAIL("RPC recv() on pco_tst unexpected errno");
                    }
                    else
                    {
                        break;
                    }
                }
                else
                    total_recv += recv_bytes;
            }

            /* Checking for received data */
            for (ii = 0; ii < recv_bytes; ii++)
            {
                j += i;
                m[0] = m[0] + m[1] + m[2] + m[3];

                if (rx_buf[ii] != m[0])
                   TEST_FAIL("Received data corrupted: "
                             "rx_buf[%d]=%d, =%d", 
                             ii, rx_buf[ii], m[0]);
                i++; j++;
            }

        } while (1);

    } while (1);

    if (total_sent != total_recv)
       TEST_FAIL("The number of received(%d) data is not the same as sent(%d)",
                 (int)total_recv, (int)total_sent);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (arp_entry_added &&
        tapi_cfg_del_neigh_entry(pco_gw->ta, gw2_if->if_name, tst_addr) != 0)
    {
        ERROR("Cannot delete ARP entry while cleanup");
        result = EXIT_FAILURE;
    }

    if (route_dst_added &&
        tapi_cfg_del_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw1_addr)) != 0)
    {
        ERROR("Cannot delete route to the dst");
        result = EXIT_FAILURE;
    }

    if (route_src_added &&
        tapi_cfg_del_route_via_gw(pco_tst->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw2_addr)) != 0)
    {
        ERROR("Cannot delete route to the src");
        result = EXIT_FAILURE;
    }

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&gw_mtus));

    TEST_END;
}
