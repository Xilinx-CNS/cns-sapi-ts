/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id$
 */

/** @page arp-if_ll_addr_1 Change MAC address after socket creation
 *
 * @objective Change MAC address of an interface after a socket is
 *            created. Check that the new MAC address is used by the
 *            traffic originated from the socket.
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
 * -# Create @p iut_s socket of type @p sock_type on @p pco_iut;
 * -# Create @p tst_s socket of type @c sock_type on @p pco_tst;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Change @p iut_if interface link layer address to new one;
 * -# Add valid arp entry to access TST side through @p iut_if
 *    on IUT side (To exclude IUT side's ARP resolution);
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b bind() @p iut_s socket to @p iut_addr;
 * -# @b bind() @p tst_s socket to @p tst_addr;
 * -# Run ARP filter on TST side to catch IUT side's ARP reply;
 * -# Run Ether filter on TST side to catch IUT side's IP packets;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# In the case @p local_server is @c TRUE:
 *     - if @p sock_type is @c SOCK_STREAM:
 *         - @b listen() on @p iut_s socket;
 *         - @b connect() @p tst_s socket to @p pco_iut server;
 *    \n @htmlonly &nbsp; @endhtmlonly
 *     - if @p sock_type is @c SOCK_DGRAM:
 *         - @b sendto() some data through @p tst_s to @p iut_s;
 *         - @b sendto() some data through @p iut_s to @p tst_s;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# In the case @p local_server is @c FALSE:
 *     - if @p sock_type is @c SOCK_STREAM:
 *         - Call @b listen() on @p tst_s socket;
 *         - @b connect() @p iut_s socket to @p pco_tst server;
 *     - if @p sock_type is @c SOCK_DGRAM:
 *         - @b sendto() some data through @p iut_s to @p tst_s;
 *         - @b sendto() some data through @p tst_s to @p iut_s;
 * -# Stop both ARP and Ether filters;
 * -# Check that both filters have detected appropriate ARP and IP
 *    packets with changed link layer interface address;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close opened sockets and frees allocated resources.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "arp/if_ll_addr_1"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"
#include "tapi_route_gw.h"

#undef TST_HANDOVER

int
main(int argc, char *argv[])
{
    rpc_socket_type             sock_type;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rcf_rpc_server        *pco_srv = NULL;
    rcf_rpc_server        *pco_cln = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    const struct sockaddr *srv_addr = NULL;
    const struct sockaddr *cln_addr = NULL;

    const struct sockaddr  *iut_lladdr = NULL;
    const struct sockaddr  *tst_lladdr = NULL;
    const struct sockaddr  *alien_link_addr = NULL;
    struct sockaddr         cache_hwaddr;

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    srv_s = -1;
    int                    cln_s = -1;

    void                  *tx_buf = NULL;
    size_t                 tx_buflen = 1024;
    void                  *rx_buf = NULL;
    size_t                 rx_buflen = 1024;

    char                   opt_ifname[IFNAMSIZ];

    int                    arp_flags;
    te_bool                arp_entry_exist;

    csap_handle_t          arp_catcher = CSAP_INVALID_HANDLE;
    csap_handle_t          ip_catcher = CSAP_INVALID_HANDLE;
    unsigned int           arp_frames = 0;
    unsigned int           ip_frames = 0;
    te_bool                local_server;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(local_server);

    strncpy(opt_ifname, iut_if->if_name, IFNAMSIZ);

    /* Prepare buffers */
    tx_buf = te_make_buf_by_len(tx_buflen);
    rx_buf = te_make_buf_by_len(rx_buflen);

    /* Prepare sockets */
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, RPC_AF_INET, sock_type, RPC_PROTO_DEF);

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



    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      iut_addr));
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(tst_lladdr), FALSE));

    if (local_server == TRUE)
    {
        pco_srv = pco_iut;
        srv_s = iut_s;
        srv_addr = iut_addr;
        pco_cln = pco_tst;
        cln_s = tst_s;
        cln_addr = tst_addr;
    }
    else
    {
        pco_srv = pco_tst;
        srv_s = tst_s;
        srv_addr = tst_addr;
        pco_cln = pco_iut;
        cln_s = iut_s;
        cln_addr = iut_addr;
    }

    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);


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

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_srv, srv_s, SOCKTS_BACKLOG_DEF);


        rpc_connect(pco_cln, cln_s, srv_addr);

    }
    else if (sock_type == RPC_SOCK_DGRAM)
    {

        rc = rpc_sendto(pco_cln, cln_s, tx_buf, tx_buflen, 0, srv_addr);
        if (rc != (int)tx_buflen)
            TEST_FAIL("Unexpectedly sendto(cln) returns %d instead of %d",
                      rc, tx_buflen);

        rc = rpc_sendto(pco_srv, srv_s, tx_buf, tx_buflen, 0, cln_addr);
        if (rc != (int)tx_buflen)
            TEST_FAIL("Unexpectedly sendto(srv) returns %d instead of %d",
                      rc, tx_buflen);
    }

    TAPI_WAIT_NETWORK;

    /* Stop ARP catcher on TST side */
    STOP_ETH_FILTER(pco_tst->ta, arp_catcher, arp_frames);
    /* Check the absence of ARP requests */
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
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                               arp_catcher));
    if (pco_tst != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, ip_catcher));

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
