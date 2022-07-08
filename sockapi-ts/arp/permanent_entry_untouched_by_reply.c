/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id$
 */

/** @page arp-permanent_entry_untouched_by_reply ARP reply does not change permanent ARP table entry
 *
 * @objective Send() or connect() to an unknown address to provoke ARP
 *            request. Add permanent ARP table entry. Send ARP reply
 *            from a peer with a different MAC address. Check that
 *            permanent ARP table entry remains unchanged.
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_addr          Network address on IUT
 * @param tst_addr          Network address on Tester
 * @param iut_lladdr        Ethernet address on IUT
 * @param tst_lladdr        Ethernet address on Tester
 * @param alien_link_addr   Alien link address
 * @param iut_if            Network interface on IUT
 * @param tst_if            Network interface on Tester
 * @param sock_type         Socket type
 *
 * @par Test sequence:
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME "arp/permanent_entry_untouched_by_reply"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    tapi_env_net           *net = NULL;

    const struct sockaddr  *iut_lladdr = NULL;
    const struct sockaddr  *tst_lladdr = NULL;
    const struct sockaddr  *alien_link_addr = NULL;
    struct sockaddr        *new_addr = NULL;
    cfg_handle              new_addr_handle = CFG_HANDLE_INVALID;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    int iut_s = -1;
    int tst_s = -1;
    int iut_s_listener = -1;
    int tst_s_listener = -1;

    te_bool is_static = FALSE;
    uint8_t hwaddr[ETHER_ADDR_LEN];

    te_dbuf iut_sent = TE_DBUF_INIT(0);

    csap_handle_t arp_filter_handle = CSAP_INVALID_HANDLE;
    unsigned int  pkts_num = 0;

    sockts_socket_type sock_type;

    /* Preambule */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_NET(net);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_LINK_ADDR(alien_link_addr);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    SOCKTS_GET_SOCK_TYPE(sock_type);

    /* Scenario */

    TEST_STEP("Allocate a new IP address @b new_addr from the same network "
              "as @p tst_addr, choosing it so that there is no neighbor "
              "entry on IUT for it yet. Assign it to @p tst_if interface.");

    sockts_alloc_addr_without_arp_entry(net, pco_iut,
                                        iut_if->if_name, &new_addr);
    CHECK_RC(tapi_allocate_set_port(pco_tst, new_addr));

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           new_addr, net->ip4pfx,
                                           TRUE, &new_addr_handle));

    CFG_WAIT_CHANGES;

    TEST_CHECK_ARP_ENTRY_IS_DELETED(pco_iut->ta, iut_if->if_name,
                                    new_addr);

    TEST_STEP("Disable ARP on TESTER interface, add static ARP entry "
              "for @p iut_addr.");
    CHECK_RC(tapi_cfg_base_if_arp_disable(pco_tst->ta, tst_if->if_name));
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             iut_addr, CVT_HW_ADDR(iut_lladdr), TRUE));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a pair of sockets on IUT and Tester according "
              "to @p sock_type. In case of TCP start nonblocking connection "
              "establishment; in case of UDP call @b send() or @b sendto() "
              "on IUT. Use @b new_addr as destination on IUT. This should "
              "result in sending ARP requests to resolve @b new_addr.");
    sockts_connection_begin(pco_iut, pco_tst, iut_addr, new_addr,
                            sock_type, &iut_s, &iut_s_listener,
                            &tst_s, &tst_s_listener, &iut_sent);

    TEST_STEP("Wait for some time for ARP requests to be sent.");
    /* We MUST NOT wait longer than 3s because connect(tcp_sock)
     * will time out. */
    MSLEEP(2800);

    TEST_STEP("Add permanent ARP entry for @b new_addr on IUT.");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             new_addr, CVT_HW_ADDR(tst_lladdr), TRUE));
    CFG_WAIT_CHANGES;

    TEST_STEP("Check that after adding permanent ARP entry no ARP "
              "requests are sent.");

    START_ARP_FILTER_WITH_HDR(pco_tst->ta, tst_if->if_name,
                              CVT_HW_ADDR(iut_lladdr), NULL,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              NULL, NULL,
                              CVT_PROTO_ADDR(new_addr),
                              NULL, 0, arp_filter_handle);
    /* ARP spec requires to send ARP every minute. */
    SLEEP(60);
    STOP_ETH_FILTER(pco_tst->ta, arp_filter_handle, pkts_num);

    if (pkts_num > 0)
        ERROR_VERDICT("ARP requests were sent after adding static ARP "
                      "table entry");

    TEST_STEP("Generate and send invalid ARP reply from @p pco_tst to @p pco_iut. "
              "This reply must not touch permanent ARP entry.");
    START_ARP_SENDER(pco_tst->ta, tst_if->if_name,
                     CVT_HW_ADDR(alien_link_addr),
                     CVT_HW_ADDR(iut_lladdr),
                     ARPOP_REPLY,
                     CVT_PROTO_ADDR(new_addr),
                     CVT_HW_ADDR(alien_link_addr),
                     CVT_PROTO_ADDR(iut_addr),
                     CVT_HW_ADDR(iut_lladdr), 1, NULL);

    TEST_STEP("In case of TCP, finish connection establishment. In case of UDP, "
              "receive a packet on Tester.");
    sockts_connection_end(pco_iut, pco_tst, iut_addr, new_addr,
                          sock_type, &iut_s, &iut_s_listener,
                          &tst_s, &tst_s_listener, &iut_sent);

    TEST_STEP("Check that data can be sent and received in both directions "
              "with help of the sockets.");
    sockts_test_connection_ext(pco_iut, iut_s, pco_tst, tst_s,
                               new_addr, sock_type);

    TEST_STEP("Get @b new_addr ARP entry on IUT, check that hardware address "
              "is set right and ARP entry is permanent.");
    rc = tapi_cfg_get_neigh_entry(pco_iut->ta, iut_if->if_name,
                                  new_addr, hwaddr, &is_static, NULL);
    if (rc == TE_RC(TE_CS, TE_ENOENT))
        TEST_FAIL("Test expected that ARP entry "
                  "with Tester address exists");
    else if (rc != 0)
        TEST_FAIL("Unexpected failure of tapi_cfg_get_neigh_entry(): %r",
                  rc);
    else if (!is_static)
        TEST_VERDICT("Static ARP entry became dynamic");
    else if (memcmp(hwaddr, CVT_HW_ADDR(tst_lladdr), ETHER_ADDR_LEN) != 0)
        TEST_VERDICT("Static ARP entry HW address was updated to invalid "
                     "value");

    TEST_SUCCESS;

cleanup:

    /*
     * It's very importent to close all sockets for delition ARP entry.
     * It seems the socket closed by OS keeps refcount for ARP entry
     * for a long time.
     */

    /* Avoid TIME_WAIT socket on IUT in case of TCP */
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_STREAM)
        TAPI_WAIT_NETWORK;
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listener);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listener);

    if (arp_filter_handle != CSAP_INVALID_HANDLE)
    {
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                               arp_filter_handle));
    }

    CLEANUP_CHECK_RC(cfg_del_instance(new_addr_handle, FALSE));
    CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                              new_addr));
    free(new_addr);

    /* Added static ARP entries are deleted by configuration rollback */
    TEST_END;
}
