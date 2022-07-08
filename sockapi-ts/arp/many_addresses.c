/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 */

/** @page arp-many_addresses ARP resolving while there are a few IP addresses in use
 *
 * @objective Check that ARP is resolved when a few local and a few remote
 *            IP addresses are used.
 *
 * @type conformance
 *
 * @param pco_iut         PCO on IUT
 * @param pco_tst         PCO on TESTER
 * @param iut_addr        Network address on IUT
 * @param tst_addr        Network address on Tester
 * @param iut_lladdr      Ethernet address on IUT
 * @param tst_lladdr      Ethernet address on Tester
 * @param iut_if          Network interface on IUT
 * @param tst_if          Network interface on Tester
 * @param sock_type       Socket type
 * @param diff_subnet     If @c TRUE, use different subnets in remote IP
 *                        addresses
 * @param addr_num        Number of local and remote IP addresses
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "arp/many_addresses"

#include "sockapi-test.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"
#include "onload.h"
#include "tapi_mem.h"

/**
 * Structure describing a pair of sockets
 * and addresses to which they are bound.
 */
typedef struct socks_pair {
    struct sockaddr_storage iut_addr;   /**< IUT address. */
    struct sockaddr_storage tst_addr;   /**< Tester address. */

    cfg_handle iut_addr_handle1;        /**< Configurator handle
                                             of IUT address. */
    cfg_handle iut_addr_handle2;        /**< Configurator handle
                                             of IUT address assigned
                                             to IUT interface. */
    cfg_handle tst_addr_handle1;        /**< Configurator handle
                                             of Tester address. */
    cfg_handle tst_addr_handle2;        /**< Configurator handle
                                             of Tester address
                                             assigned to Tester
                                             interface. */

    cfg_handle  tst_net_handle;         /**< Configurator handle
                                             of network to which
                                             the tester address
                                             belongs. */
    int         tst_net_prefix;         /**< Tester network prefix. */
    cfg_handle  iut_route_handle;       /**< Route handle on IUT. */

    int iut_s;                          /**< IUT socket. */
    int tst_s;                          /**< Tester socket. */
    int iut_s_listener;                 /**< IUT listener socket. */
    int tst_s_listener;                 /**< Tester listener socket. */
} socks_pair;

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct sockaddr  *iut_lladdr = NULL;
    const struct sockaddr  *tst_lladdr = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    tapi_env_net      *net = NULL;
    struct sockaddr   *addr_aux = NULL;

    char    *net_oid = NULL;

    csap_handle_t   ip_filter_out_handle = CSAP_INVALID_HANDLE;
    csap_handle_t   ip_filter_in_handle = CSAP_INVALID_HANDLE;
    unsigned int    ip_packets = 0;

    socks_pair  *socks = NULL;

    int i;

    sockts_socket_type  sock_type;
    te_bool             diff_subnet;
    int                 addr_num;
    te_dbuf             iut_sent = TE_DBUF_INIT(0);

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_NET(net);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(diff_subnet);
    TEST_GET_INT_PARAM(addr_num);

    socks = tapi_calloc(addr_num, sizeof(*socks));
    for (i = 0; i < addr_num; i++)
    {
        socks[i].iut_addr_handle1 = CFG_HANDLE_INVALID;
        socks[i].iut_addr_handle2 = CFG_HANDLE_INVALID;
        socks[i].tst_addr_handle1 = CFG_HANDLE_INVALID;
        socks[i].tst_addr_handle2 = CFG_HANDLE_INVALID;
        socks[i].tst_net_handle = CFG_HANDLE_INVALID;
        socks[i].iut_route_handle = CFG_HANDLE_INVALID;

        socks[i].iut_s = -1;
        socks[i].tst_s = -1;
        socks[i].iut_s_listener = -1;
        socks[i].tst_s_listener = -1;
    }

    TEST_STEP("Add @p addr_num IP addresses on IUT interface.");
    TEST_STEP("Add @p addr_num IP addresses on Tester interface, use different "
              "subnets or the same as IUT according to @p diff_subnet.");
    TEST_STEP("Add appropriate routes if required.");

    for (i = 0; i < addr_num; i++)
    {
        CHECK_RC(tapi_cfg_alloc_net_addr(net->ip4net,
                                         &socks[i].iut_addr_handle1,
                                         &addr_aux));
        CHECK_RC(tapi_sockaddr_clone(pco_iut, addr_aux,
                                     &socks[i].iut_addr));
        free(addr_aux);
        addr_aux = NULL;

        CHECK_RC(tapi_cfg_base_if_add_net_addr(
                                            pco_iut->ta, iut_if->if_name,
                                            SA(&socks[i].iut_addr),
                                            net->ip4pfx,
                                            FALSE,
                                            &socks[i].iut_addr_handle2));

        if (diff_subnet)
        {
            cfg_val_type  val_type;
            int           prefix;

            CHECK_RC(tapi_cfg_alloc_ip4_net(&socks[i].tst_net_handle));
            CHECK_RC(cfg_get_oid_str(socks[i].tst_net_handle, &net_oid));
            val_type = CVT_INTEGER;
            CHECK_RC(cfg_get_instance_fmt(&val_type, &prefix, "%s/prefix:",
                                          net_oid));
            free(net_oid);
            net_oid = NULL;

            socks[i].tst_net_prefix = prefix;
        }
        else
        {
            socks[i].tst_net_handle = net->ip4net;
            socks[i].tst_net_prefix = net->ip4pfx;
        }

        CHECK_RC(tapi_cfg_alloc_net_addr(socks[i].tst_net_handle,
                                         &socks[i].tst_addr_handle1,
                                         &addr_aux));
        CHECK_RC(tapi_sockaddr_clone(pco_tst, addr_aux,
                                     &socks[i].tst_addr));
        free(addr_aux);
        addr_aux = NULL;

        CHECK_RC(tapi_cfg_base_if_add_net_addr(
                                            pco_tst->ta, tst_if->if_name,
                                            SA(&socks[i].tst_addr),
                                            socks[i].tst_net_prefix,
                                            FALSE,
                                            &socks[i].tst_addr_handle2));

        if (diff_subnet)
        {
            CHECK_RC(tapi_cfg_add_route(
                          pco_iut->ta, AF_INET,
                          te_sockaddr_get_netaddr(SA(&socks[i].tst_addr)),
                          socks[i].tst_net_prefix, NULL, iut_if->if_name,
                          NULL, 0, 0, 0, 0, 0, 0,
                          &socks[i].iut_route_handle));
        }
    }

    CFG_WAIT_CHANGES;

    TEST_STEP("In a loop for @p addr_num times:");
    for (i = 0; i < addr_num; i++)
    {
        TEST_SUBSTEP("Create a pair of sockets on IUT and Tester, "
                     "bind them to the next pair of added addresses, "
                     "establish TCP connection or send a datagram from IUT "
                     "(according to @p sock_type) to provoke ARP requests.");
        sockts_connection_begin(pco_iut, pco_tst,
                                SA(&socks[i].iut_addr),
                                SA(&socks[i].tst_addr),
                                sock_type, &socks[i].iut_s,
                                &socks[i].iut_s_listener,
                                &socks[i].tst_s,
                                &socks[i].tst_s_listener,
                                &iut_sent);

        sockts_connection_end(pco_iut, pco_tst,
                              SA(&socks[i].iut_addr),
                              SA(&socks[i].tst_addr),
                              sock_type, &socks[i].iut_s,
                              &socks[i].iut_s_listener,
                              &socks[i].tst_s,
                              &socks[i].tst_s_listener,
                              &iut_sent);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Create CSAPs listening for IP packets sent between "
              "the two hosts (on IUT).");

    START_ETH_FILTER(pco_iut->ta,
                     iut_if->if_name,
                     TAD_ETH_RECV_HOST |
                     TAD_ETH_RECV_NO_PROMISC,
                     CVT_HW_ADDR(tst_lladdr),
                     CVT_HW_ADDR(iut_lladdr),
                     ETHERTYPE_IP,
                     0, ip_filter_in_handle);

    START_ETH_FILTER(pco_iut->ta,
                     iut_if->if_name,
                     TAD_ETH_RECV_OUT |
                     TAD_ETH_RECV_NO_PROMISC,
                     CVT_HW_ADDR(iut_lladdr),
                     CVT_HW_ADDR(tst_lladdr),
                     ETHERTYPE_IP,
                     0, ip_filter_out_handle);

    TEST_STEP("Check data transmission in both directions for "
              "each sockets couple.");
    for (i = 0; i < addr_num; i++)
    {
        sockts_test_connection_ext(pco_iut, socks[i].iut_s,
                                   pco_tst, socks[i].tst_s,
                                   SA(&socks[i].tst_addr), sock_type);
    }

    TEST_STEP("Check that traffic is detected on IUT interface if and only if "
              "the test is run on Linux (not on Onload).");

    STOP_ETH_FILTER(pco_iut->ta, ip_filter_in_handle, ip_packets);
    if (tapi_onload_run())
    {
        if (ip_packets != 0)
            TEST_VERDICT("Incoming traffic was not accelerated");
    }
    else
    {
        if (ip_packets == 0)
            TEST_VERDICT("Incoming traffic was not detected");
    }

    STOP_ETH_FILTER(pco_iut->ta, ip_filter_out_handle, ip_packets);
    if (tapi_onload_run())
    {
        if (ip_packets != 0)
            TEST_VERDICT("Outgoing traffic was not accelerated");
    }
    else
    {
        if (ip_packets == 0)
            TEST_VERDICT("Outgoing traffic was not detected");
    }

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < addr_num; i++)
    {
        CLEANUP_RPC_CLOSE(pco_tst, socks[i].tst_s);
        CLEANUP_RPC_CLOSE(pco_tst, socks[i].tst_s_listener);
        CLEANUP_RPC_CLOSE(pco_iut, socks[i].iut_s);
        CLEANUP_RPC_CLOSE(pco_iut, socks[i].iut_s_listener);

        CLEANUP_CHECK_RC(cfg_del_instance(socks[i].iut_addr_handle2,
                                          FALSE));
        CLEANUP_CHECK_RC(cfg_del_instance(socks[i].tst_addr_handle2,
                                          FALSE));
        CLEANUP_CHECK_RC(tapi_cfg_free_entry(&socks[i].iut_addr_handle1));
        CLEANUP_CHECK_RC(tapi_cfg_free_entry(&socks[i].tst_addr_handle1));
        if (socks[i].tst_net_handle != CFG_HANDLE_INVALID && diff_subnet)
            CLEANUP_CHECK_RC(tapi_cfg_free_entry(&socks[i].tst_net_handle));
    }

    CFG_WAIT_CHANGES;

    if (ip_filter_in_handle != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0,
                                               ip_filter_in_handle));

    if (ip_filter_out_handle != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0,
                                               ip_filter_out_handle));

    free(addr_aux);
    free(socks);
    free(net_oid);
    te_dbuf_free(&iut_sent);

    TEST_END;
}
