/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP.
 *
 * $Id: mcast_mac_via_gw.c 65286 2010-07-13 11:01:05Z rast $
 */

/** @page multicast-mcast_mac_via_gw MAC address when sending via gateway.
 *
 * @objective Check that multicast packet has appropriate
 *            destination MAC address when sending via gateway.
 *
 * @type Conformance
 *
 * @param pco_tst       PCO on Tester
 * @param pco_iut       PCO on IUT
 * @param iut_addr      Address on IUT
 * @param tst_addr      Address on Tester
 * @param mcast_addr    Multicast address
 * @param iut_ll_addr   IUT link-level address
 * @param tst_ll_addr   Tester link-level address
 * @param tst_if        Tester interace connected to IUT
 * @param iut_if        IUT interace connected to Tester
 * @param data_len      Datagram size
 * @param connect_iut   Connect @p iut_s and use @b send() instead of
 *                      @b sendto()
 * @param bind_iut      Bind @p iut_s socket to iut_addr
 * @param packet_number Number of datagrams to send for reliability.
 * @param use_route     If @c TRUE, add a route to mcast_addr on IUT.
 * @param prefix        destination prefix for route on @p pco_iut.
 * @param opt_name      Option to be tested.
 *
 * @par Test sequence:
 * -# If @p prefix is zero, remove default route on @p pco_iut.
 * -# Clear @p mcast_addr according to @p prefix and use the result as a
 *    destination addres for a route on @p pco_iut via gateway @p tst_addr.
 * -# Create datagram socket @p iut_s on @p pco_iut. If @p bind_iut is
 *    @c TRUE, bind it to @p iut_addr, if @p connect_iut is @c TRUE,
 *    connect it to @p tst_addr.
 * -# Send datagram in order to resolve ARP.
 * -# Create CSAP on Tester to catch packets from IUT. Start listening.
 * -# Send @p packet_number @p data_len bytes long datagrams from @p iut_s
 *    to @p mcast_addr.
 * -# Stop the CSAP. Make sure it has caught the multicast datagrams.
 *    Check destination MAC address.
 * -# Issue verdicts.
 * -# Recover the initial state of routes on @p pco_iut.
 * -# Close socket.
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_mac_via_gw"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_ip4.h"
#include "mcast_lib.h"
#include "multicast.h"

#ifndef ETH_ALEN
#define ETH_ALEN        6
#endif

struct callback_data {
    const char *tst_mac;
    uint8_t  mcast_mac[ETH_ALEN];
    int      mcast_pkts;
    int      ucast_pkts;
    int      inval_pkts;
    int      udp_pkts;
};

/**
 * Callback function to proceed received packets.
 *
 * @param pkt        Pointer to packet received
 * @param user_data  User data;
 */
void
check_dst_mac_callback(asn_value *pkt, void *user_data)
{
    int         rc;
    uint8_t     dst_mac[ETH_ALEN];
    size_t      len = sizeof(dst_mac);
    uint16_t    offset;

    struct callback_data *data = user_data;

    rc = asn_read_value_field(pkt, dst_mac, &len,
                              "pdus.1.#eth.dst-addr.#plain");
    if (rc != 0 || len != ETH_ALEN)
        TEST_FAIL("Failed to parse captured Ethernet packet");

    if (memcmp(dst_mac, data->mcast_mac, ETH_ALEN) == 0)
        data->mcast_pkts++;
    else if (memcmp(dst_mac, data->tst_mac, ETH_ALEN) == 0)
        data->ucast_pkts++;
    else
        data->inval_pkts++;


    len = sizeof(offset);
    rc = asn_read_value_field(pkt, &offset, &len,
                              "pdus.0.#ip4.frag-offset.#plain");
    if (rc != 0 || len != sizeof(offset))
        TEST_FAIL("Failed to parse captured IP packet");

    if (offset == 0)
        data->udp_pkts++;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;

    int             s_tst;           /* Session on Tester */
    csap_handle_t   tst_csap =       /* CSAP on Tester */
                        CSAP_INVALID_HANDLE;

    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *mcast_addr = NULL;
    struct sockaddr            dst_addr;
    uint8_t                   *sendbuf = NULL;
    unsigned int               num = 0;
    const struct sockaddr     *iut_ll_addr = NULL;
    const struct sockaddr     *tst_ll_addr = NULL;
    socklen_t                  data_len = 0;
    int                        i;
    int                        packet_number;
    te_bool                    connect_iut;
    te_bool                    bind_iut;
    te_bool                    route_mcast_added    = FALSE;
    te_bool                    use_route;
    unsigned int               prefix;
    rpc_sockopt                opt_name;

    tapi_rt_entry_t           *rt_tbl;
    tapi_rt_entry_t           *rt_def = NULL;
    unsigned int               rt_num;

    cfg_handle                 rt_hndl = CFG_HANDLE_INVALID;
    cfg_handle                 cfg_hndl;
    struct sockaddr_storage    zero_addr;

    rpc_socket_domain          domain;
    int                        af;

    mcast_listener_t listener = CSAP_INVALID_HANDLE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_LINK_ADDR(iut_ll_addr);
    TEST_GET_LINK_ADDR(tst_ll_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_BOOL_PARAM(bind_iut);
    TEST_GET_BOOL_PARAM(use_route);
    TEST_GET_INT_PARAM(prefix);
    TEST_GET_SOCKOPT(opt_name);

    domain  = rpc_socket_domain_by_addr(iut_addr);
    af = addr_family_rpc2h(sockts_domain2family(domain));

    sendbuf = te_make_buf_by_len(data_len);

    memset(&zero_addr, 0, sizeof(zero_addr));
    zero_addr.ss_family = af;

    memcpy(&dst_addr, mcast_addr, sizeof(dst_addr));
    te_sockaddr_cleanup_to_prefix(&dst_addr, prefix);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    if (bind_iut)
        rpc_bind(pco_iut, iut_s, iut_addr);

    if (use_route)
    {
        if (prefix == 0)
        {
            cfg_val_type     val_type;
            char            *def_ifname;

            char             oid_str[128];
            char             val_str[128];

            /* Get default route interface */
            val_type = CVT_STRING;
            if (cfg_get_instance_fmt(&val_type, &def_ifname,
                "/agent:%s/ip4_rt_default_if:", pco_iut->ta) != 0)
                TEST_FAIL("It's impossible to get instance of "
                          "ip4_rt_default_if");

            snprintf(oid_str, 128, "/agent:%s/interface:%s",
                     pco_iut->ta, def_ifname);
            snprintf(val_str, 128,  "/agent:%s/rsrc:%s",
                     pco_iut->ta, def_ifname);
            /* Reserve interface used by default route for test purposes */
            if (cfg_add_instance_fmt(NULL, val_type, oid_str, val_str) != 0)
                TEST_FAIL("It's impossible to reserve %s resource on %s",
                          def_ifname, pco_iut->ta);

            /* Get routing table and find default route */
            CHECK_RC(tapi_cfg_get_route_table(pco_iut->ta, af,
                                              &rt_tbl, &rt_num));
            for (i = 0; i < (int)rt_num; i++)
            {
                if (rt_tbl[i].prefix == 0 &&
                    rt_tbl[i].dst.ss_family == af &&
                    rt_tbl[i].table == TAPI_RT_TABLE_MAIN)
                {
                    rt_def = &rt_tbl[i];
                    CHECK_RC(tapi_cfg_del_route(&(rt_tbl[i].hndl)));
                    break;
                }
            }
            CFG_WAIT_CHANGES;
            /* Add default route on 'pco_iut' via 'tst_addr' */
            if (tapi_cfg_add_route(pco_iut->ta, af,
                    te_sockaddr_get_netaddr(SA(&zero_addr)), prefix,
                    te_sockaddr_get_netaddr(tst_addr),
                    NULL, NULL, 0, 0, 0, 0, 0, 0, &cfg_hndl) != 0)
            {
                TEST_FAIL("Cannot add route to the dst");
            }
        }
        else
        {
            /* Add route on 'pco_iut': 'mcast_addr' via 'tst_addr' */
            if (tapi_cfg_add_route_via_gw(pco_iut->ta, af,
                    te_sockaddr_get_netaddr(&dst_addr), prefix,
                    te_sockaddr_get_netaddr(tst_addr)) != 0)
            {
                TEST_FAIL("Cannot add route to the dst");
            }
        }
        route_mcast_added = TRUE;
    }

    switch (opt_name)
    {
        case RPC_SO_BINDTODEVICE:
            rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                               iut_if->if_name, (strlen(iut_if->if_name) + 1));
            break;
        case RPC_IP_MULTICAST_IF:
            set_ip_multicast_if(pco_iut, iut_s, iut_addr);
            break;
        default:
            RING("No option");
            break;
    }

    CFG_WAIT_CHANGES;

    /* Resolve ARP */
    rpc_sendto(pco_iut, iut_s, sendbuf, data_len, 0, tst_addr);

    if (connect_iut)
        rpc_connect(pco_iut, iut_s, mcast_addr);

    /* Create CSAP that controls incoming packets on Tester */
    rcf_ta_create_session(pco_tst->ta, &s_tst);
    if (tapi_ip4_eth_csap_create(pco_tst->ta, s_tst, tst_if->if_name,
                            TAD_ETH_RECV_DEF,
                            NULL,
                            (const unsigned char *)(iut_ll_addr->sa_data),
                            SIN(mcast_addr)->sin_addr.s_addr,
                            SIN(iut_addr)->sin_addr.s_addr,
                            IPPROTO_UDP, &tst_csap) != 0)
    {
        TEST_FAIL("Cannot create CSAP on Tester");
    }

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, s_tst, tst_csap, NULL,
                                   TAD_TIMEOUT_INF, 10,
                                   RCF_TRRECV_PACKETS));

    listener = mcast_listener_init(pco_iut, iut_if, mcast_addr, NULL, 0);
    mcast_listen_start(pco_iut, listener);

    /* See bug 9644 */
    TAPI_WAIT_NETWORK;

    for (i = 0; i < packet_number; i++)
    {
        if (connect_iut)
            rpc_send(pco_iut, iut_s, sendbuf, data_len, 0);
        else
            rpc_sendto(pco_iut, iut_s, sendbuf, data_len, 0, mcast_addr);

    }

    TAPI_WAIT_NETWORK;

    rc = mcast_listen_stop(pco_iut, listener, NULL);
    if (rc > 0)
        RING_VERDICT("Multicast packet was detected by system");

    {
        tapi_tad_trrecv_cb_data     cb_data;
        struct callback_data        data;

        data.mcast_pkts = data.ucast_pkts = data.inval_pkts = 0;
        data.udp_pkts = 0;
        data.tst_mac = tst_ll_addr->sa_data;
        data.mcast_mac[0] = 0x01;
        data.mcast_mac[1] = 0x00;
        data.mcast_mac[2] = 0x5e;
        memcpy(&data.mcast_mac[3],
               (uint8_t *)te_sockaddr_get_netaddr(mcast_addr) + 1,
               3);
        data.mcast_mac[3] &= 0x7F;
        cb_data.callback = check_dst_mac_callback;
        cb_data.user_data = &data;

        CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, s_tst, tst_csap,
                                      &cb_data, &num));
        RING("Captured: %d multicast, %d unicast and %d other packets; "
             "among them %d IP packets with offset=0",
             data.mcast_pkts, data.ucast_pkts, data.inval_pkts,
             data.udp_pkts);

        if (data.inval_pkts != 0)
            TEST_VERDICT("Got packets with incorrect MAC address");
        if (data.udp_pkts != packet_number)
        {
            TEST_VERDICT("Got %d packets instead of %d",
                         data.udp_pkts, packet_number);
        }
        if ((data.mcast_pkts + data.ucast_pkts) % packet_number)
            TEST_VERDICT("Not all IP fragments are captured");
        if (data.mcast_pkts == 0)
            RING_VERDICT("Multicast packets are sent with unicast MAC");
        else if (data.ucast_pkts != 0)
            RING_VERDICT("Some multicast packets are sent with unicast MAC");
    }

    TEST_SUCCESS;

cleanup:
    mcast_listener_fini(pco_iut, listener);
    free(sendbuf);
    if (tst_csap != CSAP_INVALID_HANDLE)
    {
        if ((rc = tapi_tad_csap_destroy(pco_tst->ta,
                                      s_tst, tst_csap)) != 0)
        {
            ERROR("tapi_tad_csap_destroy() failed: %r", rc);
            result = -1;
        }
    }

    if (route_mcast_added)
    {
        if (prefix != 0)
        {
            if (tapi_cfg_del_route_via_gw(pco_iut->ta, af,
                    te_sockaddr_get_netaddr(&dst_addr),
                    prefix,
                    te_sockaddr_get_netaddr(tst_addr)) != 0)
            {
                ERROR("Cannot delete route to the dst");
                result = EXIT_FAILURE;
            }
        }
        else
        {
            if (rt_def != NULL && rt_def->hndl == CFG_HANDLE_INVALID)
            {
                tapi_cfg_del_route(&cfg_hndl);
                tapi_cfg_add_route(pco_iut->ta, af,
                    te_sockaddr_get_netaddr(SA(&zero_addr)), 0,
                    (rt_def->flags & TAPI_RT_GW) ?
                    te_sockaddr_get_netaddr(SA(&(rt_def->gw))) : NULL,
                    (rt_def->flags & TAPI_RT_IF) ? rt_def->dev : NULL,
                    NULL, rt_def->flags, rt_def->metric, 0,
                    rt_def->mtu, rt_def->win, rt_def->irtt, &rt_hndl);
            }
        }
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
