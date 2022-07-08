/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-ip_mtu_discover_udp Path MTU discovery on SOCK_DGRAM socket
 *
 * @objective Check possibility of performing Path MTU discovery
 *            functionality on @c SOCK_DGRAM type socket.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_gw        Host in the tested network that is able to forward
 *                      incoming packets (router)
 * @param pco_tst       PCO on TESTER
 * @param connected     Tells which socket to use for sending message:
 *                      - @c TRUE - connected: use @b send()
 *                      - @c FALSE - not connected: use @b sendto()
 * @param pmtu_val      Path MTU discovery value:
 *                      - @c PMTU_DISCOVER_WANT
 *                      - @c PMTU_DISCOVER_DONT
 *                      - @c PMTU_DISCOVER_DO
 *                      - @c PMTU_DISCOVER_PROBE
 * @param ip_recverr    If @c TRUE, use socket option @c IP_RECVERR
 *                      (@c IPV6_RECVERR for IPv6) to read message from
 *                      error queue
 * @param route_direct  Use direct route or not
 *                      - @c TRUE - use default prefix length
 *                      - @c FALSE - use 24 for prefix length
 *
 * @par Test sequence:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 * @author Damir Mansurov <dnman@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ip_mtu_discover_udp"

#include "sockopts_common.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"
#include "parse_icmp.h"
#include "te_ethernet.h"

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#ifndef ICMP6_PACKET_TOO_BIG
#define ICMP6_PACKET_TOO_BIG 2
#endif

#define TST_BUF_LEN       65535
/* some reserve of bytes */
#define TST_UDP_RSV       100

/* The test does not use MTU values, less than declared */
#define MIN_PMTU_IPV4               576
#define MIN_PMTU_IPV6               1280

#define MTU_EXPIRES_VALUE           60
#define TST_TIME_TO_SLEEP           1
#define TIME_TO_WAIT_MTU_INCREASING ((MTU_EXPIRES_VALUE * 2) / \
                                     TST_TIME_TO_SLEEP)

#define IP_MTU_MODES \
    {"want", IP_PMTUDISC_WANT},    \
    {"dont", IP_PMTUDISC_DONT},  \
    {"do", IP_PMTUDISC_DO},   \
    {"probe", IP_PMTUDISC_PROBE}

/* IMDU - Ip Mtu Discover Udp */
#define IMDU_CHECK_RECEIVE(_sent, _tx_buf, _pco_rcv, _rcv_s, \
                           _rx_buf, _rx_buf_len, _msg)                      \
    do {                                                                    \
        memset(_rx_buf, 0, _rx_buf_len);                                    \
        int _received = rpc_recv(_pco_rcv, _rcv_s, _rx_buf, _rx_buf_len, 0);\
        if (_sent != _received)                                             \
            TEST_VERDICT(_msg ": unexpected number of bytes was "           \
                         "received");                                       \
        if (memcmp(_tx_buf, _rx_buf, _sent) != 0)                           \
            TEST_VERDICT(_msg ": received data "                            \
                         "does not match with sent data");                  \
    } while (0)

/* Check that ip error queue containts only one icmp message with
   specific params */
static void
check_iperrque_msg(rcf_rpc_server *pco, int pco_s, rpc_msghdr *msghdr,
                   const char *msg, uint32_t exp_ee_origin, uint8_t exp_ee_type,
                   uint8_t exp_ee_code, uint32_t exp_ee_info, te_bool is_ipv6)
{
    struct cmsghdr             *cmsg = NULL;
    struct sock_extended_err   *see;
    int                         res;

    msghdr->msg_controllen = SOCKTS_CMSG_LEN;

    RPC_AWAIT_IUT_ERROR(pco);
    res = rpc_recvmsg(pco, pco_s, msghdr, RPC_MSG_ERRQUEUE);
    if (res < 0)
        TEST_VERDICT("%s: recvmsg() unexpectedly failed with errno %r",
                     msg, RPC_ERRNO(pco));

    if(is_ipv6)
        cmsg  = sockts_msg_lookup_control_data(msghdr, SOL_IPV6, IPV6_RECVERR);
    else
        cmsg  = sockts_msg_lookup_control_data(msghdr, SOL_IP, IP_RECVERR);

    if (cmsg == NULL)
        TEST_FAIL("%s: ancillary data is not received", msg);

    see = (struct sock_extended_err *) CMSG_DATA(cmsg);
    sockts_print_sock_extended_err(see);

    if (see->ee_errno != EMSGSIZE)
        TEST_VERDICT("%s: unexpected ee_errno %s, expected EMSGSIZE",
                     msg, errno_rpc2str(errno_h2rpc(see->ee_errno)));

    if (see->ee_origin != exp_ee_origin)
        TEST_VERDICT("%s: unexpected ee_origin %d, expected %d",
                     msg, see->ee_origin, exp_ee_origin);

    if (see->ee_type != exp_ee_type)
        TEST_VERDICT("%s: unexpected ee_type %d, expected %d",
                     msg, see->ee_type, exp_ee_type);

    if (see->ee_code != exp_ee_code)
        TEST_VERDICT("%s: unexpected ee_code %d, expected %d",
                     msg, see->ee_code, exp_ee_code);

    if (see->ee_info != exp_ee_info)
        TEST_VERDICT("%s: unexpected ee_info %d, expected %d",
                     msg, see->ee_info, exp_ee_info);

    check_iperrque_is_empty(pco, pco_s, msghdr, msg);
}

/* Check ipv4 or ipv6 is using in test */
te_bool ip_version_6(const struct sockaddr *addr)
{
    return addr->sa_family == AF_INET6 ? TRUE : FALSE;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_gw  = NULL;
    tapi_env_host      *iut_host  = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    int                 iut_s = -1;
    int                 aux_s = -1;
    int                 tst_s = -1;

    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *gw_iut_addr = NULL;
    const struct sockaddr *gw_tst_addr = NULL;

    struct sockaddr         *new_iut_addr = NULL;
    struct sockaddr         *new_tst_addr = NULL;
    struct sockaddr         *new_gw_iut_addr = NULL;
    struct sockaddr         *new_gw_tst_addr = NULL;

    te_bool                route_dst_added = FALSE;
    te_bool                route_src_added = FALSE;
    te_bool                neigh_gw_iut_entry_added = FALSE;
    te_bool                neigh_gw_tst_entry_added = FALSE;

    int                    mtu_sock_saved;
    int                    mtu_sock_current;
    int                    mtu_gw_saved;
    int                    mtu_lo_saved;
    int                    mtu_gw_new;

    int                    pmtu_flags_saved;
    int                    pmtu_flags;

    uint8_t                tx_buf[TST_BUF_LEN];
    uint8_t                rx_buf[TST_BUF_LEN];
    size_t                 buf_len;
    uint8_t                iut_if_mac[ETHER_ADDR_LEN];
    uint8_t                tst_if_mac[ETHER_ADDR_LEN];
    size_t                 mac_len = ETHER_ADDR_LEN;
    int                    received;
    int                    sent;


    cfg_val_type                 type = CVT_INTEGER;
    const struct if_nameindex   *gw_tst_if = NULL;
    const struct if_nameindex   *gw_iut_if = NULL;
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;

    int i;

    rpc_socket_domain domain;
    int               ret;

    cfg_handle              net_handle1;
    cfg_handle              net_handle2;

    cfg_handle              h1 = CFG_HANDLE_INVALID;
    cfg_handle              h2 = CFG_HANDLE_INVALID;
    cfg_handle              h3 = CFG_HANDLE_INVALID;
    cfg_handle              h4 = CFG_HANDLE_INVALID;

    char                  *net_oid;
    unsigned int           net_prefix;
    te_bool                connected = FALSE;
    int                    pmtu_val;
    int                    old_mtu_expires_val = -1;
    te_bool                ip_recverr;
    rpc_msghdr             msg;

    te_saved_mtus   gw_mtus = LIST_HEAD_INITIALIZER(gw_mtus);

    te_bool                route_direct;
    size_t                 prefix_len;

    rpc_sockopt            mtu_opt;
    rpc_sockopt            mtu_discover_opt;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_HOST(iut_host);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(gw_iut_addr);
    TEST_GET_ADDR_NO_PORT(gw_tst_addr);

    TEST_GET_IF(gw_tst_if);
    TEST_GET_IF(gw_iut_if);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(connected);

    TEST_GET_ENUM_PARAM(pmtu_val, IP_MTU_MODES);
    TEST_GET_BOOL_PARAM(ip_recverr);

    TEST_GET_BOOL_PARAM(route_direct);

    domain = rpc_socket_domain_by_addr(tst_addr);

    prefix_len = (route_direct ? te_netaddr_get_size(
                  addr_family_rpc2h(sockts_domain2family(domain))) * 8 : 24);

    mtu_opt = ip_version_6(tst_addr) ? RPC_IPV6_MTU : RPC_IP_MTU;
    mtu_discover_opt = ip_version_6(tst_addr) ? RPC_IPV6_MTU_DISCOVER
                                              : RPC_IP_MTU_DISCOVER;

    te_fill_buf(tx_buf, TST_BUF_LEN);

    if (ip_version_6(iut_addr))
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, MTU_EXPIRES_VALUE,
                                         &old_mtu_expires_val,
                                         "net/ipv6/route/mtu_expires"));
    else
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, MTU_EXPIRES_VALUE,
                                         &old_mtu_expires_val,
                                         "net/ipv4/route/mtu_expires"));

    sockts_init_msghdr(&msg, SOCKTS_BUF_SZ);
    msg.msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;

    if (connected)
    {
        if (ip_version_6(tst_addr))
            CHECK_RC(tapi_cfg_alloc_ip6_net(&net_handle1));
        else
            CHECK_RC(tapi_cfg_alloc_ip4_net(&net_handle1));

        CHECK_RC(tapi_cfg_alloc_net_addr(net_handle1, NULL, &new_iut_addr));
        CHECK_RC(tapi_cfg_alloc_net_addr(net_handle1, NULL, &new_gw_iut_addr));
        CHECK_RC(cfg_get_oid_str(net_handle1, &net_oid));
        type = CVT_INTEGER;
        CHECK_RC(cfg_get_instance_fmt(&type, &net_prefix,
                                      "%s/prefix:", net_oid));

        tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                      new_iut_addr, net_prefix, TRUE, &h1);
        tapi_cfg_base_if_add_net_addr(pco_gw->ta, gw_iut_if->if_name,
                                      new_gw_iut_addr, net_prefix, TRUE, &h2);

        iut_addr = new_iut_addr;
        gw_iut_addr = new_gw_iut_addr;

        if (ip_version_6(tst_addr))
            CHECK_RC(tapi_cfg_alloc_ip6_net(&net_handle2));
        else
            CHECK_RC(tapi_cfg_alloc_ip4_net(&net_handle2));

        CHECK_RC(tapi_cfg_alloc_net_addr(net_handle2, NULL, &new_tst_addr));
        CHECK_RC(tapi_cfg_alloc_net_addr(net_handle2, NULL, &new_gw_tst_addr));
        CHECK_RC(cfg_get_oid_str(net_handle2, &net_oid));
        type = CVT_INTEGER;
        CHECK_RC(cfg_get_instance_fmt(&type, &net_prefix,
                                      "%s/prefix:", net_oid));

        tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                      new_tst_addr, net_prefix, TRUE, &h3);
        tapi_cfg_base_if_add_net_addr(pco_gw->ta, gw_tst_if->if_name,
                                      new_gw_tst_addr, net_prefix, TRUE, &h4);

        tst_addr = new_tst_addr;
        gw_tst_addr = new_gw_tst_addr;

    }

    TEST_STEP("Add route on @p pco_iut: "
              "@p tst_addr via gateway @p gw_iut_addr.");
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
        addr_family_rpc2h(sockts_domain2family(domain)),
        te_sockaddr_get_netaddr(tst_addr),
        prefix_len,
        te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the dst");
    }
    route_dst_added = TRUE;

    TEST_STEP("Add route on @p pco_tst: "
              "@p iut_addr via gateway @p gw_tst_addr.");
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
        addr_family_rpc2h(sockts_domain2family(domain)),
        te_sockaddr_get_netaddr(iut_addr),
        te_netaddr_get_size(
            addr_family_rpc2h(sockts_domain2family(domain))) * 8,
        te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the src");
    }
    route_src_added = TRUE;

    TEST_STEP("Turn on forwarding on @p pco_gw.");
    if (ip_version_6(gw_iut_addr))
        CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                      "net/ipv6/conf/all/forwarding"));
    else
        CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                      "net/ipv4/ip_forward"));

    TEST_STEP("Add neigbor entries to @p pco_gw if IPv6 is used.");
    if (ip_version_6(iut_addr))
    {
        CHECK_RC(tapi_cfg_get_hwaddr(pco_iut->ta, iut_if->if_name,
                                     iut_if_mac, &mac_len));
        CHECK_RC(tapi_update_arp(pco_gw->ta, gw_iut_if->if_name, NULL, NULL,
                                 iut_addr, iut_if_mac, TRUE));
        neigh_gw_iut_entry_added = TRUE;

        CHECK_RC(tapi_cfg_get_hwaddr(pco_tst->ta, tst_if->if_name,
                                     tst_if_mac, &mac_len));
        CHECK_RC(tapi_update_arp(pco_gw->ta, gw_tst_if->if_name, NULL, NULL,
                                 tst_addr, tst_if_mac, TRUE));
        neigh_gw_tst_entry_added = TRUE;
    }

    CFG_WAIT_CHANGES;

    TEST_STEP("Retrieve the path MTU of @p pco_gw and @p pco_iut by means "
              "of tapi_cfg_base_if_get_mtu_u().");
    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_gw->ta, gw_tst_if->if_name,
                                        &mtu_gw_saved));
    RING("Current 'gw' %s MTU=%d", gw_tst_if->if_name, mtu_gw_saved);

    CHECK_RC(tapi_cfg_base_if_get_mtu_u(iut_host->ta, iut_if->if_name,
                                        &mtu_lo_saved));
    RING("Current local %s MTU=%d", iut_if->if_name, mtu_lo_saved);

    TEST_STEP("Create and bind UDP socket on IUT and its peer on Tester. "
              "If @p connected, connect IUT socket to its peer's address.");
    if (connected)
    {
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &iut_s, &tst_s);
        aux_s = iut_s;
    }
    else
    {
        iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM,
                           RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s, iut_addr);
        aux_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM,
                           RPC_PROTO_DEF);
        rpc_connect(pco_iut, aux_s, tst_addr);
        tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM,
                           RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_s, tst_addr);
    }

    TEST_STEP("Retrieve the current known path MTU of the @p iut_s by means "
              "of @b getsockopt(@c IP_MTU) for IPv4 configuration or "
              "@b getsockopt(@c IPV6_MTU) for IPv6 configuration and save it "
              "in @b mtu_sock_saved.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, mtu_opt, &mtu_sock_saved);
    if ((ret != 0 && connected) || (ret != -1 && !connected))
    {
        TEST_VERDICT("getsockopt(%s) returned incorrect "
                     "value %d", ip_version_6(iut_addr) ? "IPV6_MTU" : "IP_MTU",
                     ret);
    }
    if (!connected)
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN, "getsockopt(%s)",
                        ip_version_6(iut_addr) ? "IPV6_MTU" : "IP_MTU");
    if (!connected)
        rpc_getsockopt(pco_iut, aux_s, mtu_opt, &mtu_sock_saved);

    RING("Current 'aux_s' MTU=%d\n", mtu_sock_saved);

    TEST_STEP("Set the @c IP_MTU_DISCOVER (@c IPV6_MTU_DISCOVER for IPv6) "
              "option to @p pmtu_val.");
    rpc_getsockopt(pco_iut, iut_s, mtu_discover_opt, &pmtu_flags_saved);
    if (pmtu_flags_saved != pmtu_val)
    {
        /* It is necessary for PMTU Discovery processing forcing */
        pmtu_flags = pmtu_val;
        rpc_setsockopt_check_int(pco_iut, iut_s, mtu_discover_opt,
                                 pmtu_flags);
    }

    TEST_STEP("Check that a datagram with less than MTU bytes can be sent in "
              "both directions between IUT and Tester sockets and received by "
              "a peer.");
    /* forward direction */
    buf_len = mtu_sock_saved - TST_UDP_RSV;
    if (buf_len > TST_BUF_LEN)
        TEST_FAIL("Sent buffer length is too small");
    if (connected)
        sent = rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    else
        sent = rpc_sendto(pco_iut, iut_s, tx_buf, buf_len, 0, tst_addr);

    IMDU_CHECK_RECEIVE(sent, tx_buf, pco_tst, tst_s, rx_buf,
                       TST_BUF_LEN, "Sending data from IUT first time");

    rpc_getsockopt(pco_iut, aux_s, mtu_opt, &mtu_sock_current);
    RING("Current 'aux_s' MTU=%d", mtu_sock_current);

    /* reverse direction */
    buf_len = mtu_sock_saved - TST_UDP_RSV;
    if (connected)
        sent = rpc_send(pco_tst, tst_s, tx_buf, buf_len, 0);
    else
        sent = rpc_sendto(pco_tst, tst_s, tx_buf, buf_len, 0, iut_addr);

    IMDU_CHECK_RECEIVE(sent, tx_buf, pco_iut, iut_s, rx_buf,
                       TST_BUF_LEN, "Sending data from Tester");

    TEST_STEP("Reduce MTU on @p gw_tst_if to @p mtu_gw_saved/2, but not less "
              "than minimal value (@c MIN_PMTU_IPV4/@c MIN_PMTU_IPV6).");
    mtu_gw_new = mtu_sock_saved / 2;
    if (ip_version_6(tst_addr))
    {
        if(mtu_gw_new < MIN_PMTU_IPV6)
            mtu_gw_new = MIN_PMTU_IPV6;
    }
    else
    {
        if(mtu_gw_new < MIN_PMTU_IPV4)
            mtu_gw_new = MIN_PMTU_IPV4;
    }
    CHECK_RC(tapi_set_if_mtu_smart2(pco_gw->ta, gw_tst_if->if_name,
                                    mtu_gw_new, &gw_mtus));
    CFG_WAIT_CHANGES;

    TEST_STEP("Set the @c IP_RECVERR or @c IPV6_RECVERR if required by "
              "@p ip_recverr and check that error queue is empty using "
              "@b recvmsg(@c MSG_ERRQUEUE).");
    if (ip_recverr)
    {
        if(ip_version_6(iut_addr))
        {
            rpc_setsockopt_check_int(pco_iut, iut_s, RPC_IPV6_RECVERR, 1);
            check_iperrque_is_empty(pco_iut, iut_s, &msg,
                                    "Set opt IPV6_RECVERR");
        }
        else
        {
            rpc_setsockopt_check_int(pco_iut, iut_s, RPC_IP_RECVERR, 1);
            check_iperrque_is_empty(pco_iut, iut_s, &msg, "Set opt IP_RECVERR");
        }
    }

    TEST_STEP("Attempt to send datagram with length equal to @b mtu_sock_saved "
              "value to provoke message @c ICMP_DEST_UNREACH (or "
              "@c ICMP6_PACKET_TOO_BIG) because MTU on @p gw_tst_if reduced "
              "before.");
    buf_len = mtu_sock_saved - TST_UDP_RSV;
    if (connected)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        sent = rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        sent = rpc_sendto(pco_iut, iut_s, tx_buf, buf_len, 0, tst_addr);
    }

    TEST_STEP("If @c IP_PMTUDISC_DONT: for IPv4 check that IP error queue is "
              "empty and Tester received data; for IPv6 check that error "
              "queue containts message @c ICMP6_PACKET_TOO_BIG and Tester "
              "does not received data; in both cases finish testing."
              "For other values of @p pmtu_val, check that no data can be read "
              "from Tester socket.");
    TAPI_WAIT_NETWORK;
    memset(rx_buf, 0, TST_BUF_LEN);
    RPC_AWAIT_IUT_ERROR(pco_tst);
    received = rpc_recv(pco_tst, tst_s, rx_buf, TST_BUF_LEN, RPC_MSG_DONTWAIT);
    if (received != -1 && pmtu_val != IP_PMTUDISC_DONT)
    {
        TEST_VERDICT("recv(MSG_DONTWAIT) should return -1"
                     " because 'gw' interface Path MTU is reduced");
    }
    else if (pmtu_val == IP_PMTUDISC_DONT)
    {
        if (ip_version_6(iut_addr))
        {
            if (ip_recverr)
            {
                check_iperrque_msg(pco_iut, iut_s, &msg, "IP_PMTUDISC_DONT",
                                   SO_EE_ORIGIN_ICMP6, ICMP6_PACKET_TOO_BIG,
                                   0, mtu_gw_new, TRUE);
            }

            if (received >= 0)
            {
                TEST_FAIL("IP_PMTUDISC_DONT: "
                          "recv(MSG_DONTWAIT) succeeded unexpectedly");
            }
        }
        else
        {
            check_iperrque_is_empty(pco_iut, iut_s, &msg, "IP_PMTUDISC_DONT");
            if (received != sent)
            {
                TEST_FAIL("IP_PMTUDISC_DONT: "
                          "recv(MSG_DONTWAIT) returned unexpected value");
            }
        }
        TEST_SUCCESS;
    }
    CHECK_RPC_ERRNO(pco_tst, RPC_EAGAIN, "recv() after reduce MTU");

    /* Further work only with IP_PMTUDISC_{WANT|DO|PROBE} */

    TEST_STEP("When @p ip_recverr is @c FALSE send 1-byte UDP message from IUT "
              "and check that @b send() fails with @c EMSGSIZE, if "
              "@p ip_recverr is @c TRUE check @c ICMP/@c ICMPV6 message in "
              "error queue using @b recvmsg(@c MSG_ERRQUEUE).");
    if (connected)
    {
        if (ip_recverr)
        {
            if (ip_version_6(iut_addr))
            {
                check_iperrque_msg(pco_iut, iut_s, &msg, "Stage 1",
                                   SO_EE_ORIGIN_ICMP6, ICMP6_PACKET_TOO_BIG,
                                   0, mtu_gw_new, TRUE);
            }
            else
            {
                check_iperrque_msg(pco_iut, iut_s, &msg, "Stage 1",
                                   SO_EE_ORIGIN_ICMP, ICMP_DEST_UNREACH,
                                   ICMP_FRAG_NEEDED, mtu_gw_new, FALSE);
            }
        }
        else
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            sent = rpc_send(pco_iut, iut_s, tx_buf, 1, 0);
            if (sent != -1)
                TEST_FAIL("Attempt to get previous error message "
                          "returns %d instead -1", sent);
            CHECK_RPC_ERRNO(pco_iut, RPC_EMSGSIZE, "Stage 1");
        }

    }
    else /* connected == FALSE */
    {
        if (ip_recverr)
        {
            if (ip_version_6(iut_addr))
            {
                check_iperrque_msg(pco_iut, iut_s, &msg, "Stage 2",
                                   SO_EE_ORIGIN_ICMP6, ICMP6_PACKET_TOO_BIG,
                                   0, mtu_gw_new, TRUE);
            }
            else
            {
                check_iperrque_msg(pco_iut, iut_s, &msg, "Stage 2",
                                   SO_EE_ORIGIN_ICMP, ICMP_DEST_UNREACH,
                                   ICMP_FRAG_NEEDED, mtu_gw_new, FALSE);
            }
        }
        else
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            sent = rpc_sendto(pco_iut, iut_s, tx_buf, 1, 0, tst_addr);
            if (sent < 0)
                TEST_VERDICT("Stage 2: sendto() failed with errno %r",
                             RPC_ERRNO(pco_iut));

            IMDU_CHECK_RECEIVE(sent, tx_buf, pco_tst, tst_s, rx_buf,
                               TST_BUF_LEN,
                               "Stage 2: sending data from IUT");
        }

    } /* if (connected) */

    rpc_getsockopt(pco_iut, aux_s, mtu_opt, &mtu_sock_current);
    RING("Current 'aux_s' MTU=%d", mtu_sock_current);

    TEST_STEP("Send message again with initial length equal to "
              "@b mtu_sock_saved and check result:");
    if (connected)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        sent = rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    }
    else
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        sent = rpc_sendto(pco_iut, iut_s, tx_buf, buf_len, 0, tst_addr);
    }

    TAPI_WAIT_NETWORK;

    /* Check result of sent and after recv() on pco_tst */
    if (pmtu_val == IP_PMTUDISC_WANT)
    {
        TEST_SUBSTEP("For @c IP_PMTUDISC_WANT send() must return message "
                     "length: message go out to the ethernet "
                     "(IPv4 flag DF is off).");
        if (sent < 0)
            TEST_VERDICT("IP_PMTUDISC_WANT: sending failed with errno %r",
                         RPC_ERRNO(pco_iut));
        else if (sent != (int)buf_len)
            TEST_VERDICT("IP_PMTUDISC_WANT: number of sent bytes not "
                         "equal buf_len");

        IMDU_CHECK_RECEIVE(sent, tx_buf, pco_tst, tst_s, rx_buf, TST_BUF_LEN,
                           "IP_PMTUDISC_WANT");

        check_iperrque_is_empty(pco_iut, iut_s, &msg, "IP_PMTUDISC_WANT");
    }
    else if (pmtu_val == IP_PMTUDISC_PROBE)
    {
        TEST_SUBSTEP("For @c IP_PMTUDISC_PROBE send() must return message "
                     "length, because discovered path MTU ignored: message "
                     "go out to the ethernet (IPv4 flag DF is on). "
                     "If @p ip_recverr is @c TRUE get @c ICMP or @c ICMPV6 "
                     "message from error queue, if @p ip_recverr is @c FALSE "
                     "send() 1-byte UDP message from IUT and check that for "
                     "connected socket send() fails with @c EMSGSIZE, while "
                     "for not connected socket data is sent successfully and "
                     "received on @p pco_tst.");
        if (sent < 0)
            TEST_VERDICT("IP_PMTUDISC_PROBE: sending failed with errno %r",
                         RPC_ERRNO(pco_iut));
        if (sent != (int)buf_len)
            TEST_VERDICT("IP_PMTUDISC_PROBE: number of sent bytes not "
                         "equal buf_len");

        RPC_AWAIT_IUT_ERROR(pco_tst);
        received = rpc_recv(pco_tst, tst_s, rx_buf,
                            TST_BUF_LEN, RPC_MSG_DONTWAIT);
        if (received != -1)
            TEST_VERDICT("IP_PMTUDISC_PROBE: recv(MSG_DONTWAIT) should return "
                         "-1 because 'gw' interface MTU is reduced (IPv4 "
                         "flag DF is on)");
        CHECK_RPC_ERRNO(pco_tst, RPC_EAGAIN, "IP_PMTUDISC_PROBE recv()");

        if (ip_recverr)
        {
            if (ip_version_6(iut_addr))
            {
                check_iperrque_msg(pco_iut, iut_s, &msg, "IP_PMTUDISC_PROBE",
                                   SO_EE_ORIGIN_ICMP6, ICMP6_PACKET_TOO_BIG,
                                   0, mtu_gw_new, TRUE);
            }
            else
            {
                check_iperrque_msg(pco_iut, iut_s, &msg, "IP_PMTUDISC_PROBE",
                                   SO_EE_ORIGIN_ICMP, ICMP_DEST_UNREACH,
                                   ICMP_FRAG_NEEDED, mtu_gw_new, FALSE);
            }
        }
        else
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            if (connected)
            {
                sent = rpc_send(pco_iut, iut_s, tx_buf, 1, 0);
                if (sent != -1)
                    TEST_VERDICT("send() for IP_PMTUDISC_PROBE unexpectedly "
                                 "returned success");

                CHECK_RPC_ERRNO(pco_iut, RPC_EMSGSIZE, "IP_PMTUDISC_PROBE "
                                "send()");
            }
            else
            {
                sent = rpc_sendto(pco_iut, iut_s, tx_buf, 1, 0, tst_addr);
                if (sent < 0)
                    TEST_VERDICT("IP_PMTUDISC_PROBE: sending failed with "
                                 "errno %r", RPC_ERRNO(pco_iut));
                if (sent != 1)
                    TEST_VERDICT("IP_PMTUDISC_PROBE: send() must return 1");
                IMDU_CHECK_RECEIVE(sent, tx_buf, pco_tst, tst_s, rx_buf,
                                   TST_BUF_LEN, "IP_PMTUDISC_PROBE");
            }
        }
    }
    else /* pmtu_val == IP_PMTUDISC_DO */
    {
        TEST_SUBSTEP("For @c IP_PMTUDISC_DO send() must return -1, because "
                     "message length is greater than discovered path MTU "
                     "(will be dropped). Send 1-byte message from IUT, check "
                     "that it can be received on Tester.");
        if (sent != -1)
        {
            TEST_VERDICT("IP_PMTUDISC_DO: send() returned success in case "
                         "of sending the data with length more then PMTU.");
        }
        else
        {
            if (ip_recverr)
            {
                if (ip_version_6(iut_addr))
                {
                    check_iperrque_msg(pco_iut, iut_s, &msg, "IP_PMTUDISC_DO",
                                       SO_EE_ORIGIN_LOCAL, 0, 0, mtu_gw_new,
                                       TRUE);
                }
                else
                {
                    check_iperrque_msg(pco_iut, iut_s, &msg, "IP_PMTUDISC_DO",
                                       SO_EE_ORIGIN_LOCAL, 0, 0, mtu_gw_new,
                                       FALSE);
                }
            }
            else
            {
                CHECK_RPC_ERRNO(pco_iut, RPC_EMSGSIZE, "IP_PMTUDISC_DO");
            }
        }

        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (connected)
            sent = rpc_send(pco_iut, iut_s, tx_buf, 1, 0);
        else
            sent = rpc_sendto(pco_iut, iut_s, tx_buf, 1, 0, tst_addr);

        if (sent < 0)
            TEST_VERDICT("IP_PMTUDISC_DO: sending failed with errno %r",
                         RPC_ERRNO(pco_iut));
        else if (sent != 1)
            TEST_VERDICT("IP_PMTUDISC_DO: send(1) returned unexpected value");

        RPC_AWAIT_IUT_ERROR(pco_tst);
        IMDU_CHECK_RECEIVE(sent, tx_buf, pco_tst, tst_s, rx_buf, 1,
                           "IP_PMTUDISC_DO");
        check_iperrque_is_empty(pco_iut, iut_s, &msg, "IP_PMTUDISC_DO");
    }

    TEST_STEP("Check that error queue is empty using "
              "@b recvmsg(@c MSG_ERRQUEUE).");
    check_iperrque_is_empty(pco_iut, iut_s, &msg, "Finish");

    buf_len = mtu_gw_new - TST_UDP_RSV;
    TEST_STEP("Wait while OS restore socket MTU value.");
    for (i = 0; i < TIME_TO_WAIT_MTU_INCREASING; i++)
    {
        sent = rpc_send(pco_iut, aux_s, tx_buf, buf_len, 0);
        received = rpc_recv(pco_tst, tst_s, rx_buf, TST_BUF_LEN, 0);
        if (sent != received)
        {
            TEST_FAIL("Expected received=%d to be the same as sent=%d"
                      "while increasing PathMTU", received, sent);
        }
        SLEEP(TST_TIME_TO_SLEEP);

        rpc_getsockopt(pco_iut, aux_s, mtu_opt, &mtu_sock_current);

        RING("'iut_s' MTU=%d after waiting %d sec",
             mtu_sock_current, (i+1) * TST_TIME_TO_SLEEP);
        if (mtu_sock_current == mtu_sock_saved)
            break;
    }

    if (mtu_sock_current != mtu_sock_saved)
    {
        TEST_VERDICT("Failed to restore socket IP_MTU value from %d "
                     "to original value %d",
                     mtu_sock_current, mtu_sock_saved);
    }
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (aux_s != iut_s)
        CLEANUP_RPC_CLOSE(pco_iut, aux_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (neigh_gw_iut_entry_added)
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_gw->ta, gw_iut_if->if_name,
                 iut_addr));

    if (neigh_gw_tst_entry_added)
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_gw->ta, gw_tst_if->if_name,
                 tst_addr));

    if (route_dst_added &&
        tapi_cfg_del_route_via_gw(pco_iut->ta,
                           addr_family_rpc2h(
                                sockts_domain2family(domain)),
                           te_sockaddr_get_netaddr(tst_addr),
                            prefix_len,
                           te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
    {
        ERROR("Cannot delete route to the dst");
        result = EXIT_FAILURE;
    }

    if (route_src_added &&
        tapi_cfg_del_route_via_gw(pco_tst->ta,
                           addr_family_rpc2h(
                               sockts_domain2family(domain)),
                           te_sockaddr_get_netaddr(iut_addr),
                            te_netaddr_get_size(addr_family_rpc2h(
                                sockts_domain2family(domain))) * 8,
                           te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
    {
        ERROR("Cannot delete route to the src");
        result = EXIT_FAILURE;
    }

    if (h1 != CFG_HANDLE_INVALID)
        cfg_del_instance(h1, FALSE);
    if (h2 != CFG_HANDLE_INVALID)
        cfg_del_instance(h2, FALSE);
    if (h3 != CFG_HANDLE_INVALID)
        cfg_del_instance(h3, FALSE);
    if (h4 != CFG_HANDLE_INVALID)
        cfg_del_instance(h4, FALSE);

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&gw_mtus));

    if (old_mtu_expires_val >= 0)
    {
        if (ip_version_6(iut_addr))
            CLEANUP_CHECK_RC(
                tapi_cfg_sys_ns_set_int(pco_iut->ta, old_mtu_expires_val, NULL,
                                        "net/ipv6/route/mtu_expires"));
        else
            CLEANUP_CHECK_RC(
                tapi_cfg_sys_ns_set_int(pco_iut->ta, old_mtu_expires_val, NULL,
                                        "net/ipv4/route/mtu_expires"));
    }

    TEST_END;
}
