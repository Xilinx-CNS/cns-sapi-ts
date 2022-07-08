/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-ipv4_mapped_in_ipv6 Receive IPv6 packet with IPv4-mapped addresses
 *
 * @objective Check what happens when IPv6 packet is received in which
 *            source and/or destination addresses are IPv4-mapped IPv6
 *            addresses.
 *
 * @note Test is tuned to expect Linux behavior.
 *
 * @type conformance, robustness
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_p2p_ip4_ip6
 * @param sock_type   Socket type:
 *                    - @c SOCK_DGRAM
 *                    - @c SOCK_STREAM
 * @param ipv4_src    If @c TRUE, source address in checked packet is
 *                    IPv4-mapped, otherwise it is normal IPv6 address
 * @param ipv4_dst    If @c TRUE, destination address in checked packet is
 *                    IPv4-mapped, otherwise it is normal IPv6 address
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/ipv4_mapped_in_ipv6"

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include "sockapi-test.h"
#include "tapi_tad.h"
#include "tapi_ip6.h"
#include "tapi_udp.h"
#include "ndn.h"
#include "tapi_route_gw.h"
#include "te_string.h"

/** Maximum length of payload in checked packet */
#define TST_PKT_LEN 1000

/** Auxiliary structure passed to CSAP callback */
typedef struct callback_data {
    te_bool        tcp_pkt;       /**< Will be set to TRUE if
                                       TCP packet was detected */
    uint32_t       ackn_got;      /**< Last recieved ACKN */
    uint32_t       seqn_got;      /**< Last received SEQN */
    unsigned int   rst_got;       /**< Number of captured TCP packets
                                       with RST flag set */
    unsigned int   syn_ack_got;   /**< Number of captured SYN-ACK
                                       TCP packets */
    unsigned int   syn_got;       /**< Number of captured SYN TCP
                                       packets */
    unsigned int   fin_got;       /**< Number of captured TCP packets
                                       with FIN flag set */
    unsigned int   urg_got;       /**< Number of captured TCP packets
                                       with URG flag set */

    te_bool        ipv4_pkt;      /**< Will be set to TRUE if
                                       IPv4 packet was captured */

    int            exp_icmp_type; /**< Expected ICMP message type
                                       (negative if such message is not
                                        expected) */
    int            exp_icmp_code; /**< Expected ICMP message code */
    unsigned int   icmp_pkts;     /**< Number of captured ICMP messages */
} callback_data;

/**
 * Callback function to process captured IPv4 packets.
 *
 * @param pkt       Captured packet.
 * @param userdata  Pointer to callback_data.
 */
static void
ipv4_callback(const tapi_ip4_packet_t *pkt, void *userdata)
{
    callback_data *data = (callback_data *)userdata;

    UNUSED(pkt);

    if (!(data->ipv4_pkt))
    {
        ERROR_VERDICT("IUT sent IPv4 packet");
        data->ipv4_pkt = TRUE;
    }
}

/**
 * Append flag name to string.
 *
 * @param str     Pointer to te_string.
 * @param flag    Flag name.
 */
static void
te_string_append_flag(te_string *str, const char *flag)
{
    te_errno rc;

    rc = te_string_append(str, "%s%s", (str->len > 0 ? "|" : ""),
                          flag);
    if (rc != 0)
        ERROR("te_string_append() returned %r", rc);
}

/**
 * Get string representation of flags set in TCP header.
 *
 * @param tcp       Pointer to tcphdr structure.
 *
 * @return String with flag names.
 */
static const char *
tcp_flags2str(struct tcphdr *tcp)
{
    /*
     * I cannot use TE_STRING_INIT_STATIC here because C demands
     * initializer for static variable to be constant and it does
     * not think that TE_STRING_INIT_STATIC() is a constant expression.
     */
    static char buf[1000];
    te_string   str = TE_STRING_BUF_INIT(buf);

    te_string_reset(&str);
    if (tcp->fin)
        te_string_append_flag(&str, "FIN");
    if (tcp->syn)
        te_string_append_flag(&str, "SYN");
    if (tcp->rst)
        te_string_append_flag(&str, "RST");
    if (tcp->psh)
        te_string_append_flag(&str, "PSH");
    if (tcp->ack)
        te_string_append_flag(&str, "ACK");
    if (tcp->urg)
        te_string_append_flag(&str, "URG");

    return buf;
}

/**
 * Callback function to process captured IPv6 packets.
 *
 * @param pkt       Captured packet.
 * @param userdata  Pointer to callback_data.
 */
static void
ipv6_callback(const tapi_ip6_packet_t *pkt, void *userdata)
{
    callback_data *data = (callback_data *)userdata;

    if (pkt->next_header == IPPROTO_ICMPV6)
    {
        struct icmphdr *icmp = (struct icmphdr *)(pkt->payload);

        if (data->exp_icmp_type < 0 ||
            (int)icmp->type != data->exp_icmp_type ||
            (int)icmp->code != data->exp_icmp_code)
        {
            if (icmp->type == ICMP6_DST_UNREACH)
            {
                RING_VERDICT("IUT sent ICMPv6 destination unreachable "
                             "message (type=%d code=%d)", (int)(icmp->type),
                             (int)(icmp->code));
            }
            else
            {
                RING_VERDICT("IUT sent ICMPv6 message (type=%d code=%d)",
                             (int)(icmp->type), (int)(icmp->code));
            }
        }

        data->icmp_pkts++;
    }
    else if (pkt->next_header == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)pkt->payload;

        data->tcp_pkt = TRUE;

        data->seqn_got = ntohl(tcp->seq);
        if (tcp->ack)
            data->ackn_got = ntohl(tcp->ack_seq);
        if (tcp->syn)
        {
            if (tcp->ack)
                data->syn_ack_got++;
            else
                data->syn_got++;
        }
        if (tcp->fin)
            data->fin_got++;
        if (tcp->urg)
            data->urg_got++;

        RING("TCP packet with flags %s was captured", tcp_flags2str(tcp));
    }
    else
    {
        ERROR_VERDICT("IUT responded with packet having unexpected "
                      "next-header %d", (int)(pkt->next_header));
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *iut_addr6 = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_fake_addr = NULL;
    const struct sockaddr      *tst_fake_addr6 = NULL;
    const struct sockaddr      *iut_lladdr = NULL;
    const struct sockaddr      *alien_link_addr = NULL;

    te_bool                 ipv4_src;
    te_bool                 ipv4_dst;
    rpc_socket_type         sock_type;

    struct sockaddr_storage src_addr;
    struct sockaddr_storage dst_addr;
    struct sockaddr_storage iut_bind_addr;
    struct sockaddr_storage from_addr;
    socklen_t               from_addr_len = sizeof(from_addr);

    csap_handle_t           csap_send;
    csap_handle_t           csap_recv_ip6;
    csap_handle_t           csap_recv_ip4;
    callback_data           data;
    int                     iut_s = -1;
    int                     iut_acc = -1;
    asn_value              *pkt_templ = NULL;
    int                     num;
    uint32_t                init_seqn;
    te_bool                 readable;
    te_bool                 exp_readable;

    char                    send_buf[TST_PKT_LEN];
    size_t                  send_len;
    char                    recv_buf[TST_PKT_LEN];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr6);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_BOOL_PARAM(ipv4_src);
    TEST_GET_BOOL_PARAM(ipv4_dst);
    TEST_GET_SOCK_TYPE(sock_type);

    if (ipv4_src)
    {
        tapi_sockaddr_clone_exact(tst_fake_addr, &src_addr);
        te_sockaddr_ip4_to_ip6_mapped(SA(&src_addr));
    }
    else
    {
        tapi_sockaddr_clone_exact(tst_fake_addr6, &src_addr);
    }

    if (ipv4_dst)
    {
        tapi_sockaddr_clone_exact(iut_addr, &dst_addr);
        te_sockaddr_ip4_to_ip6_mapped(SA(&dst_addr));
        SIN6(&dst_addr)->sin6_port = SIN6(iut_addr6)->sin6_port;
    }
    else
    {
        tapi_sockaddr_clone_exact(iut_addr6, &dst_addr);
    }

    TEST_STEP("Add ARP table entries for @p tst_fake_addr6 and "
              "@p tst_fake_addr on IUT to avoid address resolution "
              "requests. @p tst_fake_addr6 will be used as source "
              "address of a checked packet if @p ipv4_src is @c FALSE, "
              "otherwise IPv4-mapped IPv6 address corresponding to "
              "@p tst_fake_addr will be used. @p alien_link_addr is "
              "set as corresponding MAC address so that no host will "
              "interfere.");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_fake_addr6, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_fake_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));

    TEST_STEP("Create IPv6 CSAP on Tester for sending TCP or UDP packets "
              "(choose its type according to @p sock_type). Use "
              "@p alien_link_addr as source MAC address.");
    if (sock_type == RPC_SOCK_DGRAM)
    {
        CHECK_RC(tapi_udp_ip6_eth_csap_create(
                        pco_tst->ta, 0, tst_if->if_name,
                        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                        CVT_HW_ADDR(alien_link_addr),
                        CVT_HW_ADDR(iut_lladdr),
                        (uint8_t *)&SIN6(&src_addr)->sin6_addr,
                        (uint8_t *)&SIN6(&dst_addr)->sin6_addr,
                        SIN6(&src_addr)->sin6_port,
                        SIN6(&dst_addr)->sin6_port,
                        &csap_send));
    }
    else
    {
         CHECK_RC(tapi_tcp_ip6_eth_csap_create(
                        pco_tst->ta, 0, tst_if->if_name,
                        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                        CVT_HW_ADDR(alien_link_addr),
                        CVT_HW_ADDR(iut_lladdr),
                        (uint8_t *)&SIN6(&src_addr)->sin6_addr,
                        (uint8_t *)&SIN6(&dst_addr)->sin6_addr,
                        SIN6(&src_addr)->sin6_port,
                        SIN6(&dst_addr)->sin6_port,
                        &csap_send));
    }

    TEST_STEP("Create IPv4 and IPv6 CSAPs on Tester to capture "
              "packets sent from IUT.");

    CHECK_RC(tapi_ip4_eth_csap_create(
                      pco_tst->ta, 0, tst_if->if_name,
                      TAD_ETH_RECV_DEF,
                      CVT_HW_ADDR(alien_link_addr), NULL,
                      htonl(INADDR_ANY), htonl(INADDR_ANY),
                      -1, &csap_recv_ip4));

    CHECK_RC(tapi_ip6_eth_csap_create(
                      pco_tst->ta, 0, tst_if->if_name,
                      TAD_ETH_RECV_DEF,
                      CVT_HW_ADDR(alien_link_addr), NULL,
                      NULL, NULL,
                      -1, &csap_recv_ip6));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_recv_ip4,
                                   NULL, TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_recv_ip6,
                                   NULL, TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));
    TAPI_WAIT_NETWORK;

    memset(&data, 0, sizeof(data));
    data.exp_icmp_type = -1;
    data.exp_icmp_code = -1;

    TEST_STEP("Create IPv6 socket on IUT, choosing its type according to "
              "@p sock_type. Bind it to wildcard address. If @p sock_type "
              "is @c SOCK_STREAM, call @b listen().");

    iut_s = rpc_socket(pco_iut, RPC_PF_INET6, sock_type,
                       RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_V6ONLY, 0);

    tapi_sockaddr_clone_exact(iut_addr6, &iut_bind_addr);
    te_sockaddr_set_wildcard(SA(&iut_bind_addr));

    rpc_bind(pco_iut, iut_s, SA(&iut_bind_addr));
    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_iut, iut_s, -1);

    TEST_STEP("If @p sock_type is @c SOCK_DGRAM, send UDP packet from "
              "Tester CSAP, otherwise send TCP @c SYN. Set source and "
              "destination addresses in the packet according to "
              "@p ipv4_src and @p ipv4_dst.");

    if (sock_type == RPC_SOCK_DGRAM)
    {
        CHECK_RC(asn_parse_value_text(
                  "{ pdus { udp: {}, ip6:{}, eth:{} } }",
                  ndn_traffic_template,  &pkt_templ, &num));
        send_len = rand_range(1, sizeof(send_buf));
        te_fill_buf(send_buf, send_len);
        CHECK_RC(asn_write_value_field(pkt_templ, send_buf, send_len,
                                       "payload.#bytes"));
    }
    else
    {
        init_seqn = rand_range(1, 0xffff);
        CHECK_RC(tapi_tcp_template(TRUE, init_seqn, 0, TRUE, FALSE, NULL, 0,
                                   &pkt_templ));
    }

    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, 0, csap_send, pkt_templ,
                                   RCF_MODE_BLOCKING));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Capture packets sent from IUT. Check that if source address "
              "is normal IPv6, but destination address is IPv4-mapped "
              "IPv6, then IUT sends ICMPv6 destination unreachable message "
              "in response.");

    if (!ipv4_src && ipv4_dst)
    {
        data.exp_icmp_type = ICMP6_DST_UNREACH;
        data.exp_icmp_code = ICMP6_DST_UNREACH_NOROUTE;
    }

    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, csap_recv_ip6,
                                 tapi_ip6_eth_trrecv_cb_data(
                                          &ipv6_callback, &data),
                                 NULL));

    if ((!ipv4_src && !ipv4_dst) ||
        (sock_type == RPC_SOCK_DGRAM && ipv4_src && !ipv4_dst))
    {
        exp_readable = TRUE;
    }
    else
    {
        exp_readable = FALSE;
    }

    TEST_STEP("If @p sock_type is @c SOCK_STREAM and @c SYN-ACK was sent "
              "from IUT, send @c ACK in response to finish TCP connection "
              "establishment.");

    if (sock_type == RPC_SOCK_STREAM)
    {
        if (data.syn_ack_got > 0)
        {
            if (!exp_readable)
                RING_VERDICT("SYN-ACK was unexpectedly received");

            asn_free_value(pkt_templ);
            pkt_templ = NULL;

            if (data.ackn_got != init_seqn + 1)
                ERROR_VERDICT("Unexpected ACKN was received from IUT");

            CHECK_RC(tapi_tcp_template(TRUE, init_seqn + 1,
                                       data.seqn_got + 1,
                                       FALSE, TRUE, NULL, 0,
                                       &pkt_templ));
            CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, 0, csap_send,
                                           pkt_templ, RCF_MODE_BLOCKING));

            TAPI_WAIT_NETWORK;
            CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, csap_recv_ip6,
                                         tapi_ip6_eth_trrecv_cb_data(
                                                   &ipv6_callback, &data),
                                          NULL));
        }

        if (data.rst_got > 0)
        {
            ERROR_VERDICT("RST was sent from IUT");
        }

        if (data.fin_got > 0 || data.urg_got > 0 || data.syn_got > 0)
        {
            ERROR_VERDICT("TCP packet(s) with unexpected flags was "
                          "captured");
        }
    }
    else
    {
        if (data.tcp_pkt)
            ERROR_VERDICT("TCP packet(s) was unexpectedly captured");
    }

    TEST_STEP("Check whether IUT socket became readable. It happens on "
              "Linux if both source and destination addresses are normal "
              "IPv6, or if only source address is IPv4-mapped and "
              "@p sock_type is @c SOCK_DGRAM.");

    TEST_STEP("If IUT socket is readable, in case of UDP receive and "
              "check data. In case of TCP call @b accept() to retrieve "
              "connected IUT socket.");

    RPC_GET_READABILITY(readable, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY);
    if (readable)
    {
        if (!exp_readable)
            ERROR_VERDICT("Unexpectedly IUT socket is readable");

        if (sock_type == RPC_SOCK_DGRAM)
        {
            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_recvfrom(pco_iut, iut_s, recv_buf, sizeof(recv_buf),
                              RPC_MSG_DONTWAIT, SA(&from_addr),
                              &from_addr_len);
            if (rc < 0)
            {
                ERROR_VERDICT("recv() failed unexpectedly with errno %r",
                              RPC_ERRNO(pco_iut));
            }
            else if (rc != (int)send_len ||
                     memcmp(recv_buf, send_buf, send_len) != 0)
            {
                ERROR_VERDICT("recv() returned unexpected data");
            }
        }
        else
        {
            RPC_AWAIT_ERROR(pco_iut);
            iut_acc = rc = rpc_accept(pco_iut, iut_s, SA(&from_addr),
                                      &from_addr_len);
            if (iut_acc < 0)
            {
                ERROR_VERDICT("accept() unexpectedly failed with errno %r",
                              RPC_ERRNO(pco_iut));
            }
            else
            {
                tarpc_linger  opt_val;

                /*
                 * This is done to avoid socket hanging in TIME_WAIT state
                 * and interfering with other iterations.
                 */
                opt_val.l_onoff  = 1;
                opt_val.l_linger = 0;
                rpc_setsockopt(pco_iut, iut_acc, RPC_SO_LINGER, &opt_val);
            }
        }

        if (rc >= 0)
        {
            if (te_sockaddrcmp(SA(&from_addr), from_addr_len,
                               SA(&src_addr),
                               te_sockaddr_get_size(SA(&src_addr))) != 0)
            {
                ERROR_VERDICT("Source address reported by recvfrom() or "
                              "accept() is different from source address "
                              "in sent packet.");
            }
        }
    }
    else
    {
        if (exp_readable)
            ERROR_VERDICT("Unexpectedly IUT socket is not readable");
    }

    if (data.icmp_pkts > 1)
        ERROR_VERDICT("More than one ICMP message was received from IUT");
    else if (data.icmp_pkts == 0 && data.exp_icmp_type >= 0)
        ERROR_VERDICT("ICMP message is expected but none was received");

    TEST_STEP("Check that no IPv4 packets were sent from IUT.");

    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, csap_recv_ip4,
                                 tapi_ip4_eth_trrecv_cb_data(
                                           &ipv4_callback, &data),
                                  NULL));

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap_send));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap_recv_ip4));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap_recv_ip6));
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc);
    asn_free_value(pkt_templ);

    TEST_END;
}
