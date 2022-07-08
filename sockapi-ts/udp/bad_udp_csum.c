/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 */

/** @page udp-bad_udp_csum Receiving packets with bad or zero UDP layer checksum
 *
 * @objective Check that socket receives packets with correct or zero
 *            checksum and drops packets with bad checksum.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_tst
 *                      - @ref arg_types_env_peer2peer_ipv6
 *                      - @ref arg_types_env_peer2peer_tst_ipv6
 * @param checksum      UDP checksum description:
 *                      - @c correct
 *                      - @c bad
 *                      - @c zero
 * @param mtu_size      IUT MTU value:
 *                      - @c -1 (do not change the current value)
 *                      - @c 2500
 *                      - @c 4500
 *                      - @c 7000
 * @param fragmented    Whether the packet should be fragmented or not
 *
 * @par Scenario
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "udp/bad_udp_csum"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_ip6.h"
#include "tapi_udp.h"
#include "tapi_cfg_base.h"
#include "ndn.h"

#define IP_HDR_LEN        20      /**< IPv4 header length */
#define IP6_HDR_LEN       40      /**< IPv6 header length */
#define UDP_HDR_LEN       8       /**< UDP header length */
#define IP6_FRAG_HDR_LEN  8       /**< Length of IPv6 Fragment
                                       extension header */

/** Maximum length of data in UDP datagram */
#define MAX_DATA_LEN 15000

/**
 * Add fragments specification splitting UDP datagram in two IP fragments.
 *
 * @param pkt           ASN description of a packet where to specify
 *                      fragments.
 * @param ipv4          If TRUE, IPv4 is checked, else IPv6.
 * @param payload_len   Length of UDP payload.
 * @param mtu_size      MTU size.
 *
 * @return Status code.
 */
static te_errno
add_fragments(asn_value *pkt, te_bool ipv4, int payload_len, int mtu_size)
{
    tapi_ip_frag_spec frags[2] = { {0, }, };
    asn_value *ip_pdu = NULL;
    te_errno rc;

    int total_udp_len;
    int max_ip_payload_len;
    int ip_hdr_len;
    int first_len;
    int second_len;

    total_udp_len = payload_len + UDP_HDR_LEN;
    ip_hdr_len = (ipv4 ? IP_HDR_LEN :
                         (IP6_HDR_LEN + IP6_FRAG_HDR_LEN));
    max_ip_payload_len = mtu_size - ip_hdr_len;

    if (max_ip_payload_len >= total_udp_len)
    {
        ERROR("Packet is too small to be fragmented");
        return TE_EFAIL;
    }

    first_len = max_ip_payload_len;

    /*
     * Fragment offset will be written in 8 octets units, so the length
     * of the first fragment must be a multiple of 8.
     */
    first_len -= (first_len % 8);

    second_len = total_udp_len - first_len;
    if (second_len > max_ip_payload_len)
    {
        ERROR("Packet is too big to fit into two fragments");
        return TE_EFAIL;
    }

    tapi_ip_frag_specs_init(frags, TE_ARRAY_LEN(frags));
    frags[0].more_frags = TRUE;
    frags[1].more_frags = FALSE;
    frags[0].real_length = first_len;
    frags[1].real_length = second_len;
    frags[1].hdr_offset = first_len;
    frags[1].real_offset = first_len;

    if (ipv4)
    {
        frags[0].hdr_length = first_len + IP_HDR_LEN;
        frags[1].hdr_length = second_len + IP_HDR_LEN;
    }
    else
    {
        frags[0].hdr_length = first_len + IP6_FRAG_HDR_LEN;
        frags[1].hdr_length = second_len + IP6_FRAG_HDR_LEN;
    }

    frags[0].id = frags[1].id = rand_range(1, 0xffff);

    ip_pdu = asn_find_descendant(pkt, &rc, "pdus.1.#ip%d", (ipv4 ? 4 : 6));
    if (rc != 0)
    {
        ERROR("Failed to locate IP PDU");
        return rc;
    }

    return tapi_ip_pdu_tmpl_fragments(NULL, &ip_pdu, ipv4, frags, 2);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;

    const struct sockaddr *iut_lladdr = NULL;
    const struct sockaddr *tst_lladdr = NULL;

    char snd_buf[MAX_DATA_LEN];
    char rcv_buf[MAX_DATA_LEN];

    te_string str = TE_STRING_INIT_STATIC(1024);

    int sid;
    int num;
    int iut_s = -1;

    int mtu_size;
    int dgram_len;

    csap_handle_t csap = CSAP_INVALID_HANDLE;
    asn_value    *pkt = NULL;

    te_bool fragmented = FALSE;

    const char  *checksum;
    int          csum_val;

    rpc_socket_domain domain;
    te_bool           readable = FALSE;
    te_bool           exp_readable;
    te_bool           test_failed = FALSE;

    te_saved_mtus   iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus   tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(mtu_size);
    TEST_GET_BOOL_PARAM(fragmented);
    TEST_GET_STRING_PARAM(checksum);

    domain = rpc_socket_domain_by_addr(iut_addr);
    if ((domain != RPC_PF_INET) && (domain != RPC_PF_INET6))
        TEST_FAIL("Invalid socket domain");

#define GET_CSUM_VAL(type_) \
    domain == RPC_PF_INET ? TE_IP4_UPPER_LAYER_CSUM_##type_ : \
                            TE_IP6_UPPER_LAYER_CSUM_##type_

    if (strcmp(checksum, "correct") == 0)
        csum_val = GET_CSUM_VAL(CORRECT);
    else if (strcmp(checksum, "bad") == 0)
        csum_val = GET_CSUM_VAL(BAD);
    else if (strcmp(checksum, "zero") == 0)
        csum_val = GET_CSUM_VAL(ZERO);
    else
        TEST_FAIL("Incorrect value of 'checksum' parameter");

    TEST_STEP("Set MTU on @p iut_if to @p mtu_size if it is positive, "
              "otherwise save the current MTU value in @p mtu_size.");

    if (mtu_size > 0)
    {
        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                        mtu_size, &iut_mtus));
    }
    else
    {
        tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name,
                                   &mtu_size);
    }

    TEST_STEP("Set MTU on @p tst_if to the same value as on @p iut_if.");
    CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                    mtu_size, &tst_mtus));

    CFG_WAIT_CHANGES;

    if (fragmented)
        dgram_len = mtu_size * 1.1;
    else
        dgram_len = mtu_size * 0.5;

    if (dgram_len > MAX_DATA_LEN)
    {
        TEST_FAIL("Not enough space in send/receive buffers for UDP "
                  "payload of %d bytes", dgram_len);
    }

    te_fill_buf(snd_buf, dgram_len);

    TEST_STEP("Create @c SOCK_DGRAM socket @b iut_s on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("Send an UDP datagram from Tester to IUT with checksum "
              "set according to @p checksum. If @p fragmented is @c TRUE, "
              "size of UDP packet should exceed IUT MTU and it should be "
              "sent in two IP fragments; otherwise its size should fit "
              "into IUT MTU and it should be sent in a single IP packet.");

    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));

    if (domain == RPC_PF_INET)
    {
        CHECK_RC(tapi_udp_ip4_eth_csap_create(
                                      pco_tst->ta, sid,
                                      tst_if->if_name,
                                      (TAD_ETH_RECV_DEF &
                                       ~TAD_ETH_RECV_OTHER) |
                                      TAD_ETH_RECV_NO_PROMISC,
                                      CVT_HW_ADDR(tst_lladdr),
                                      CVT_HW_ADDR(iut_lladdr),
                                      SIN(tst_addr)->sin_addr.s_addr,
                                      SIN(iut_addr)->sin_addr.s_addr,
                                      SIN(tst_addr)->sin_port,
                                      SIN(iut_addr)->sin_port,
                                      &csap));

        CHECK_RC(te_string_append(
                      &str, "{ pdus { udp: { checksum plain: %d}, "
                      "ip4:{}, eth:{} } }", csum_val));
    }
    else
    {
        CHECK_RC(tapi_udp_ip6_eth_csap_create(
                                      pco_tst->ta, sid,
                                      tst_if->if_name,
                                      (TAD_ETH_RECV_DEF &
                                       ~TAD_ETH_RECV_OTHER) |
                                      TAD_ETH_RECV_NO_PROMISC,
                                      CVT_HW_ADDR(tst_lladdr),
                                      CVT_HW_ADDR(iut_lladdr),
                                      SIN6(tst_addr)->sin6_addr.s6_addr,
                                      SIN6(iut_addr)->sin6_addr.s6_addr,
                                      SIN6(tst_addr)->sin6_port,
                                      SIN6(iut_addr)->sin6_port,
                                      &csap));

        CHECK_RC(te_string_append(
                    &str, "{ pdus { udp: { checksum plain: %d}, "
                    "ip6:{}, eth:{} } }", csum_val));
    }

    CHECK_RC(asn_parse_value_text(str.ptr, ndn_traffic_template,
                                  &pkt, &num));
    CHECK_RC(asn_write_value_field(pkt, snd_buf, dgram_len,
                                   "payload.#bytes"));

    if (fragmented)
    {
        CHECK_RC(add_fragments(pkt, (domain == RPC_PF_INET), dgram_len,
                               mtu_size));
    }

    CHECK_RC(rcf_tr_op_log(FALSE));
    RING("Sending from Tester an UDP datagram with payload of length %d%s",
         dgram_len, (fragmented ? " split into two fragments" : ""));
    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid, csap, pkt,
                                   RCF_MODE_BLOCKING));

    TAPI_WAIT_NETWORK;

    TEST_STEP("If either @p checksum is @c bad or IPv6 is checked and "
              "@p checksum is @c zero, check that the IUT socket is not "
              "readable. Otherwise check that it is readable and sent "
              "data can be received.");

    if (strcmp(checksum, "bad") == 0 ||
        (domain == RPC_PF_INET6 && strcmp(checksum, "zero") == 0))
    {
        exp_readable = FALSE;
    }
    else
    {
        exp_readable = TRUE;
    }

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 0);
    if (exp_readable && !readable)
    {
        TEST_VERDICT("IUT socket should be readable but it is not");
    }
    else if (!exp_readable && readable)
    {
        test_failed = TRUE;
        ERROR_VERDICT("IUT socket is readable but it should not be");
    }

    if (readable)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_recv(pco_iut, iut_s, rcv_buf, sizeof(rcv_buf),
                      RPC_MSG_DONTWAIT);
        if (rc < 0)
        {
            TEST_VERDICT("recv() on IUT unexpectedly failed with error %r",
                         RPC_ERRNO(pco_iut));
        }

        if (rc != dgram_len)
            TEST_VERDICT("recv() returned unexpected value");
        if (memcmp(rcv_buf, snd_buf, dgram_len) != 0)
            TEST_VERDICT("recv() returned unexpected data");
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, sid, csap));

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));
    CFG_WAIT_CHANGES;

    asn_free_value(pkt);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
