/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-last_pending_error Correct behaviour of SO_ERROR socket option
 *
 * @objective Check that @c SO_ERROR socket option can be used to get
 *            the correct value of pending socket error despite several
 *            different ICMP error messages were received from
 *            different interfaces.
 *
 * @reference @ref STEVENS, setcion 7.5
 *
 * @param pco_iut        PCO on IUT
 * @param pco_tst1       PCO on Tester1
 * @param pco_tst2       PCO on Tester2
 * @param tst1_msgs      list of ICMP messages' parameters
 *                       with corresponding expected socket errors
 *                       to be sent from pco_tst1
 * @param tst2_msgs      list of ICMP messages' parameters
 *                       with corresponding expected socket errors
 *                       to be sent from pco_tst2
 * @param num_pkts       number of ICMP messages to be sent
 *                       each tester PCO
 * @param ip_recverr     enable to set IP_RECVERR socket option
 *
 * @par Test sequence:
 * -# Create datagram sockets @p iut_s, @p tst1_s and  @p tst2_s;
 * -# Bind @p iut_s to wildcard IP address and port, bind @p tst1_s to @p tst1_addr,
 *    @p tst2_s - to @p tst2_addr;
 * -# Create @p tst1_eth_csap and @p tst2_eth_csap on
 *    @p pco_tst1 and @p pco_tst2 correspondingly.
 * -# Set @c IP_RECVERR socket option enabled if @p ip_recverr is @c TRUE;
 * -# Repeat the following steps @p num_pkts times:
 *      -# Send datagrams addressed to @p tst1_addr and @p tst2_addr
 *         via @p iut_s;
 *      -# Send two different ICMP messages via  @p tst1_eth_csap and
 *         @p tst2_eth_csap to  @p iut_s;
 *      -# Call @b getsockopt() on @p iut_s socket with @c SO_ERROR
 *         socket option. Check that the function returns @c 0 and
 *         @a option_value parameter is updated to the expected
 *         @b errno corresponding to the last sent ICMP message.
 *
 * @author Konstantin Petrov <Konstantin.Petrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/last_pending_error"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_icmp4.h"
#include "icmp_send.h"
#include "parse_icmp.h"

#define ICMP_MSGS_MAX_NUM 10

int
main(int argc, char *argv[])
{
    rcf_rpc_server                 *pco_iut = NULL;
    rcf_rpc_server                 *pco_tst1 = NULL;
    rcf_rpc_server                 *pco_tst2 = NULL;

    const struct sockaddr          *iut_addr1;
    const struct sockaddr          *iut_addr2;
    const struct sockaddr          *tst1_addr;
    const struct sockaddr          *tst2_addr;
    const struct sockaddr          *iut_if1_hwaddr;
    const struct sockaddr          *iut_if2_hwaddr;
    const struct sockaddr          *tst1_hwaddr;
    const struct sockaddr          *tst2_hwaddr;

    struct sockaddr_storage         bind_addr;
    uint16_t                        bind_port;

    const struct if_nameindex      *tst1_if;
    const struct if_nameindex      *tst2_if;

    te_bool                         ip_recverr = FALSE;

    int                             iut_s = -1;
    int                             tst1_s = -1;
    int                             tst2_s = -1;

    csap_handle_t                   tst1_icmp_csap = CSAP_INVALID_HANDLE;
    csap_handle_t                   tst2_icmp_csap = CSAP_INVALID_HANDLE;

    rpc_errno                       opt_val = 0;

    rpc_socket_domain               domain;

    const char                     *tst1_msgs;
    const char                     *tst2_msgs;
    struct test_icmp_msg            tst1_msgs_arr[ICMP_MSGS_MAX_NUM];
    struct test_icmp_msg            tst2_msgs_arr[ICMP_MSGS_MAX_NUM];
    int                             tst1_msg_cnt = 0;
    int                             tst2_msg_cnt = 0;
    const char                     *err_str;

    int                             num_pkts;

    int                             i;

    asn_value                      *icmp_pkt = NULL;

    unsigned char                   pkt_buf[32] = {0, };

    void                           *tx_buf = NULL;
    size_t                          buf_len;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_LINK_ADDR(iut_if1_hwaddr);
    TEST_GET_LINK_ADDR(iut_if2_hwaddr);
    TEST_GET_LINK_ADDR(tst1_hwaddr);
    TEST_GET_LINK_ADDR(tst2_hwaddr);

    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);

    TEST_GET_BOOL_PARAM(ip_recverr);

    TEST_GET_STRING_PARAM(tst1_msgs);
    TEST_GET_STRING_PARAM(tst2_msgs);

    TEST_GET_INT_PARAM(num_pkts);

    domain =  rpc_socket_domain_by_addr(iut_addr1);
    CHECK_NOT_NULL(tx_buf = sockts_make_buf_dgram(&buf_len));

    if (parse_icmp_msgs_param_with_errno(tst1_msgs, tst1_msgs_arr,
                                         ICMP_MSGS_MAX_NUM,
                                         &tst1_msg_cnt, &err_str) != 0)
    {
        TEST_FAIL("%s", err_str);
    }
    if (tst1_msg_cnt < num_pkts)
    {
        TEST_FAIL("At least %d ICMP messages for "
                  "pco_tst1 should be specified", num_pkts);
    }

    if (parse_icmp_msgs_param_with_errno(tst2_msgs, tst2_msgs_arr,
                                         ICMP_MSGS_MAX_NUM,
                                         &tst2_msg_cnt, &err_str) != 0)
    {
        TEST_FAIL("%s", err_str);
    }
    if (tst2_msg_cnt < num_pkts)
    {
        TEST_FAIL("At least %d ICMP messages for "
                  "pco_tst2 should be specified", num_pkts);
    }

    /* 1) Create datagram sockets */
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    /* Bind to wildcard address */
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.ss_family = iut_addr1->sa_family;
    te_sockaddr_set_port(SA(&bind_addr),
                         bind_port = te_sockaddr_get_port(iut_addr1));
    rpc_bind(pco_iut, iut_s, CONST_SA(&bind_addr));

    rpc_bind(pco_tst1, tst1_s, tst1_addr);
    rpc_bind(pco_tst2, tst2_s, tst2_addr);

    /* 2a) Create Ethernet CSAP on pco_tst1 */
    rc = tapi_udp_ip4_icmp_ip4_eth_csap_create(pco_tst1->ta, 0,
             tst1_if->if_name, TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
             (uint8_t *)tst1_hwaddr->sa_data,
             (uint8_t *)iut_if1_hwaddr->sa_data,
             *(in_addr_t *)&(SIN(tst1_addr)->sin_addr),
             *(in_addr_t *)&(SIN(iut_addr1)->sin_addr),
             *(in_addr_t *)&(SIN(iut_addr1)->sin_addr),
             *(in_addr_t *)&(SIN(tst1_addr)->sin_addr),
             bind_port, te_sockaddr_get_port(tst1_addr),
             &tst1_icmp_csap);
    if (rc != 0)
    {
        TEST_FAIL("Cannot create ICMP CSAP on pco_tst1");
    }

    /* 2b) Create Ethernet CSAP on pco_tst2 */
    rc = tapi_udp_ip4_icmp_ip4_eth_csap_create(pco_tst2->ta, 0,
             tst2_if->if_name, TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
             (uint8_t *)tst2_hwaddr->sa_data,
             (uint8_t *)iut_if2_hwaddr->sa_data,
             *(in_addr_t *)&(SIN(tst2_addr)->sin_addr),
             *(in_addr_t *)&(SIN(iut_addr2)->sin_addr),
             *(in_addr_t *)&(SIN(iut_addr2)->sin_addr),
             *(in_addr_t *)&(SIN(tst2_addr)->sin_addr),
             bind_port, te_sockaddr_get_port(tst1_addr),
             &tst2_icmp_csap);
    if (rc != 0)
    {
        TEST_FAIL("Cannot create ICMP CSAP on pco_tst2");
    }

    if (ip_recverr)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        opt_val = 1;
        if (rpc_setsockopt(pco_iut, iut_s, RPC_IP_RECVERR, &opt_val) != 0)
            TEST_VERDICT("setsockopt(IP_RECVERR) failed with errno %s",
                          errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    for (i = 0; i < num_pkts; i++)
    {
        rpc_sendto(pco_iut, iut_s, tx_buf, buf_len, 0, tst1_addr);
        rpc_sendto(pco_iut, iut_s, tx_buf, buf_len, 0, tst2_addr);

        /* 4a) Send ICMP message via tst1_icmp_csap */
        rc = tapi_icmp4_error_msg_pdu((uint8_t *)tst1_hwaddr->sa_data,
                                      (uint8_t *)iut_if1_hwaddr->sa_data,
                                      (uint8_t *)&(SIN(tst1_addr)->sin_addr),
                                      (uint8_t *)&(SIN(iut_addr1)->sin_addr),
                                      tst1_msgs_arr[i].type,
                                      tst1_msgs_arr[i].code,
                                      (uint8_t *)&(SIN(iut_addr1)->sin_addr),
                                      (uint8_t *)&(SIN(tst1_addr)->sin_addr),
                                      IPPROTO_UDP, bind_port,
                                      te_sockaddr_get_port(tst1_addr),
                                      pkt_buf, 10,
                                      &icmp_pkt);

        if (tapi_tad_trsend_start(pco_tst1->ta, 0, tst1_icmp_csap, icmp_pkt,
                                  RCF_MODE_BLOCKING) != 0)
        {
            asn_free_value(icmp_pkt);
            TEST_FAIL("Cannot send a frame via tst1_icmp_csap");
        }
        asn_free_value(icmp_pkt);
        TAPI_WAIT_NETWORK;

        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
        if (opt_val != tst1_msgs_arr[i].map_errno)
            TEST_VERDICT("SO_ERROR option is set to %s instead of %s",
                         errno_rpc2str(opt_val),
                         errno_rpc2str(tst1_msgs_arr[i].map_errno));


        /* 4b) Send ICMP message via tst2_icmp_csap */
        rc = tapi_icmp4_error_msg_pdu((uint8_t *)tst2_hwaddr->sa_data,
                                      (uint8_t *)iut_if2_hwaddr->sa_data,
                                      (uint8_t *)&(SIN(tst2_addr)->sin_addr),
                                      (uint8_t *)&(SIN(iut_addr2)->sin_addr),
                                      tst2_msgs_arr[i].type,
                                      tst2_msgs_arr[i].code,
                                      (uint8_t *)&(SIN(iut_addr2)->sin_addr),
                                      (uint8_t *)&(SIN(tst2_addr)->sin_addr),
                                      IPPROTO_UDP, bind_port,
                                      te_sockaddr_get_port(tst1_addr),
                                      pkt_buf, 10,
                                      &icmp_pkt);

        if (tapi_tad_trsend_start(pco_tst2->ta, 0, tst2_icmp_csap, icmp_pkt,
                                  RCF_MODE_BLOCKING) != 0)
        {
            asn_free_value(icmp_pkt);
            TEST_FAIL("Cannot send a frame via tst2_icmp_csap");
        }
        asn_free_value(icmp_pkt);
        TAPI_WAIT_NETWORK;

        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
        if (opt_val != tst2_msgs_arr[i].map_errno)
            TEST_VERDICT("SO_ERROR option is set to %s instead of %s",
                         errno_rpc2str(opt_val),
                         errno_rpc2str(tst2_msgs_arr[i].map_errno));
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != 0)
        TEST_VERDICT("SO_ERROR option was not cleared after "
                     "getsockopt() call.");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0, tst1_icmp_csap));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst2->ta, 0, tst2_icmp_csap));

    free(tx_buf);

    TEST_END;
}
