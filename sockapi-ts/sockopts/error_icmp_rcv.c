/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-error_icmp_rcv Usage of SO_ERROR socket option for detecting of incoming ICMP error messages
 *
 * @objective Check that @c SO_ERROR socket option can be used to get
 *            the pending errors reported by incoming ICMP messages.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param icmp_msgs     The list of ICMP messages to send in format:
 *                      "type:XX1,code:YY1/type:XX2,code:YY2/..."
 * @param exp_errno     Expected errno value obtained with @c SO_ERROR
 *                      socket option
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/error_icmp_rcv"

#include "sockapi-test.h"

#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#include <linux/types.h>
#include <linux/errqueue.h>

#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"
#include "tapi_icmp.h"
#include "icmp_send.h"
#include "parse_icmp.h"

static const char *
icmp_msgs_to_str(const struct icmp_msg *msgs, unsigned int num)
{
    static char     buf[100];

    unsigned int    i;

    *buf = '\0';
    for (i = 0; i < num; ++i)
    {
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
                 "%stype:%d,code:%d", i == 0 ? "" : "/",
                 msgs[i].type, msgs[i].code);
    }
    return buf;
}

#define ICMP_MSGS_MAX_NUM 10

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    int             iut_s = -1;
    int             tst_s = -1;
    
    rpc_errno          exp_errno;
    const char        *icmp_msgs;
    struct icmp_msg    icmp_msgs_arr[ICMP_MSGS_MAX_NUM];
    
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *iut_lladdr = NULL;

    const struct if_nameindex   *tst_if;
    const struct sockaddr       *tst_addr;
    const struct sockaddr       *tst_lladdr = NULL;
    
    int                    opt_val;

    unsigned char          pkt_buf[32] = {0, };
    
    csap_handle_t  tst_icmp_csap = CSAP_INVALID_HANDLE;
    asn_value     *icmp_pkt = NULL;
    int            icmp_msg_cnt = 0;
    int            i;
    const char    *err_str;
    int            ret;
   

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(tst_if);
    TEST_GET_STRING_PARAM(icmp_msgs);
    TEST_GET_ERRNO_PARAM(exp_errno);

    if (parse_icmp_msgs_param(icmp_msgs, icmp_msgs_arr, ICMP_MSGS_MAX_NUM,
                              &icmp_msg_cnt, &err_str) != 0)
    {
        TEST_FAIL("%s", err_str);
    }

    TEST_STEP("Create CSAP for sending ICMP messages from @b Tester.");
    rc = tapi_udp_ip_icmp_ip_eth_csap_create(pco_tst->ta, 0,
             tst_if->if_name, TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
             (uint8_t *)tst_lladdr->sa_data,
             (uint8_t *)iut_lladdr->sa_data,
             tst_addr, iut_addr,
             iut_addr, tst_addr,
             iut_addr->sa_family, &tst_icmp_csap);
    if (rc != 0)
    {
        TEST_FAIL("Cannot create Ethernet CSAP on Tester");
    }

    TEST_STEP("Create a connection of type @c SOCK_DGRAM between two sockets "
              "@p iut_s and @p tst_s that reside on @b IUT and @b Tester "
              "correspondingly.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);


    TEST_STEP("Enable @c IP_RECVERR socket option on @p iut_s.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    opt_val = 1;
    ret = rpc_setsockopt(pco_iut, iut_s,
                         iut_addr->sa_family == AF_INET ? RPC_IP_RECVERR :
                                                          RPC_IPV6_RECVERR,
                         &opt_val);
    if (ret != 0)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOPROTOOPT,
                        "setsockopt(IP_RECVERR) failed");
        WARN("IP_RECVERR is not supported");
    }

    TEST_STEP("Send a set of ICMP messages from @b Tester CSAP to @b IUT with "
              "specified type and code fields and containing as the payload "
              "IP datagram with UDP content that could be sent from @b IUT "
              "to @b Tester.");
    for (i = 0; i < icmp_msg_cnt; i++)
    {
        /* Send ICMP error message */
        rc = tapi_icmp_error_msg_pdu((uint8_t *)tst_lladdr->sa_data,
                                     (uint8_t *)iut_lladdr->sa_data,
                                     tst_addr, iut_addr,
                                     icmp_msgs_arr[i].type,
                                     icmp_msgs_arr[i].code,
                                     iut_addr, tst_addr,
                                     IPPROTO_UDP,
                                     pkt_buf, 10,
                                     iut_addr->sa_family,
                                     &icmp_pkt);
        if (tapi_tad_trsend_start(pco_tst->ta, 0, tst_icmp_csap, icmp_pkt,
                                  RCF_MODE_BLOCKING) != 0)
        {
            asn_free_value(icmp_pkt);
            TEST_FAIL("Cannot send a frame from the CSAP");
        }

        asn_free_value(icmp_pkt);
    }

    TEST_STEP("Get the value of @c SO_ERROR socket option on @p iut_s the "
              "first time and make sure it is equal to @p exp_errno.");
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if ((rpc_errno)opt_val != exp_errno)
    {
        TEST_VERDICT("After receiving the sequence of ICMP messages %s "
                      "SO_ERROR option is set to %s, but it is expected "
                      "to be %s",
                      icmp_msgs_to_str(icmp_msgs_arr, icmp_msg_cnt),
                      errno_rpc2str(opt_val), errno_rpc2str(exp_errno));
    }

    TEST_STEP("Get the value of @c SO_ERROR socket option on @p iut_s the "
              "second time and make sure it is reset to zero.");
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != 0)
    {
        TEST_FAIL("SO_ERROR socket option is not reset to zero after "
                  "it is got");
    }

    TEST_SUCCESS;

cleanup:
    if (tst_icmp_csap != CSAP_INVALID_HANDLE)
        tapi_tad_csap_destroy(pco_tst->ta, 0, tst_icmp_csap);
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
