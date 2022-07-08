/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP protocol special cases
 */

/** @page tcp-connect_nb_impossible_icmp Functions behaviour after ICMP destination unreachable sent
 *
 * @objective Check behaviour of various functions after ICMP message
 *            "destination unreachable" is received from server after
 *            @b connect().
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param func          Function to check after unsatisfied connect:
 *                      - @b connect
 *                      - @b send
 *                      - @b recv
 *                      - @b recvmsg
 *                      - @b onload_zc_recv
 *                      - @b onload_zc_hlrx_recv_zc
 *                      - @b onload_zc_hlrx_recv_copy
 *                      - @b select
 *                      - @b getsockopt(@c SO_ERROR)
 *                      - @b poll
 *                      - @b onload_zc_send
 *                      - @b onload_zc_send_user_buf
 *                      - @b template_send
 *                      - @b od_send
 *                      - @b od_send_raw
 * @param icmp_code     Code from ICMP/ICMPv6 message
 *
 * @par Scenario
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/connect_nb_impossible_icmp"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"

#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif
#include <linux/icmpv6.h>

#include <linux/types.h>
#include <linux/errqueue.h>

#include "icmp_send.h"

#include "tapi_tad.h"
#include "tapi_tcp.h"
#include "tapi_ip4.h"
#include "tapi_eth.h"
#include "tapi_cfg_base.h"
#include "ndn.h"
#include "iomux.h"

#include "tcp_test_macros.h"

#define DATA_BULK       1024  /**< Size of data to be sent */
#define POLL_TIMEOUT    2000  /**< Timeout for poll() function */

static uint8_t data_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;

    int iut_s = -1;

    const struct sockaddr   *iut_addr;
    const struct sockaddr   *tst_fake_addr;
    const struct sockaddr   *conn_addr;

    int8_t                   icmp_type;    /** ICMP type number */
    int8_t                   icmp_code;    /** ICMP code number */
    const char              *func;

    char                    *format_string;

    const struct sockaddr       *alien_link_addr;
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if;

    csap_handle_t                csap = CSAP_INVALID_HANDLE;

    int sid;
    int num;

    int await_err_code;

    int     req_val = TRUE;

    asn_value *pkt;

    /* Preambule */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_STRING_PARAM(func);

    if (iut_addr->sa_family == AF_INET)
    {
        icmp_type = ICMP_DEST_UNREACH;
        TEST_GET_ENUM_PARAM(icmp_code, ICMPV4_CODES);
    }
    else
    {
        icmp_type = ICMPV6_DEST_UNREACH;
        TEST_GET_ENUM_PARAM(icmp_code, ICMPV6_CODES);
    }

    conn_addr = tst_fake_addr;

    TEST_STEP("Create socket @p iut_s of type @c SOCK_STREAM on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Bind @p iut_s to local address.");
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("Call @b ioctl(@c FIONBIO) on @p iut_s socket to make it "
              "nonblocking.");
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    TEST_STEP("Create neighbor entry for @p tst_fake_addr on @b IUT, "
              "associating it with nonassigned MAC.");

    if (tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                        tst_fake_addr, CVT_HW_ADDR(alien_link_addr),
                        TRUE) != 0)
    {
        TEST_FAIL("Cannot add neighbor entry");
    }
    CFG_WAIT_CHANGES;

    TEST_STEP("Create CSAP for sending ICMP messages from @b Tester.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
                    pco_tst->ta, sid, tst_if->if_name, TAD_ETH_RECV_DEF,
                    NULL, NULL, iut_addr->sa_family,
                    TAD_SA2ARGS(tst_fake_addr, iut_addr), &csap));
    format_string = malloc(100);
    sprintf(format_string, "{{ pdus {tcp:{}, ip%u:{}, eth:{}},"
                           "   actions { function:\"tad_icmp_error:%d:%d\" }}}",
                           (iut_addr->sa_family == AF_INET6 ? 6 : 4),
                           icmp_type, icmp_code);

    rc = asn_parse_value_text(format_string, ndn_traffic_pattern, &pkt, &num);

    TEST_STEP("Start CSAP operation: send ICMP with needed code about fake "
              "address from @b Tester to @b IUT when IP packet will be "
              "captured.");
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap,
                                   pkt, 32000, 30, RCF_TRRECV_COUNT));
    RPC_AWAIT_IUT_ERROR(pco_iut);

    TEST_STEP("Try to connect from @p pco_iut to fake address and check error "
              "code.");
    if (rpc_connect(pco_iut, iut_s, tst_fake_addr) != -1)
    {
        TEST_VERDICT("connect() returned unexpected success when invalid "
                     "neighbor entry for server IP address exists");
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINPROGRESS,
                    "connect() function called on IUT "
                    "returned -1, but");

    SLEEP(2);

    /* Determine expected error code */
    if (iut_addr->sa_family == AF_INET)
    {
        switch (icmp_code)
        {
            case ICMP_NET_UNREACH:
                await_err_code = RPC_ENETUNREACH;
                break;
            case ICMP_HOST_UNREACH:
                await_err_code = RPC_EHOSTUNREACH;
                break;
            case ICMP_PROT_UNREACH:
                await_err_code = RPC_ENOPROTOOPT;
                break;
            case ICMP_PORT_UNREACH:
                await_err_code = RPC_ECONNREFUSED;
                break;
        }
    }
    else
    {
        switch (icmp_code)
        {
            case ICMPV6_NOROUTE:
                await_err_code = RPC_ENETUNREACH;
                break;
            case ICMPV6_ADM_PROHIBITED:
            case ICMPV6_POLICY_FAIL:
            case ICMPV6_REJECT_ROUTE:
                await_err_code = RPC_EACCES;
                break;
            case ICMPV6_NOT_NEIGHBOUR:
            case ICMPV6_ADDR_UNREACH:
                await_err_code = RPC_EHOSTUNREACH;
                break;
            case ICMPV6_PORT_UNREACH:
                await_err_code = RPC_ECONNREFUSED;
                break;
        }
    }

    TEST_STEP("Call @p func on @p iut_s socket and check rc, if it fails with "
              "expected errno, call send/receive functions and check their "
              "returned errors.");
    TCP_TEST_CHECK_FUNCTION(func, await_err_code);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (pco_iut != NULL && iut_if != NULL &&
        tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                 tst_fake_addr) != 0)
    {
        ERROR("Cannot delete ARP entry");
        result = EXIT_FAILURE;
    }

    if (pco_tst != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    free(format_string);

    TEST_END;
}
