/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-error_errqueue_shutdown Socket error queue reading after shutdown
 *
 * @objective  Check that error queue events can be read after the socket
 *             shutdown.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param icmp_msgs     The list of ICMP messages to send in format:
 *                      "type:XX1,code:YY1,errno:ERR1/
 *                      type:XX2,code:YY2,errno:ERR2/..."
 * @param iomux         I/O multiplexing function type
 * @param shutdown_how  Shutdown type
 * 
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/error_errqueue_shutdown"

#include "sockapi-test.h"

#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"
#include "tapi_icmp4.h"
#include "icmp_send.h"
#include "parse_icmp.h"
#include "iomux.h"

#define ICMP_MSGS_MAX_NUM 10
#define BUF_SIZE          100

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *iut_lladdr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *tst_lladdr = NULL;
    const char                 *icmp_msgs;
    struct test_icmp_msg        icmp_msgs_arr[ICMP_MSGS_MAX_NUM];
    rpc_shut_how                shutdown_how;

    struct sockaddr_storage     msg_name;
    rpc_msghdr                  msg;
    csap_handle_t               tst_icmp_csap = CSAP_INVALID_HANDLE;
    asn_value                  *icmp_pkt = NULL;
    const char                 *err_str;
    unsigned char               pkt_buf[BUF_SIZE] = {0, };
    iomux_call_type             iomux;
    iomux_evt_fd                event;
    tarpc_timeval               timeout = {.tv_sec = 0, .tv_usec = 0};
    struct cmsghdr             *cmsg = NULL;
    struct sock_extended_err   *err;

    int iut_s = -1;
    int tst_s = -1;
    int icmp_msg_cnt = 0;
    int exp_rc;
    int exp_ev;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(tst_if);
    TEST_GET_STRING_PARAM(icmp_msgs);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_SHUT_HOW(shutdown_how);

    sockts_init_msghdr(&msg, 300);
    msg.msg_name = &msg_name;
    msg.msg_namelen = msg.msg_rnamelen = sizeof(msg_name);
    msg.msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;

    if (parse_icmp_msgs_param_with_errno(icmp_msgs, icmp_msgs_arr,
                                         ICMP_MSGS_MAX_NUM,
                                         &icmp_msg_cnt, &err_str) != 0)
        TEST_FAIL("%s", err_str);

    CHECK_RC(tapi_udp_ip4_icmp_ip4_eth_csap_create(pco_tst->ta, 0,
             tst_if->if_name, TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
             (uint8_t *)tst_lladdr->sa_data, (uint8_t *)iut_lladdr->sa_data,
             *(in_addr_t *)&(SIN(tst_addr)->sin_addr),
             *(in_addr_t *)&(SIN(iut_addr)->sin_addr),
             *(in_addr_t *)&(SIN(iut_addr)->sin_addr),
             *(in_addr_t *)&(SIN(tst_addr)->sin_addr),
             SIN(iut_addr)->sin_port, SIN(tst_addr)->sin_port,
             &tst_icmp_csap));

    TEST_STEP("Create sockets on IUT and tester, bind and connect them.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Set socket option IP_RECVERR for IUT socket.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_RECVERR, 1);

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("Shut down IUT socket for RD, WR or RDWR in dependence on "
              "@p shutdown_how.");
    rpc_shutdown(pco_iut, iut_s, shutdown_how);

    TEST_STEP("Send ICMP messages to get error event on IUT socket.");
    for (i = 0; i < icmp_msg_cnt; i++)
    {
        rc = tapi_icmp4_error_msg_pdu((uint8_t *)tst_lladdr->sa_data,
                                      (uint8_t *)iut_lladdr->sa_data,
                                      (uint8_t *)&(SIN(tst_addr)->sin_addr),
                                      (uint8_t *)&(SIN(iut_addr)->sin_addr),
                                      (uint8_t)icmp_msgs_arr[i].type,
                                      (uint8_t)icmp_msgs_arr[i].code,
                                      (uint8_t *)&(SIN(iut_addr)->sin_addr),
                                      (uint8_t *)&(SIN(tst_addr)->sin_addr),
                                      IPPROTO_UDP, SIN(iut_addr)->sin_port,
                                      SIN(tst_addr)->sin_port, pkt_buf, 100,
                                      &icmp_pkt);

        if (tapi_tad_trsend_start(pco_tst->ta, 0, tst_icmp_csap, icmp_pkt,
                                  RCF_MODE_BLOCKING) != 0)
        {
            asn_free_value(icmp_pkt);
            TEST_FAIL("Cannot send a frame from the CSAP");
        }
        asn_free_value(icmp_pkt);
    }
   TAPI_WAIT_NETWORK;

    exp_ev = iomux_init_rd_error(&event, iut_s, iomux, FALSE, &exp_rc);
    if (iomux != IC_SELECT && iomux != IC_PSELECT)
    {
        if (shutdown_how != RPC_SHUT_WR)
            exp_ev |= EVT_RD;
        if (shutdown_how == RPC_SHUT_RDWR)
            exp_ev |= EVT_HUP;
    }

    TEST_STEP("Call iomux function and check events.");
    IOMUX_CHECK_EXP(exp_rc, exp_ev, event,
                    iomux_call(iomux, pco_iut, &event, 1, &timeout));

    TEST_STEP("Read error form the IUT error queue, check its value.");
    rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
    if (te_sockaddrcmp(SA(&msg_name), msg.msg_namelen,
                       tst_addr, te_sockaddr_get_size(tst_addr)) != 0)
        TEST_VERDICT("Unexpected address was extracted from error message");

    sockts_check_msg_flags(&msg, RPC_MSG_ERRQUEUE);
    /* Check returned ancillary data */
    cmsg = sockts_msg_lookup_control_data(&msg, SOL_IP, IP_RECVERR);
    if (cmsg == NULL)
        TEST_FAIL("IP_RECVERR, ancillary data on pco_iut socket "
                  "is not received");

    err = (struct sock_extended_err *) CMSG_DATA(cmsg);
    sockts_print_sock_extended_err(err);
    sockts_check_icmp_errno(icmp_msgs_arr, err);

    TEST_SUCCESS;

cleanup:
    if (tst_icmp_csap != CSAP_INVALID_HANDLE)
        tapi_tad_csap_destroy(pco_tst->ta, 0, tst_icmp_csap);
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_release_msghdr(&msg);

    TEST_END;
}
