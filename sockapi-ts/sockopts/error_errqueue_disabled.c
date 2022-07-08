/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 */

/** @page sockopts-error_errqueue_disabled Any ICMP error message should be discarded while IP_RECVERR option is disabled
 *
 * @objective Check that any incoming ICMP error message is discarded
 *            while IP_RECVERR option is disabled.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_tst
 *                          - @ref arg_types_env_peer2peer_ipv6
 *                          - @ref arg_types_env_peer2peer_tst_ipv6
 * @param icmp_msgs         The list of ICMP messages to send in format:
 *                          "type:XX1,code:YY1,errno:ERR1/
 *                          type:XX2,code:YY2,errno:ERR2/..."
 * @param iomux             I/O multiplexing function type
 * @param select_err_queue  Set SO_SELECT_ERR_QUEUE socket option
 * 
 * @par Test sequence:
 * -# Create a connection of @p type between two sockets
 *    @p iut_s and @p tst_s that reside on @p pco_iut and @p pco_tst
 *    correspondingly;
 * -# Call @b setsockopt() on @p iut_s socket with @c IP_RECVERR socket
 *    option disabled (the option of @c SOL_IP level).
 * -# Call @b getsockopt() on @p iut_s socket with @c IP_RECVERR socket
 *    option, and check that the option is disabled.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Send a set of ICMP messages from @p tst_s to @p iut_s with 
 *    specified type and code fields and containing as the payload
 *    IPv4 datagram with UDP content that could be sent from @p iut_s
 *    to @p tst_s;
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_ERROR socket
 *    option;
 * -# Check that the function returns @c 0 and no error in
 *    @a option_value parameter 
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b recvmsg() function on @p iut_s socket with @c MSG_ERRQUEUE 
 *    flag - to extract a message from error queue;
 * -# Check that the function returns @c -1 and sets @b errno to @c EAGAIN;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s and @p tst_s sockets.
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/error_errqueue_disabled"

#include "sockapi-test.h"

#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"
#include "tapi_icmp4.h"
#include "icmp_send.h"
#include "parse_icmp.h"
#include "iomux.h"
#include "tapi_icmp.h"

#define ICMP_MSGS_MAX_NUM 10

#define TST_CMSG_LEN   300
#define TST_VEC        1
#define BUF_SIZE       100

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const char                 *icmp_msgs;
    struct test_icmp_msg        icmp_msgs_arr[ICMP_MSGS_MAX_NUM];    
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *iut_lladdr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *tst_lladdr = NULL;
    iomux_call_type            iomux;
    te_bool                    select_err_queue;
    
    struct sockaddr_storage     msg_name;
    socklen_t                   msg_namelen = sizeof(struct sockaddr_storage);
    uint8_t                     rx_buf[100];
    size_t                      rx_buf_len = sizeof(rx_buf);
    struct rpc_iovec            rx_vector;
    uint8_t                     cmsg_buf[TST_CMSG_LEN];
    rpc_msghdr                  rx_msghdr;
    csap_handle_t               tst_icmp_csap = CSAP_INVALID_HANDLE;
    asn_value                  *icmp_pkt = NULL;
    const char                 *err_str;
    unsigned char               pkt_buf[BUF_SIZE] = {0, };
    iomux_evt_fd                event;
    tarpc_timeval               timeout = {.tv_sec = 0, .tv_usec = 0};

    int icmp_msg_cnt = 0;
    int received;
    int opt_val;
    int iut_s = -1;
    int tst_s = -1;
    int i;

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
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(select_err_queue);

    rx_vector.iov_base = rx_buf;
    rx_vector.iov_len = rx_vector.iov_rlen = rx_buf_len;

    memset(&rx_msghdr, 0, sizeof(rx_msghdr));
    rx_msghdr.msg_iovlen = rx_msghdr.msg_riovlen = TST_VEC;
    rx_msghdr.msg_iov = &rx_vector;
    rx_msghdr.msg_control = cmsg_buf;
    rx_msghdr.msg_controllen = TST_CMSG_LEN;
    rx_msghdr.msg_cmsghdr_num = 1;
    rx_msghdr.msg_name = &msg_name;
    rx_msghdr.msg_namelen = rx_msghdr.msg_rnamelen = msg_namelen;

    if (parse_icmp_msgs_param_with_errno(icmp_msgs, icmp_msgs_arr,
                                         ICMP_MSGS_MAX_NUM,
                                        &icmp_msg_cnt, &err_str) != 0)
        TEST_FAIL("%s", err_str);
    if (icmp_msg_cnt < 2)
        TEST_FAIL("At least two ICMP messages should be specified");

    CHECK_RC(tapi_udp_ip_icmp_ip_eth_csap_create(pco_tst->ta, 0,
             tst_if->if_name, TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
             (uint8_t *)tst_lladdr->sa_data,
             (uint8_t *)iut_lladdr->sa_data,
             tst_addr, iut_addr,
             iut_addr, tst_addr,
             iut_addr->sa_family, &tst_icmp_csap));

    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    rpc_setsockopt_int(pco_iut, iut_s, iut_addr->sa_family == AF_INET ?
                                       RPC_IP_RECVERR : RPC_IPV6_RECVERR,
                       0);
    if (select_err_queue)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SELECT_ERR_QUEUE, 1);

    /* Send ICMP messagas and fill error queue of the socket on IUT side. */
    for (i = 0; i < icmp_msg_cnt; i++)
    {
        rc = tapi_icmp_error_msg_pdu((uint8_t *)tst_lladdr->sa_data,
                                     (uint8_t *)iut_lladdr->sa_data,
                                     tst_addr, iut_addr,
                                     (uint8_t)icmp_msgs_arr[i].type,
                                     (uint8_t)icmp_msgs_arr[i].code,
                                     iut_addr, tst_addr,
                                     IPPROTO_UDP, pkt_buf, 10,
                                     iut_addr->sa_family, &icmp_pkt);

        if (tapi_tad_trsend_start(pco_tst->ta, 0, tst_icmp_csap, icmp_pkt,
                                  RCF_MODE_BLOCKING) != 0)
        {
            asn_free_value(icmp_pkt);
            TEST_FAIL("Cannot send a frame from the CSAP");
        }
        asn_free_value(icmp_pkt);
    }
    TAPI_WAIT_NETWORK;

    event.fd = iut_s;
    event.events = EVT_RD | EVT_PRI;
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

    /* 
     * Get the value of SO_ERROR socket option, no error should be reported
     */
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if ((rpc_errno)opt_val != RPC_EOK)
        TEST_VERDICT("While IP_RECVERR option is disabled SO_ERROR option "
                     "is set to %s, but it is expected to be %s", 
                     errno_rpc2str(opt_val), errno_rpc2str(RPC_EOK));

    /* Check that error queue is empty */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    received = rpc_recvmsg(pco_iut, iut_s, &rx_msghdr,
                           RPC_MSG_ERRQUEUE | RPC_MSG_DONTWAIT);
    if (received != -1)
        TEST_FAIL("recvmsg(iut_s, &rx_msghdr, RPC_MSG_ERRQUEUE) return %d, "
                  "but it is expected to return -1, because error queue "
                  "is empty", received);
    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, 
                    "recvmsg(iut_s, &rx_msghdr, RPC_MSG_ERRQUEUE) "
                    "returns -1, but");

    TEST_SUCCESS;

cleanup:
    if (tst_icmp_csap != CSAP_INVALID_HANDLE)
        tapi_tad_csap_destroy(pco_tst->ta, 0, tst_icmp_csap);
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    TEST_END;
}
