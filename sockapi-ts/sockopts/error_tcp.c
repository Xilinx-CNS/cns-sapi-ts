/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 */

/** @page sockopts-error_tcp TCP socket state is not affected by ICMP error messages
 *
 * @objective Check that the value of @c SO_ERROR socket option is not
 *            updated on retriving error message from error queue  
 *            containg incoming ICMP messages.
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
 * @param pco_tst           PCO on TST
 * @param icmp_msgs         ICMP message
 * @param passive           Passive connection opening if @c TRUE
 * @param iomux             I/O multiplexing function type
 * @param select_err_queue  Set SO_SELECT_ERR_QUEUE socket option
 * 
 * @par Test sequence:
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/error_tcp"

#include "sockapi-test.h"

#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"
#include "tapi_icmp4.h"
#include "icmp_send.h"
#include "parse_icmp.h"
#include "iomux.h"
#include "tapi_icmp.h"

#define TST_CMSG_LEN    300
#define TST_VEC         1

#define BUF_SIZE        100

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *iut_lladdr = NULL;
    const struct sockaddr     *tst_lladdr = NULL;
    const char                *icmp_msgs;
    struct test_icmp_msg       icmp;
    te_bool                    passive;
    iomux_call_type            iomux;
    te_bool                    select_err_queue;

    struct sockaddr_storage     msg_name;
    socklen_t                   msg_namelen = sizeof(struct sockaddr_storage);
    uint8_t                     rx_buf[100];
    size_t                      rx_buf_len = sizeof(rx_buf);
    struct rpc_iovec            rx_vector;
    uint8_t                     cmsg_buf[TST_CMSG_LEN];
    rpc_msghdr                  rx_msghdr;
    csap_handle_t               csap = CSAP_INVALID_HANDLE;
    unsigned char               buf[BUF_SIZE] = {0, };
    unsigned char               pkt_buf[BUF_SIZE] = {0, };
    asn_value                  *icmp_pkt = NULL;
    const char                 *err_str;
    iomux_evt_fd                event;
    tarpc_timeval               timeout = {.tv_sec = 0, .tv_usec = 0};

    int icmp_msg_cnt;
    int iut_s = -1;
    int tst_s = -1;
    int opt_val;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_STRING_PARAM(icmp_msgs);
    TEST_GET_BOOL_PARAM(passive);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(select_err_queue);

    if (parse_icmp_msgs_param_with_errno(icmp_msgs, &icmp, 1,
                                         &icmp_msg_cnt, &err_str) != 0)
        TEST_FAIL("%s", err_str);
    if (icmp_msg_cnt == 0)
        TEST_FAIL("No ICMP messages requested, fix arg icmp_msgs");

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

    CHECK_RC(tapi_tcp_ip_icmp_ip_eth_csap_create(pco_tst->ta, 0,
                 tst_if->if_name, TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                 (uint8_t *)tst_lladdr->sa_data,
                 (uint8_t *)iut_lladdr->sa_data,
                 tst_addr, iut_addr,
                 iut_addr, tst_addr,
                 iut_addr->sa_family, &csap));

    TEST_STEP("Create TCP socket and establish connection with a peer.");
    if (passive)
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                       iut_addr, tst_addr, &iut_s, &tst_s);
    else
        GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                       tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Set socket option IP_RECVERR to @c 1.");
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s, iut_addr->sa_family == AF_INET ?
                                   RPC_IP_RECVERR : RPC_IPV6_RECVERR,
                   &opt_val);
    rpc_getsockopt(pco_iut, iut_s, iut_addr->sa_family == AF_INET ?
                                   RPC_IP_RECVERR : RPC_IPV6_RECVERR,
                   &opt_val);
    if (opt_val == 0)
        TEST_VERDICT("IP_RECVERR could not be ENABLED for TCP socket");

    if (select_err_queue)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SELECT_ERR_QUEUE, 1);

    CHECK_RC(tapi_icmp_error_msg_pdu((uint8_t *)tst_lladdr->sa_data,
                                     (uint8_t *)iut_lladdr->sa_data,
                                     tst_addr, iut_addr,
                                     (uint8_t)icmp.type, (uint8_t)icmp.code,
                                     iut_addr, tst_addr,
                                     IPPROTO_TCP, pkt_buf, 10,
                                     iut_addr->sa_family, &icmp_pkt));

    TEST_STEP("Send ICMP error message from the peer.");
    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, 0, csap, icmp_pkt,
                                   RCF_MODE_BLOCKING));
    TAPI_WAIT_NETWORK;

    event.fd = iut_s;
    event.events = EVT_RD | EVT_PRI;

    TEST_STEP("Call iomux function to make sure that there is no incoming or error "
              "events on the IUT socket.");
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

    TEST_STEP("Senda a data packet from the socket.");
    rpc_send(pco_iut, iut_s, buf, BUF_SIZE, 0);
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);

    TEST_STEP("Check that error queue is empty.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvmsg(pco_iut, iut_s, &rx_msghdr,
                     RPC_MSG_ERRQUEUE | RPC_MSG_DONTWAIT);
    if (rc != -1)
        TEST_VERDICT("recvmsg call unexpectedly succeeded");
    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "recvmsg call failed, but");

    TEST_SUCCESS;

cleanup:
    asn_free_value(icmp_pkt);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    TEST_END;
}
