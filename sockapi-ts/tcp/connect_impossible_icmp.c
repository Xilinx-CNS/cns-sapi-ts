/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 *
 * This test package contains tests for special cases of TCP protocol,
 * such as ICMP and routing table handling, small and zero window,
 * fragmentation of TCP packets, etc.
 */

/** @page tcp-connect_impossible_icmp  ICMP destination unreachable is sent in answer to SYN
 *
 * @objective Check @b connect() call behaviour when ICMP message
 *            "destination unreachable" is received from the peer.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param error_code        Code from ICMP message
 * @param iomux             I/O multiplexing function type
 * @param select_err_queue  Set SO_SELECT_ERR_QUEUE socket option
 * @param blocking          if @c FALSE, tested function calls are
 *                          non-blocking.
 *
 * @par Scenario
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Dmitrij Komoltsev <Dmitrij.Komoltsev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/connect_impossible_icmp"

#include "sockapi-test.h"
#include "tapi_cfg.h"

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
#include "tapi_route_gw.h"
#include "ndn.h"
#include "iomux.h"

#define DATA_BULK       1024  /**< Size of data to be sent */
static uint8_t data_buf[DATA_BULK];

/*
 * This function is used instead of CHECK_RPC_ERRNO() because it does
 * not print expected errno in verdict in case of failure. This greatly
 * simplifies TRC for this test.
 */
static te_errno
check_rpc_errno(rcf_rpc_server *rpcs, te_errno exp_errno, const char *msg)
{
    te_errno err = RPC_ERRNO(rpcs);

    if (err != exp_errno)
    {
        ERROR("%s: %r errno was expected but %r was reported instead",
              msg, exp_errno, err);
        ERROR_VERDICT("%s: unexpected errno %r was reported", msg, err);
        return TE_EFAIL;
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_iut_aux = NULL;
    rcf_rpc_server    *pco_tst = NULL;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_fake_addr;
    const void                *alien_link_addr;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if;
    int8_t                     error_type;    /** ICMP type number */
    int8_t                     error_code;    /** ICMP code number */
    te_bool                    select_err_queue;
    te_bool                    blocking;
    te_bool                    test_failed = FALSE;

    unsigned int    pkt_count = 0;
    csap_handle_t   csap = CSAP_INVALID_HANDLE;
    asn_value      *pkt;
    iomux_call_type iomux;
    iomux_evt_fd    event;
    tarpc_timeval   timeout = {.tv_sec = 0, .tv_usec = 500000};
    char           *format_string = NULL;
    rpc_msghdr      msg = {.msg_iov = NULL, .msg_control = NULL};

    int             wait_count = 10;

    int ret_errno;
    int iut_s = -1;
    int val = 1;
    int sid;
    int num;
    int exp;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_fake_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(select_err_queue);
    TEST_GET_BOOL_PARAM(blocking);

    if (iut_addr->sa_family == AF_INET)
    {
        error_type = ICMP_DEST_UNREACH;
        TEST_GET_ENUM_PARAM(error_code, ICMPV4_CODES);
    }
    else
    {
        error_type = ICMPV6_DEST_UNREACH;
        TEST_GET_ENUM_PARAM(error_code, ICMPV6_CODES);
    }

    /* Determine expected error code */
    if (iut_addr->sa_family == AF_INET)
    {
        switch (error_code)
        {
            case ICMP_NET_UNREACH:
                ret_errno = RPC_ENETUNREACH;
                break;
            case ICMP_HOST_UNREACH:
                ret_errno = RPC_EHOSTUNREACH;
                break;
            case ICMP_PROT_UNREACH:
                ret_errno = RPC_ENOPROTOOPT;
                break;
            case ICMP_PORT_UNREACH:
                ret_errno = RPC_ECONNREFUSED;
                break;
        }
    }
    else
    {
        switch (error_code)
        {
            case ICMPV6_NOROUTE:
                ret_errno = RPC_ENETUNREACH;
                break;
            case ICMPV6_ADM_PROHIBITED:
            case ICMPV6_POLICY_FAIL:
            case ICMPV6_REJECT_ROUTE:
                ret_errno = RPC_EACCES;
                break;
            case ICMPV6_NOT_NEIGHBOUR:
            case ICMPV6_ADDR_UNREACH:
                ret_errno = RPC_EHOSTUNREACH;
                break;
            case ICMPV6_PORT_UNREACH:
                ret_errno = RPC_ECONNREFUSED;
                break;
        }
    }

    sockts_init_msghdr(&msg, DATA_BULK + 300);

    TEST_STEP("Create socket @p iut_s of type @c SOCK_STREAM on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Bind @p iut_s and @p tst_s to local addresses.");
    rpc_bind(pco_iut, iut_s, iut_addr);

    rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_RECVERR, 1);
    if (select_err_queue)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SELECT_ERR_QUEUE, 1);

    TEST_STEP("Create neighbor entry for @p tst_fake_addr on @b IUT, "
              "associating it with nonassigned MAC.");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_fake_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    TAPI_WAIT_NETWORK;

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
                           error_type, error_code);

    rc = asn_parse_value_text(format_string, ndn_traffic_pattern, &pkt, &num);

    TEST_STEP("Start CSAP operation: send ICMP with needed code "
              "from @b Tester to @b IUT when IP packet will be "
              "captured.");
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap,
                                   pkt, 32000, 30, RCF_TRRECV_COUNT));
    /* Make sure that CSAP really started (ST-2246) */
    TAPI_WAIT_NETWORK;

    TEST_STEP("Try to connect from @p pco_iut to fake address and check "
              "error code.");

    if (blocking)
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_aux", &pco_iut_aux));
    else
        rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &val);

    if (blocking)
    {
        pco_iut->op = RCF_RPC_CALL;
        rc = rpc_connect(pco_iut, iut_s, tst_fake_addr);

        TAPI_WAIT_NETWORK;
        if (!sockts_is_op_done(pco_iut))
        {
            /*
             * Waiting for connection timeout can make this test to
             * consume too much time, given number of its iterations.
             */
            ERROR_VERDICT("connect() was not unblocked by ICMP message");
            rpc_shutdown(pco_iut_aux, iut_s, RPC_SHUT_RDWR);
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rpc_connect(pco_iut, iut_s, tst_fake_addr);
            TEST_STOP;
        }
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_fake_addr);
    if (rc != -1)
        TEST_VERDICT("connect() call unexpectedly succeeded");
    if (blocking)
        CHECK_RC(check_rpc_errno(pco_iut, ret_errno, "connect()"));
    else
        CHECK_RC(check_rpc_errno(pco_iut, RPC_EINPROGRESS, "connect()"));

    TEST_STEP("Check how many packets were received from @p pco_iut by CSAP. "
              "We should wait here for SYN, because further checks are "
              "useless without getting it.");
    pkt_count = 0;
    while (pkt_count == 0 && (--wait_count) > 0)
    {
        TAPI_WAIT_NETWORK;
        tapi_tad_trrecv_get(pco_tst->ta, sid, csap,
                            NULL , &pkt_count);
    }
    if (pkt_count == 0)
        TEST_FAIL("connect() didn't send SYN.");

    TEST_STEP("Call @p iomux on IUT socket expecting @c EVT_RD. Check "
              "that it returns an event: @c EVT_RD in case of "
              "@b select() or @b pselect(); in case of other functions "
              "@c EVT_EXC | EVT_HUP (and also @c EVT_RD and @c EVT_ERR "
              "if @p blocking is @c FALSE).");

    event.fd = iut_s;
    event.events = EVT_RD;
    if (iomux == IC_SELECT || iomux == IC_PSELECT)
    {
        exp = EVT_RD;
    }
    else
    {
        exp = EVT_EXC | EVT_HUP;
        if (!blocking)
            exp |= EVT_RD | EVT_ERR;
    }

    IOMUX_CHECK_EXP(1, exp, event,
                    iomux_call(iomux, pco_iut, &event, 1, &timeout));

    TEST_STEP("Call @b recvmsg() on IUT socket with @c MSG_ERRQUEUE. "
              "Check that it fails with @c EAGAIN.");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
    if (rc >= 0)
        TEST_VERDICT("recvmsg() succeeded unexpectedly");

    if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
    {
        if (RPC_ERRNO(pco_iut) == ret_errno)
            RING_VERDICT("recvmsg() failed with ICMP errno");
        else
            RING_VERDICT("recvmsg() failed with unexpected errno %r",
                         RPC_ERRNO(pco_iut));
    }

    TEST_STEP("Check that SYN packets will not be retransmitted after receive "
              "of ICMP error.");
    tapi_tad_trrecv_get(pco_tst->ta, sid, csap,
                        NULL , &pkt_count);
    if (pkt_count > 0)
    {
        /* 1 SYN retransmit is acceptable. See ST-2300, ST-1156. */
        if (pkt_count == 1)
        {
            WARN("One SYN was retransmitted. It is acceptable.");
        }
        else
        {
            TEST_VERDICT("Connect function resends SYN before returning "
                         "error");
        }
    }

    TEST_STEP("Sleep some time and check that no more packets are captured "
              "by CSAP.");
    SLEEP(3);
    tapi_tad_trrecv_get(pco_tst->ta, sid, csap, NULL , &pkt_count);

    if (pkt_count != 0)
        TEST_VERDICT("Connect function resends SYN after returning error");

    TEST_STEP("Try to send data from IUT socket, check that it fails, "
              "returning @c EPIPE if @p blocking is @c TRUE or errno "
              "dependent on received ICMP message otherwise.");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, data_buf, DATA_BULK, 0);
    if (rc >= 0)
    {
        ERROR_VERDICT("Successful send() after failed connect()");
    }
    else
    {
        rc = check_rpc_errno(pco_iut, (blocking ? RPC_EPIPE : ret_errno),
                             "send()");
        if (rc != 0)
            test_failed = TRUE;
    }

    TEST_STEP("Try to receive data from IUT socket, check that it fails "
              "with errno @c ENOTCONN if @p blocking is @c TRUE or returns "
              "zero otherwise.");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, data_buf, DATA_BULK, 0);
    if (rc > 0)
    {
        TEST_VERDICT("Successful recv() after failed connect().");
    }
    else
    {
        if (blocking)
        {
            check_rpc_errno(pco_iut, RPC_ENOTCONN, "recv()");
        }
        else if (rc != 0)
        {
            TEST_VERDICT("recv() failed with errno %r",
                         RPC_ERRNO(pco_iut));
        }
    }

    TEST_STEP("Call @p iomux the second time on IUT socket. Check that "
              "it returns an event: @c EVT_RD in case of @b select() "
              "or @b pselect(); @c EVT_EXC | @c EVT_HUP (and also "
              "@c EVT_RD if @p blocking is @c FALSE) in case of other "
              "IOMUX functions.");

    if (iomux == IC_SELECT || iomux == IC_PSELECT)
    {
        exp = EVT_RD;
    }
    else
    {
        exp = EVT_EXC | EVT_HUP;
        if (!blocking)
            exp |= EVT_RD;
    }

    IOMUX_CHECK_EXP(1, exp, event,
                    iomux_call(iomux, pco_iut, &event, 1, &timeout));

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (pco_iut != NULL && iut_if != NULL)
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                                  tst_fake_addr));

    if (pco_tst != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    free(format_string);
    sockts_release_msghdr(&msg);

    if (pco_iut_aux != NULL)
        rcf_rpc_server_destroy(pco_iut_aux);

    TEST_END;
}
