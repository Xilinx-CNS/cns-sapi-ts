/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-error_send_recv_icmp Reporting ICMP errors by send, receive and iomux functions
 *
 * @objective Check that send/receive or iomux function reports about pending
 *            errors received by incoming ICMP messages, and that
 *            the value of @c SO_ERROR socket option is reset to zero
 *            after reporting it with send/receive function.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param env           Testing environments:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_tst
 * @param icmp_type     The value of type field used in incoming ICMP message
 * @param icmp_code     The value of code field used in incoming ICMP message
 * @param ip_recverr    Try to set @c IP_RECVERR socket option or not
 * @param exp_errno     Expected errno value obtained with @c SO_ERROR socket
 *                      option
 * @param is_iomux      Whether iomux function should be called or not
 * @param iomux         Iomux function to be called (if @p is_iomux is
 *                      @c TRUE)
 * @param func          send/recv function to be called (if @p is_iomux is
 *                      @c FALSE)
 * @param pending_err   Whether ICMP error message should be received
 *                      before or after @p func call.
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/error_send_recv_icmp"

#include "sockapi-test.h"
#include "iomux.h"

#include <linux/types.h>
#include <linux/errqueue.h>

#include "tapi_tad.h"
#include "tapi_cfg.h"
#include "tapi_eth.h"
#include "tapi_icmp.h"
#include "icmp_send.h"

#include <netinet/ip_icmp.h> 
#include <netinet/icmp6.h>

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    int             iut_s = -1;
    int             tst_s = -1;

    rpc_errno          exp_errno;
    uint8_t            icmp_type;
    uint8_t            icmp_code;
    void              *func;
    te_bool            is_send = FALSE;
    te_bool            is_iomux = FALSE;
    te_bool            ip_recverr;
    te_bool            pending_err = FALSE;

    const struct if_nameindex *iut_if;
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *iut_lladdr;

    const struct if_nameindex *tst_if;
    const struct sockaddr     *tst_addr;
    const struct sockaddr     *tst_lladdr;

    int                    opt_val;

    csap_handle_t  tst_icmp_csap = CSAP_INVALID_HANDLE;
    asn_value     *icmp_pkt = NULL;
    int            ret;
    te_bool        op_done = FALSE;

#define BUF_SIZE 100
    unsigned char           buf[BUF_SIZE] = {};
    unsigned char           pkt_buf[BUF_SIZE] = {0, };

    iomux_call_type         iomux = IC_UNKNOWN;
    iomux_evt_fd            events;
    te_bool                 use_wildcard;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(icmp_type);
    TEST_GET_INT_PARAM(icmp_code);
    TEST_GET_ERRNO_PARAM(exp_errno);
    TEST_GET_BOOL_PARAM(is_iomux);
    if (is_iomux)
        TEST_GET_IOMUX_FUNC(iomux);
    else
        TEST_GET_FUNC(func, is_send);

    TEST_GET_BOOL_PARAM(ip_recverr);
    TEST_GET_BOOL_PARAM(pending_err);

    if (!pending_err && is_send)
        TEST_FAIL("Iteration trying to call send function before ICMP "
                  "message is received doesn't make any sense");

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
        TEST_FAIL("Cannot create Ethernet CSAP on TST Agent");
    }

    TEST_STEP("Create a connection of @c SOCK_DGRAM type between @b IUT and "
              "@b Tester.");

    /*
     * Bug 44608: Onload has different behaviour on UDP sockets bound to
     * INADDR_ANY and to TST address, even when sending/receiving to/from
     * TST only. So we should use wildcard addresses when it possible.
     */
    use_wildcard = FALSE;
    if (iut_addr->sa_family == AF_INET)
    {
        if ((!is_send || is_iomux) &&
            !(!ip_recverr && ((icmp_type == ICMP_DEST_UNREACH /* 3 */ &&
                                (icmp_code == ICMP_PROT_UNREACH /* 2 */ ||
                                 icmp_code == ICMP_PORT_UNREACH /* 3 */)) ||
                icmp_type == ICMP_PARAMETERPROB /* 12 */)))
        {
            use_wildcard = TRUE;
        }
    }
    else
    {

        if ((!is_send || is_iomux) &&
            !(!ip_recverr && ((icmp_type == ICMP6_DST_UNREACH /* 1 */ &&
                              icmp_code == ICMP6_DST_UNREACH_NOPORT /* 4 */) ||
                icmp_type == ICMP6_PARAM_PROB /* 4 */)))
        {
            use_wildcard = TRUE;
        }
    }

    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s,
                        use_wildcard);

    TEST_STEP("Enable @c IP_RECVERR socket option on @p iut_s if "
              "@p ip_recverr is @c TRUE.");
    if (ip_recverr)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        opt_val = 1;
        ret = rpc_setsockopt(pco_iut, iut_s, iut_addr->sa_family == AF_INET ?
                                             RPC_IP_RECVERR : RPC_IPV6_RECVERR,
                             &opt_val);
        if (ret != 0)
        {
            TEST_VERDICT("setsockopt(IP%s_RECVERR) failed with errno %r",
                         iut_addr->sa_family == AF_INET6 ? "V6" : "",
                         RPC_ERRNO(pco_iut));
        }
    }

    if (is_iomux)
    {
        events.fd = iut_s;
        events.events = EVT_RD;
        events.revents = 0;
    }

    TEST_STEP("If @p pending_err is @c FALSE, call the function defined by "
              "values of @p is_iomux, @p iomux and @p func with @c "
              "RCF_RPC_CALL on @p iut_s socket.");
    if (!pending_err)
    {
        pco_iut->op = RCF_RPC_CALL;
        if (!is_iomux)
        {
            ((rpc_recv_f)func)(pco_iut, iut_s, buf, sizeof(buf), 0);
        }
        else
        {
            iomux_call(iomux, pco_iut, &events, 1, NULL);
        }
    }

    TEST_STEP("Send ICMP message from @b Tester CSAP to @b IUT "
              "with speciefied @p icmp_type and @p icmp_code fields and "
              "containing as the payload IP datagram with UDP content that "
              "could be sent from @b IUT to @b Tester.");
    rc = tapi_icmp_error_msg_pdu((uint8_t *)tst_lladdr->sa_data,
                                 (uint8_t *)iut_lladdr->sa_data,
                                 tst_addr, iut_addr,
                                 icmp_type, icmp_code,
                                 iut_addr, tst_addr,
                                 IPPROTO_UDP, pkt_buf, 10,
                                 iut_addr->sa_family, &icmp_pkt);

    if (tapi_tad_trsend_start(pco_tst->ta, 0, tst_icmp_csap, icmp_pkt,
                              RCF_MODE_BLOCKING) != 0)
    {
        TEST_FAIL("Cannot send a frame from the CSAP");
    }

    TAPI_WAIT_NETWORK;

    if (pending_err || exp_errno == 0)
    {
        TEST_STEP("If @p pending_err is @c TRUE or @p exp_errno is zero send "
                  "one byte from @p Tester to @p IUT: we should have some data "
                  "in receive buffer to avoid hanging out on receive or iomux "
                  "operation.");
        if (!is_send)
        {
            /* Send just one byte */
            rpc_send(pco_tst, tst_s, buf, 1, 0);
        }
        TAPI_WAIT_NETWORK;
    }
    else
    {
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &op_done));
        if (!op_done)
        {
            TAPI_WAIT_NETWORK;
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &op_done));
            if (!op_done)
            {
                /* Unblock receive function sending just one byte */
                rpc_send(pco_tst, tst_s, buf, 1, 0);

                if (!is_iomux)
                    ((rpc_recv_f)func)(pco_iut, iut_s, buf, sizeof(buf), 0);
                else
                    iomux_call(iomux, pco_iut, &events, 1, NULL);

                TEST_VERDICT("ICMP error (%d,%d) does not unblock "
                             "%s function",
                             icmp_type, icmp_code,
                             is_iomux ? "iomux" : "receive");
            }
        }
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);

    TEST_STEP("If @p is_iomux is @c FALSE, call the function @p func on "
              "@p iut_s socket. Otherwise wait for completion of the function "
              "call made previously.");
    if (!is_iomux)
    {
        rc = is_send ? ((rpc_send_f)func)(pco_iut, iut_s,
                                          buf, sizeof(buf), 0)
                     : ((rpc_recv_f)func)(pco_iut, iut_s,
                                          buf, sizeof(buf), 0);
    }
    else
    {
        rc = iomux_call(iomux, pco_iut, &events, 1, NULL);
    }

    TEST_STEP("Check what returns the previously called function:");
    if (exp_errno == 0)
    {
        TEST_SUBSTEP("If @p exp_errno is @c 0: (1) check that function returns "
            "size of sending buffer if @p is_send is TRUE or returns @c 1 in "
            "case of (@p is_send is @c FALSE and @p is_iomux is @c FALSE) or "
            "(@p is_iomux is @c TRUE); (2) call @b getsockopt() on @p iut_s "
            "socket with @c SO_ERROR option and check that the function "
            "returns @c 0 and @a opt_val parameter is updated to @c 0;");
        if (rc == -1)
        {
            TEST_VERDICT("%s functon unexpectedly failed with errno %s",
                         is_iomux ? "Iomux" :
                         is_send ? "Send" : "Receive",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        if (is_send && rc != (int)sizeof(buf))
        {
            RING("Expected result %u, but returned %d", sizeof(buf), rc);
            TEST_VERDICT("Send functon returned strange value");
        }
        else if (!is_send && !is_iomux && rc != 1)
        {
            RING("Expected result 1, but returned %d", rc);
            TEST_VERDICT("Receive functon returned strange value");
        }
        else if (is_iomux && rc != 1)
        {
            RING("Expected result 1, but returned %d", rc);
            TEST_VERDICT("Iomux functon returned strange result");
        }

        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
        if (opt_val != 0)
        {
            TEST_VERDICT("SO_ERROR socket option has unexpected value "
                         "%s when ICMP error (%d,%d) was sent by peer",
                         errno_rpc2str(RPC_ERRNO(pco_iut)),
                         icmp_type, icmp_code);
        }

        TEST_SUCCESS;
    }
    else if (is_iomux)
    {
        TEST_SUBSTEP("If @p exp_errno is not @c 0 and @p is_iomux is @c TRUE: "
            "check that the function returned @c 1. If @p iomux is not @c "
            "IC_SELECT or @c IC_PSELECT, check that @c EVT_ERR is set for the "
            "socket; otherwise, check that @c EVT_RD is set for the socket;");
        if (rc != 1)
            TEST_VERDICT("Iomux function returned %d and errno %s",
                         rc, errno_rpc2str(RPC_ERRNO(pco_iut)));

        if (IOMUX_IS_POLL_LIKE(iomux))
        {
            if (!(events.revents & EVT_ERR))
                TEST_VERDICT("Iomux function didn't notice an error "
                             "on the socket");
            if (!pending_err && (events.revents & EVT_RD))
                TEST_VERDICT("Socket returns POLLIN event "
                             "when ICMP error is received");
        }
        else
        {
            if (!(events.revents & EVT_RD))
                TEST_VERDICT("select() or pselect() function didn't "
                             "report that the socket was readable "
                             "after ICMP message was received");

        }
    }
    else
    {
        TEST_SUBSTEP("If @p exp_errno is not @c 0 and @p is_iomux is @c FALSE: "
                     "check that the function failed reporting @p exp_errno.");
        if (is_send && rc == (int)sizeof(buf))
        {
            TEST_VERDICT("Send function returned success instead"
                         " of failure");
        }
        else if (!is_send && rc == 1)
        {
            TEST_VERDICT("Receive function returned success instead"
                         " of failure");
        }
        else if (rc != -1)
        {
            RING("Expected result -1, but returned %d", rc);
            TEST_VERDICT("%s function returned strange result",
                         is_send ? "Send" : "Receive");
        }

        CHECK_RPC_ERRNO(pco_iut, exp_errno,
                        "Tested function returned -1 when there is a "
                        "ICMP error (%d,%d) on the socket, but",
                        icmp_type, icmp_code);
    }

    TEST_STEP("Call @b getsockopt() on @p iut_s socket with @c SO_ERROR option "
              "and check that the function returns @c 0 and @a opt_value "
              "parameter is updated to @c 0 in case of non-iomux function "
              "(error was reported by @p func function), or is equal to @p "
              "exp_errno if @p is_iomux is @c TRUE.");
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);

    if (!is_iomux)
    {
        if (opt_val != 0)
        {
            TEST_VERDICT("SO_ERROR socket option is not reset to zero after "
                         "reporting the error in %s() function",
                         is_send ? rpc_send_func_name(func) :
                                   rpc_recv_func_name(func));
        }
    }
    else
    {
        if ((unsigned int)opt_val != exp_errno)
            TEST_VERDICT("SO_ERROR socket option is equal to %s "
                         "instead of %s when there is an ICMP "
                         "error (%d, %d) on the socket",
                         errno_rpc2str(opt_val),
                         errno_rpc2str(exp_errno),
                         icmp_type, icmp_code);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, tst_icmp_csap));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    asn_free_value(icmp_pkt);

    TEST_END;
}
