/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-error_errqueue Affecting error queue on SO_ERROR socket option
 *
 * @objective Check that the value of @c SO_ERROR socket option can be
 *            updated on retriving error message from error queue  
 *            containg incoming ICMP messages.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TST
 * @param icmp_msgs         The list of ICMP messages to send in format:
 *                          "type:XX1,code:YY1,errno:ERR1/
 *                          type:XX2,code:YY2,errno:ERR2/..."
 * @param set_msg_peek      Whether to test @c MSG_PEEK flag with
 *                          @c MSG_ERRQUEUE or not
 * @param iomux             I/O multiplexing function type
 * @param select_err_queue  Set SO_SELECT_ERR_QUEUE socket option
 * 
 * @par Test sequence:
 * -# Create a connection of type @c SOCK_DGRAM between two sockets
 *    @p iut_s and @p tst_s that reside on @p pco_iut and @p pco_tst
 *    correspondingly;
 * -# Call @b setsockopt() on @p iut_s socket with @c IP_RECVERR socket
 *    option  enabled (the option of @c SOL_IP level).
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Send a set of ICMP messages from @p tst_s to @p iut_s with 
 *    specified type and code fields and containing as the payload
 *    IPv4 datagram with UDP content that could be sent from @p iut_s
 *    to @p tst_s;
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_ERROR socket
 *    option;
 * -# Check that the function returns @c 0 and @a option_value parameter 
 *    is updated to @p exp_errno of the last ICMP message.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# For each ICMP message sent do the following:
 *    -# Call @b getsockopt() on @p iut_s socket with @c SO_ERROR socket
 *       option and Check that the function returns @c 0 and the option
 *       valie is @c 0;
 *    -# Call @b recvmsg() function on @p iut_s socket with @c MSG_ERRQUEUE
 *       flag (and with @c MSG_PEEK flag if @p set_msg_peek) -
 *       to extract a message from error queue;
 *    -# Check that @c msghdr data structure is correctly filled in:
 *       - @a msg_name field keeps address of @p tst_s socket - 
 *         the destination address of erroneous UDP packet included into
 *         ICMP message;
 *       - @a msg_flags field has @c MSG_ERRQUEUE flag set;
 *       - @a control_data keeps the valid information got from ICMP
 *         message (type, code, expected_errno);
 *         .
 *    -# If @p set_msg_peek, try to do previous steps once more for an ICMP
 *       message but without setting @p MSG_PEEK for @b recvmsg();
 *    -# If we have at least one message in error queue 
 *       (we haven't processed all the entries), then call @b getsockopt() 
 *       on @p iut_s socket with @c SO_ERROR socket option;
 *    -# Check that the function returns @c 0 and @a option_value
 *       parameter is updated to @p exp_errno of the first ICMP message
 *       placed in the queue;
 *    .
 * -# Call @b recvmsg() function on @p iut_s socket with @c MSG_ERRQUEUE 
 *    flag - to extract a message from error queue;
 * -# Check that the function returns @c -1 and sets @b errno to @c EAGAIN;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s and @p tst_s sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/error_errqueue"

#include "sockapi-test.h"

#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_cfg.h"
#include "tapi_icmp4.h"
#include "icmp_send.h"
#include "parse_icmp.h"
#include "iomux.h"

#define ICMP_MSGS_MAX_NUM 10

#define TST_CMSG_LEN   300
#define TST_VEC        1

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    int             iut_s = -1;
    int             tst_s = -1;
    
    const char           *icmp_msgs;
    struct test_icmp_msg  icmp_msgs_arr[ICMP_MSGS_MAX_NUM];
    
    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *iut_lladdr = NULL;

    const struct if_nameindex   *tst_if = NULL;
    const struct sockaddr       *tst_addr = NULL;
    const struct sockaddr       *tst_lladdr = NULL;

    int                    opt_val;

    struct sockaddr_storage     msg_name;
    socklen_t                   msg_namelen = sizeof(struct sockaddr_storage);

    uint8_t                     rx_buf[100];
    size_t                      rx_buf_len = sizeof(rx_buf);
    struct rpc_iovec            rx_vector;
    uint8_t                     cmsg_buf[TST_CMSG_LEN];
    rpc_msghdr                  rx_msghdr;
    struct cmsghdr             *cmsg;
    struct sock_extended_err   *optptr;

    csap_handle_t  tst_icmp_csap = CSAP_INVALID_HANDLE;
    asn_value     *icmp_pkt = NULL;
    const char    *err_str;

#define BUF_SIZE    100    
    unsigned char   pkt_buf[BUF_SIZE] = {0, };

    te_bool         set_msg_peek = FALSE;

    iomux_call_type         iomux;
    iomux_evt_fd            event;
    te_bool                 select_err_queue;
    tarpc_timeval           timeout = {.tv_sec = 0, .tv_usec = 0};

    int icmp_msg_cnt = 0;
    int received;
    int exp_ev;
    int exp_rc;
    int i;
    int j;

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
    TEST_GET_BOOL_PARAM(set_msg_peek);
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
    rx_msghdr.msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;

    if (parse_icmp_msgs_param_with_errno(icmp_msgs, icmp_msgs_arr,
                                         ICMP_MSGS_MAX_NUM,
                                        &icmp_msg_cnt, &err_str) != 0)
        TEST_FAIL("%s", err_str);

    if (!set_msg_peek && icmp_msg_cnt < 2)
        TEST_FAIL("At least two ICMP messages should be specified");
    else if (set_msg_peek && icmp_msg_cnt != 1)
        TEST_FAIL("To test MSG_ERRQUEUE | MSG_PEEK, exactly one ICMP "
                  "message should be specified");

    CHECK_RC(tapi_udp_ip4_icmp_ip4_eth_csap_create(pco_tst->ta, 0,
             tst_if->if_name, TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
             (uint8_t *)tst_lladdr->sa_data,
             (uint8_t *)iut_lladdr->sa_data,
             *(in_addr_t *)&(SIN(tst_addr)->sin_addr),
             *(in_addr_t *)&(SIN(iut_addr)->sin_addr),
             *(in_addr_t *)&(SIN(iut_addr)->sin_addr),
             *(in_addr_t *)&(SIN(tst_addr)->sin_addr),
             SIN(iut_addr)->sin_port, SIN(tst_addr)->sin_port,
             &tst_icmp_csap));

    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);
   
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s, RPC_IP_RECVERR, &opt_val);

    exp_ev = iomux_init_rd_error(&event, iut_s, iomux, select_err_queue,
                                 &exp_rc);
    if (select_err_queue)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SELECT_ERR_QUEUE, 1);

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
                                      IPPROTO_UDP,
                                      SIN(iut_addr)->sin_port,
                                      SIN(tst_addr)->sin_port,
                                      pkt_buf, 10,
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

    IOMUX_CHECK_EXP(exp_rc, exp_ev, event,
                    iomux_call(iomux, pco_iut, &event, 1, &timeout));

    /* 
     * Get the value of SO_ERROR socket option,
     * The value should be the errno mapped from the last ICMP message 
     */
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if ((rpc_errno)opt_val != icmp_msgs_arr[icmp_msg_cnt - 1].map_errno)
    {
        TEST_FAIL("After receiving the sequence of ICMP messages %s "
                  "SO_ERROR option is set to %s, but it is expected "
                  "to be %s", icmp_msgs,
                  errno_rpc2str(opt_val),
                  errno_rpc2str(icmp_msgs_arr[icmp_msg_cnt - 1].map_errno));
    }

    for (i = 0; i <= icmp_msg_cnt; i++)
    {
        /* Check that SO_ERROR is reset to zero */
        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
        if (opt_val != 0)
            TEST_FAIL("SO_ERROR socket option is not reset to zero after "
                      "it is got");

        /* No more messages left in error queue */
        if (i == icmp_msg_cnt)
            break;
 
        for (j = 0; j < (set_msg_peek ? 2 : 1); j++)
        {
            event.revents = 0;
            rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);

            if (!set_msg_peek || j == 0)
            {
                if ((iomux == IC_SELECT || iomux == IC_PSELECT) && select_err_queue)
                {
                     if (rc != 2)
                        TEST_VERDICT("Select function returnd unexpected value");
                }
                else if (rc != 1)
                    ERROR_VERDICT("Iomux function returned unexpected value");
                else if (event.revents != exp_ev)
                    ERROR_VERDICT("Iomux function returned unexpected events");
            }
            else if (rc != 0)
                ERROR_VERDICT("Iomux function returned unexpected value");

            /*
             * Restore msg_controllen - previous recvmsg() call could have
             * changed it.
             */
            rx_msghdr.msg_controllen = TST_CMSG_LEN;

            RPC_AWAIT_IUT_ERROR(pco_iut);
            received = rpc_recvmsg(
                        pco_iut, iut_s, &rx_msghdr,
                        RPC_MSG_ERRQUEUE |
                            (set_msg_peek && j == 0 ? RPC_MSG_PEEK : 0));
            if (received < 0)
            {
                if (j == 0)
                    TEST_VERDICT("Failed to get %d error message, errno %s",
                                 i + 1, errno_rpc2str(RPC_ERRNO(pco_iut)));
                /* MSG_PEEK does not work with MSG_ERRQUEUE */
                else if (RPC_ERRNO(pco_iut) == RPC_EAGAIN)
                    continue;
                else
                    TEST_VERDICT("The second recvmsg() call after "
                                 "attempt to use MSG_PEEK failed with "
                                 "errno %s",
                                 errno_rpc2str(RPC_ERRNO(pco_iut)));
            }

            if (te_sockaddrcmp(SA(&msg_name), rx_msghdr.msg_namelen,
                               tst_addr, te_sockaddr_get_size(tst_addr)) != 0)
            {
                VERB("Returned message name:%s is not the same as "
                     "destination addr:%s reside in ICMP message payload",
                     te_sockaddr2str(SA(&msg_name)), te_sockaddr2str(tst_addr));
                TEST_FAIL("'msg_name' and 'tst_addr' are not the same");
            }

            sockts_check_msg_flags(&rx_msghdr, RPC_MSG_ERRQUEUE);

            /* Check returned ancillary data */
            cmsg = sockts_msg_lookup_control_data(&rx_msghdr, SOL_IP, IP_RECVERR);
            if (cmsg == NULL)
                TEST_FAIL("IP_RECVERR, ancillary data on pco_iut socket "
                          "is not received");
            
            optptr = (struct sock_extended_err *) CMSG_DATA(cmsg);
            sockts_print_sock_extended_err(optptr);
            sockts_check_icmp_errno(icmp_msgs_arr + i, optptr);
        }

        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
        if (i < (icmp_msg_cnt - 1))
        {
            /* 
             * There is at least one entry in ICMP error queue,
             * so the previous get from error queue update the value of 
             * SO_ERROR socket option to the error of this entry.
             */
            if ((rpc_errno)opt_val != icmp_msgs_arr[i + 1].map_errno)
                ERROR_VERDICT("After extracting ICMP error message (number %d) "
                          "from error queue SO_ERROR socket option is set "
                          "to %s, but it is expected to be %s", i + 1,
                          errno_rpc2str(opt_val), 
                          errno_rpc2str(icmp_msgs_arr[i + 1].map_errno));

            rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
            if ((rpc_errno)opt_val != 0)
                ERROR_VERDICT("SO_ERROR is not cleared by getsockopt");
        }
        else if (opt_val != 0)
            ERROR_VERDICT("SO_ERROR is not cleared when all errors received");
    }

    /* Check that error queue is empty */
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));
    rx_msghdr.msg_controllen = TST_CMSG_LEN;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    received = rpc_recvmsg(pco_iut, iut_s, &rx_msghdr, RPC_MSG_ERRQUEUE);
    if (received != -1)
        ERROR_VERDICT("recvmsg(iut_s, &rx_msghdr, RPC_MSG_ERRQUEUE) return %d, "
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
