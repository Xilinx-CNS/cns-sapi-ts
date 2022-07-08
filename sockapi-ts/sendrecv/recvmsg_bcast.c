/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-recvmsg_bcast MSG_BCAST flag is returned by recvmsg()
 *
 * @objective Check that @b recvmsg() returns @c MSG_BCAST flag when
 *            datagram socket receives broadcast message.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.5
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Datagram socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Datagram socket on @p pco_tst
 *
 * @pre @p iut_s socket is bound to wildcard address and fixed port.
 *
 * -# Permit sending of broadcast messages from @p tst_s using
 *    @c SO_BROADCAST socket option.
 * -# Send broadcast message to @p tst_s socket with destination
 *    port equal to @p iut_s bound to.
 * -# Receive data from @p iut_s socket using @b recvmsg() function.
 *    @c MSG_BCAST must be set in @e msg_flags field of the received
 *    message.  Message source address, data and ancillary data fields
 *    must be correctly filled in.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recvmsg_bcast"

#include "sockapi-test.h"

#define TST_BUFLEN   512  


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;

    const struct sockaddr   *bcast_addr;
    socklen_t                bcast_addrlen;
    const struct sockaddr   *tst_addr;
    struct sockaddr_storage  iut_wildcard_addr;
    rpc_msghdr              *tx_msg = NULL;
    rpc_msghdr              *rx_msg = NULL; 
    ssize_t                  buflen = TST_BUFLEN;
    int                      opt_val = 1;
    int                      sentl;
    int                      recvl;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, bcast_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    bcast_addrlen = te_sockaddr_get_size(bcast_addr);
    
    tx_msg = sockts_make_msghdr(bcast_addrlen, -1, &buflen, 0);
    CHECK_NOT_NULL(tx_msg);
    rx_msg = sockts_make_msghdr(bcast_addrlen, -1, &buflen, 0);
    CHECK_NOT_NULL(rx_msg);
    rx_msg->msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;

    memcpy(tx_msg->msg_name, bcast_addr, bcast_addrlen);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    memcpy(&iut_wildcard_addr, bcast_addr, bcast_addrlen);
    te_sockaddr_set_wildcard(SA(&iut_wildcard_addr));
    rpc_bind(pco_iut, iut_s, SA(&iut_wildcard_addr));
    
    rpc_bind(pco_tst, tst_s, tst_addr);
    
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_BROADCAST, &opt_val);

    sentl = rpc_sendmsg(pco_tst, tst_s, tx_msg, 0);
    
    recvl = rpc_recvmsg(pco_iut, iut_s, rx_msg, 0);
    
    if (sockts_compare_txrx_msgdata(tx_msg, rx_msg, tst_addr,
                                    sentl, recvl) == 0)
    {  
         TEST_FAIL("Address or data fields incorrectly filled in");
    }

    sockts_check_msg_flags(rx_msg, RPC_MSG_BCAST);
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_free_msghdr(tx_msg);
    sockts_free_msghdr(rx_msg);

    TEST_END;
}
 
