/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-recvmsg_mcast MSG_MCAST flag is returned by recvmsg()
 *
 * @objective Check that @b recvmsg() returns @c MSG_MCAST flag when
 *            datagram socket receives multicast message.
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
 * -# Join @p iut_s socket to @p test multicast group using 
 *    @c IP_ADD_MEMBERSHIP socket option.
 * -# Send multicast message to @p tst_s socket with destination
 *    port equal to @p iut_s bound to and destination address of the
 *    joined multicast group.
 * -# Receive data from @p iut_s socket using @b recvmsg() function.
 *    @c MSG_MCAST must be set in @e msg_flags field of the received
 *    message.  Message source address, data and ancillary data fields 
 *    must be correctly filled in.
 * -# Leave @p test multi group using @c IP_DROP_MEMBERSHIP socket
 *    option.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recvmsg_mcast"

#include "sockapi-test.h"

#define TST_BUFLEN   512  


int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;
    rcf_rpc_server  *pco_tst = NULL;
    int              iut_s = -1;
    int              tst_s = -1;
    int              sentl;
    int              recvl;  
    rpc_sockopt      add_membeship_opt_name = RPC_IP_ADD_MEMBERSHIP;
    rpc_sockopt      drop_membeship_opt_name = RPC_IP_DROP_MEMBERSHIP;
    
    const struct sockaddr   *mcast_addr;
    socklen_t                mcast_addrlen;
    const struct sockaddr   *iut_addr;
    const struct sockaddr   *tst_addr;
    struct sockaddr_storage  iut_wildcard_addr;
    socklen_t                iut_wildcard_addrlen;
    rpc_msghdr              *tx_msg = NULL;
    rpc_msghdr              *rx_msg = NULL; 
    ssize_t                  buflen = TST_BUFLEN;
    struct ip_mreqn          opt_val;
    socklen_t                opt_len = sizeof(opt_val);

    rpc_socket_domain domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);    
    TEST_GET_ADDR_NO_PORT(mcast_addr);
    
    domain = rpc_socket_domain_by_addr(iut_addr);
    
    memset(&opt_val, 0, opt_len);
    te_mreq_set_mr_multiaddr(addr_family_rpc2h(sockts_domain2family(domain)), 
                             &opt_val, te_sockaddr_get_netaddr(mcast_addr)); 
    te_mreq_set_mr_interface(addr_family_rpc2h(sockts_domain2family(domain)), 
                             &opt_val, te_sockaddr_get_netaddr(iut_addr)); 

    mcast_addrlen = te_sockaddr_get_size(mcast_addr);
    
    tx_msg = sockts_make_msghdr(mcast_addrlen, -1, &buflen, 0);
    CHECK_NOT_NULL(tx_msg);
    rx_msg = sockts_make_msghdr(mcast_addrlen, -1, &buflen, 0);
    CHECK_NOT_NULL(rx_msg);
    rx_msg->msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;

    memcpy(tx_msg->msg_name, mcast_addr, mcast_addrlen);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    
    iut_wildcard_addrlen = mcast_addrlen;
    memcpy(&iut_wildcard_addr, mcast_addr, iut_wildcard_addrlen);
    te_sockaddr_set_wildcard(SA(&iut_wildcard_addr));
    rpc_bind(pco_iut, iut_s, SA(&iut_wildcard_addr));
    
    rpc_bind(pco_tst, tst_s, tst_addr);
    
    rpc_setsockopt(pco_iut, iut_s, add_membeship_opt_name, &opt_val);

    sentl = rpc_sendmsg(pco_tst, tst_s, tx_msg, 0);
    
    recvl = rpc_recvmsg(pco_iut, iut_s, rx_msg, 0);
    
    if (sockts_compare_txrx_msgdata(tx_msg, rx_msg, tst_addr,
                                    sentl, recvl) == 0)
    {  
         TEST_FAIL("Address or data fields incorrectly filled in");
    }

    sockts_check_msg_flags(rx_msg, RPC_MSG_MCAST);
    rpc_setsockopt(pco_iut, iut_s, drop_membeship_opt_name, &opt_val);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_free_msghdr(tx_msg);
    sockts_free_msghdr(rx_msg);

    TEST_END;
}
 
