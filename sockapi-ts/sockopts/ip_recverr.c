/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-ip_recverr Usage of IP_RECVERR linux-specific socket option
 *
 * @objective Check that @c IP_RECVERR socket option enables extended
 *            reliable error message passing and that it can be received
 *            with @b recvmsg() function.
 *
 * @type conformance
 *
 * @reference MAN 7 ip
 *
 * @param pco_iut           PCO on IUT
 * @param gw_addr           Network address of a host in the tested network 
 *                          that is able to forward incoming packets (router)
 * @param iomux             I/O multiplexing function type
 * @param select_err_queue  Set SO_SELECT_ERR_QUEUE socket option
 *
 * @par Test sequence:
 * -# Create @p pco_iut socket of type @c SOCK_DGRAM on @p pco_iut.
 * -# Create @p tx_buf of @p buf_len bytes.
 * -# Add route to some unicast address @p dst_addr using @p gw_addr 
 *    as a gateway.
 * -# Set @p new_ttl to @c 1.
 * -# Call @b setsockopt(@p pco_iut, @c SOL_IP, @c IP_TTL, @p &new_ttl,
 *                       @c sizeof(new_ttl)) - 
 *    TTL field of outgoing unicast packets is set to one.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt() on @p pco_iut socket with @c IP_RECVERR socket option.
 * -# Check that the function returns @c 0 and @a option_value parameter is 
 *    updated to @c 0 (by default this option should be disabled).
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Send @p tx_buf from @p pco_iut socket to @p dst_addr using @b sendto()
 *    function (this packet goes to the router according to the route and
 *    the router drops the packet sending ICMP Time Exceeded message 
 *    back to the sender, because the packet has TTL field equals to 1).
 * -# Check that @b sendto() returns @c 0.
 * -# Wait for a while for a couple of seconds (to make sure that ICMP
 *    message is processed).
 * -# Call @b recvmsg() with @a flags set to @c MSG_ERRQUEUE.
 * -# Check that the function returns @c -1 and sets @b errno to @c EAGAIN.
 *    See @ref sockopts_ip_recverr_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p pco_iut socket enabling @c IP_RECVERR socket
 *    option.
 * -# Call @b getsockopt() on @p pco_iut socket with @c IP_RECVERR socket option.
 * -# Check that the function returns @c 0 and @a option_value parameter is 
 *    updated to @c 1 (it is really updated).
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Send @p tx_buf from @p pco_iut socket to @p dst_addr using @b sendto()
 *    function (this packet goes to the router according to the route and
 *    the router drops the packet sending ICMP Time Exceeded message 
 *    back to the sender, because the packet has TTL field equals to 1).
 * -# Check that @b sendto() returns @c 0.
 * -# Wait for a while for a couple of seconds (to make sure that ICMP
 *    message is processed).
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Prepare @c msghdr structure as follows:
 *        - @a msg_name field should point to a buffer of an appropriate
 *          size to fit @c sockaddr structure of used address family;
 *        - @a msg_namelen field should be the size of @a msg_name buffer;
 *        - @a msg_iov field should point to scatter/gather array that
 *          consists of one buffer of size @p buf_len;
 *        - @a msg_iovlen field should be @c 1 (only one buffer in @a msg_iov);
 *        - @a msg_control field should point to a buffer big enough 
 *          to keep @c cmsghdr structure plus @c sock_extended_err
 *          structure;
 *        - @a msg_controllen should be the length of @a msg_control buffer;
 *        - @a msg_flags should be set to zero.
 *        .
 * -# Call @b recvmsg() on @p pco_iut socket passing prepared structure as the
 *    value of @a message parameter and @a flags set to @c MSG_ERRQUEUE.
 * -# Check that the function returns @p buf_len - number of bytes we sent
 *    before.
 * -# Check that @a msg_flags field of @c msghdr structure filled in with 
 *    @c MSG_ERRQUEUE.
 * -# Check that @a msg_iov scatter/gather array is filled in with @p tx_buf
 *    buffer (the payload of the packet that caused the error is passed as
 *    normal data).
 * -# Check that @a msg_name contains @p dst_addr value (the original 
 *    destination address of the datagram that caused the error is supplied
 *    via @a msg_name field).
 * -# Check that there is @c cmsghdr structure with @a cmsg_level equals to 
 *    @c IPPROTO_IP and @a cmsg_type set to @c IP_RECVERR.
 * -# Get data of corresponding @c cmsghdr structure with @b CMSG_DATA()
 *    macro - this is @c sock_extended_err structure.
 * -# Check the following fields of the structure:
 *        - @a ee_errno - @c EHOSTUNREACH;
 *        - @a ee_orig - @c SO_EE_ORIGIN_ICMP;
 *        - @a ee_type - @c ICMP_TIME_EXCEEDED (11);
 *        - @a ee_code - @c 0;
 *        - @a ee_pad - @c 0.
 *          \n @htmlonly &nbsp; @endhtmlonly
 *        .
 * -# Send @p tx_buf from @p pco_iut socket to @p gw_addr using port that is not
 *    being listened on the router (router sending ICMP Port Unreachable
 *    ICMP message back to the sender).
 * -# Check that @b sendto() returns @c 0.
 * -# Wait for a while for a couple of seconds (to make sure that ICMP
 *    message is processed).
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b recvmsg() on @p pco_iut socket passing prepared before structure as 
 *    the value of @a message parameter and @a flags set to @c MSG_ERRQUEUE.
 * -# Check that the function returns @p buf_len - number of bytes we sent
 *    before.
 * -# Check that @a msg_flags field of @c msghdr structure filled in with 
 *    @c MSG_ERRQUEUE.
 * -# Check that @a msg_iov scatter/gather array is filled in with @p tx_buf
 *    buffer (the payload of the packet that caused the error is passed as
 *    normal data).
 * -# Check that @a msg_name contains @p gw_addr value (the original 
 *    destination address of the datagram that caused the error is supplied
 *    via @a msg_name field).
 * -# Check that there is @c cmsghdr structure with @a cmsg_level equals to 
 *    @c IPPROTO_IP and @a cmsg_type set to @c IP_RECVERR.
 * -# Get data of corresponding @c cmsghdr structure with @b CMSG_DATA()
 *    macro - this is @c sock_extended_err structure.
 * -# Check the following fields of the structure:
 *        - @a ee_errno - @c ECONNREFUSED;
 *        - @a ee_orig - @c SO_EE_ORIGIN_ICMP;
 *        - @a ee_type - @c ICMP_DEST_UNREACH (3);
 *        - @a ee_code - @c ICMP_PORT_UNREACH (3);
 *        - @a ee_pad - @c 0.
 *          \n @htmlonly &nbsp; @endhtmlonly
 *        .
 * -# Delete @p tx_buf buffer.
 * -# Delete the route.
 * -# Close @p pco_iut socket.
 * 
 * @note
 * -# @anchor sockopts_ip_recverr_1
 *    As this option is a pure Linux socket option, the expected result is
 *    based on Linux behaviour;
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ip_recverr"

#include "sockapi-test.h"

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#include <linux/types.h>
#include <linux/errqueue.h>

#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "iomux.h"


#define TST_CMSG_LEN   300
#define TST_VEC        1


int
main(int argc, char *argv[])
{
    int                         sent = 0;
    int                         received = 0;
    tapi_env_host              *host_iut = NULL;
    rcf_rpc_server             *pco_gw = NULL;
    rcf_rpc_server             *pco_iut = NULL;
    int                         iut_s = -1;
    const struct sockaddr      *dst_addr;
    const struct sockaddr      *gw_addr;

    struct sockaddr_storage     msg_name;
    socklen_t                   msg_namelen = sizeof(struct sockaddr_storage);
    void                       *tx_buf = NULL;
    void                       *rx_buf = NULL;
    struct rpc_iovec            rx_vector;
    uint8_t                     cmsg_buf[TST_CMSG_LEN];
    rpc_msghdr                  rx_msghdr;
    struct cmsghdr             *cmsg;
    size_t                      tx_buf_len; /* buf_len */
    size_t                      rx_buf_len;
    struct sock_extended_err   *optptr;
    te_bool                     route_added = FALSE;
    rpc_socket_domain           domain;

    te_bool         select_err_queue;
    iomux_call_type iomux;
    iomux_evt_fd    event;
    tarpc_timeval   timeout = {.tv_sec = 0, .tv_usec = 0};
    int optval;
    int exp_ev;
    int exp_rc;

    TEST_START;
    TEST_GET_HOST(host_iut);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_ADDR(pco_iut, dst_addr);
    TEST_GET_ADDR(pco_gw, gw_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(select_err_queue);
    
    domain = rpc_socket_domain_by_addr(dst_addr);

    tx_buf = te_make_buf(1, 500, &tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

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

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);


    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));

    /* Add route on 'pco_iut': 'dst_addr' via gateway 'gw_addr' */
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(dst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw_addr)) != 0)
    {
        TEST_FAIL("Cannot add route");
    }
    route_added = TRUE;
    CFG_WAIT_CHANGES;

    rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_TTL, 1);

    rpc_getsockopt(pco_iut, iut_s, RPC_IP_RECVERR, &optval);
    if (optval != 0)
    {
        WARN("IP_RECVERR socket option default value %d, expected 0",
             optval);
        optval = 0;
        rpc_setsockopt(pco_iut, iut_s, RPC_IP_RECVERR, &optval);
    }

    RPC_SENDTO(sent, pco_iut, iut_s, tx_buf, tx_buf_len, 0, dst_addr);
    TAPI_WAIT_NETWORK;

    exp_ev = iomux_init_rd_error(&event, iut_s, iomux, select_err_queue,
                                 &exp_rc);
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

    memset(cmsg_buf, 0, TST_CMSG_LEN);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    received = rpc_recvmsg(pco_iut, iut_s, &rx_msghdr, RPC_MSG_ERRQUEUE);
    if (received != -1)
        TEST_FAIL("Unexpected recvmsg() return code %d, expected -1", received);
    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "recvmsg() called while empty buffer");

    rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_RECVERR, 1);
    if (select_err_queue)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SELECT_ERR_QUEUE, 1);

    RPC_SENDTO(sent, pco_iut, iut_s, tx_buf, tx_buf_len, 0, dst_addr);
    TAPI_WAIT_NETWORK;

    IOMUX_CHECK_EXP(exp_rc, exp_ev, event,
                    iomux_call(iomux, pco_iut, &event, 1, &timeout));

    rx_msghdr.msg_controllen = TST_CMSG_LEN;
    received = rpc_recvmsg(pco_iut, iut_s, &rx_msghdr, RPC_MSG_ERRQUEUE);
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

    if ((size_t)received != tx_buf_len)
        TEST_FAIL("Unexpected length of the returned data");
    if (memcmp(rx_buf, tx_buf, tx_buf_len))
        TEST_FAIL("Received data corrupted");

    if (te_sockaddrcmp(SA(&msg_name), rx_msghdr.msg_namelen,
                       dst_addr, te_sockaddr_get_size(dst_addr)) != 0)
    {
        VERB("Returned message name:%s is not the same as "
             "destination addr:%s ", te_sockaddr2str(SA(&msg_name)),
             te_sockaddr2str(dst_addr));
        TEST_FAIL("'msg_name' and 'dst_addr' are not the same");
    }

    sockts_check_msg_flags(&rx_msghdr, RPC_MSG_ERRQUEUE);
    /* Check returned ancillary data */
    cmsg = sockts_msg_lookup_control_data(&rx_msghdr, SOL_IP, IP_RECVERR);
    if (cmsg == NULL)
        TEST_FAIL("IP_RECVERR, ancillary data on rcv socket is not received");

    optptr = (struct sock_extended_err *) CMSG_DATA(cmsg);
    VERB("sock_extended_err - ee_errno:%d, ee_origin:%d, ee_type:%d, "
         "ee_code:%d, ee_pad:%d, ee_info:%d, ee_data:%d", optptr->ee_errno,
         optptr->ee_origin, optptr->ee_type, optptr->ee_code,
         optptr->ee_pad, optptr->ee_info, optptr->ee_data);

    if ((optptr->ee_errno != EHOSTUNREACH) ||
        (optptr->ee_origin != SO_EE_ORIGIN_ICMP) ||
        (optptr->ee_type != ICMP_TIME_EXCEEDED) ||
        (optptr->ee_code != 0) ||
        (optptr->ee_pad != 0))
        TEST_FAIL("Returned unexpected values of ancillary data");

    RPC_SENDTO(sent, pco_iut, iut_s, tx_buf, tx_buf_len, 0, gw_addr);
    TAPI_WAIT_NETWORK;

    IOMUX_CHECK_EXP(exp_rc, exp_ev, event,
                    iomux_call(iomux, pco_iut, &event, 1, &timeout));

    rx_msghdr.msg_controllen = TST_CMSG_LEN;
    received = rpc_recvmsg(pco_iut, iut_s, &rx_msghdr, RPC_MSG_ERRQUEUE);
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));

    if ((size_t)received != tx_buf_len)
    {
        VERB("(pco_gw) Unexpected length of the returned data: %d, "
             "expected %d", received, tx_buf_len);
        TEST_FAIL("(pco_gw) recvmsg() unexpected return value");
    }

    if (memcmp(rx_buf, tx_buf, tx_buf_len))
        TEST_FAIL("(pco_gw) Received data corrupted");

    if (te_sockaddrcmp(SA(&msg_name), rx_msghdr.msg_namelen, 
                       gw_addr, te_sockaddr_get_size(gw_addr)) != 0)
    {
        VERB("Returned message name:%s is not the same as pco_gw addr:%s ",
             te_sockaddr2str(SA(&msg_name)), te_sockaddr2str(gw_addr));
        TEST_FAIL("'msg_name' and 'gw_addr' are not the same");
    }

    sockts_check_msg_flags(&rx_msghdr, RPC_MSG_ERRQUEUE);
    /* Check returned ancillary data */
    cmsg = sockts_msg_lookup_control_data(&rx_msghdr, SOL_IP, IP_RECVERR);
    if (cmsg == NULL)
        TEST_FAIL("IP_RECVERR (pco_gw), ancillary data on rcv socket "
                  "is not received");

    optptr = (struct sock_extended_err *) CMSG_DATA(cmsg);
    VERB("(pco_gw) sock_extended_err - ee_errno:%d, ee_origin:%d, ee_type:%d, "
         "ee_code:%d, ee_pad:%d, ee_info:%d, ee_data:%d", optptr->ee_errno,
         optptr->ee_origin, optptr->ee_type, optptr->ee_code,
         optptr->ee_pad, optptr->ee_info, optptr->ee_data);

    if ((optptr->ee_errno != ECONNREFUSED) ||
        (optptr->ee_origin != SO_EE_ORIGIN_ICMP) ||
        (optptr->ee_type != ICMP_DEST_UNREACH) ||
        (optptr->ee_code != ICMP_PORT_UNREACH) ||
        (optptr->ee_pad != 0))
        TEST_FAIL("(pco_gw)Returned unexpected values of ancillary data");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (route_added)
        CLEANUP_CHECK_RC(tapi_cfg_del_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(dst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw_addr)));

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
