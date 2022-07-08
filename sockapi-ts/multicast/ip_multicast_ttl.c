/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page multicast-ip_multicast_ttl Usage of IP_MULTICAST_TTL socket option and IP_RECVTTL socket option for multicast packets
 *
 * @objective Check that @c IP_MULTICAST_TTL socket option can be used to 
 *            change TTL value of IP header in all multicast packets 
 *            originated from the socket. Check that IP_RECVTTL works
 *            correctly for multicast packets.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 19.5
 *
 * @param pco_snd           PCO on sender (it can be IUT or TESTER)
 * @param pco_rcv           PCO on receiver (it can be IUT or TESTER)
 * @param use_route         Specify interface for outgoing multicast datagrams
 *                          by a route instead of using IP_MULTICAST_IF option.
 * @param packet_number     Number of datagrams to send for reliability.
 * @param connect           Connect @p iut_s and use @b send() instead of @b sendto().
 *
 * @note This test should be performed twice with the following values of
 * the parameters:
 * -# Test IP_MULTICAST_TTL:
 *     - @p pco_snd - PCO on IUT
 *     - @p pco_rcv - PCO on TESTER
 *     .
 * -# Test IP_RECVTTL:
 *     - @p pco_snd - PCO on TESTER
 *     - @p pco_rcv - PCO on IUT
 *     .
 *
 * @par Test sequence:
 * -# Create datagram sockets: @p snd on @p pco_snd and @p rcv on @p pco_rcv.
 * -# @b bind() @p rcv socket to wildcard IP address.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Get default value of @c IP_TTL option on @p snd socket to variable
 *    @p ttl_val, and log it.
 * -# Try to change the value of @c IP_MULTICAST_TTL option:
 *     -# Check that initial value of the  @c IP_MULTICAST_TTL option on
 *        @p snd socket equals to @c IP_DEFAULT_MULTICAST_TTL.
 *     -# Enable @c IP_RECVTTL socket option on @p rcv socket.
 *        \n @htmlonly &nbsp; @endhtmlonly
 *     -# Set on @p snd socket @c IP_MULTICAST_TTL option value equal to
 *        @p multicast_ttl_val (choose @p multicast_ttl_val different from
 *        @c IP_DEFAULT_MULTICAST_TTL.
 *     -# Check by calling @b getsockopt(), that value of the option is
 *        the same as was set.
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# Try to change the value of @c IP_TTL option: 
 *     -# Set a new @c IP_TTL value equal to @p new_ttl for @p snd socket.
 *     -# Check that its value is the same as was set.
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# Check that multicast datagrams sent from @p snd socket and destined
 *    to the all-hosts group have a proper TTL:
 *     -# Send some data from @p snd socket towards @p rcv socket using
 *        all-hosts multicast IP address 224.0.0.1 as destination.
 *     -# Call @b recvmsg() on @p rcv socket passing enough room to 
 *        @a msg_control field of @c msghdr structure.
 *     -# Check that there is @c cmsghdr structure with @a cmsg_level equals
 *        to @c IPPROTO_IP and @a cmsg_type set to @c IP_TTL or @c IP_RECVTTL.
 *     -# Check that the value obtained from @c cmsghdr structure equals to
 *        @p multicast_ttl_val.
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# Check that unicast datagrams sent from @p snd socket have proper TTL:
 *     -# Send some data from @p snd socket towards @p rcv socket using
 *        one of unicast IP addresses assigned to an interface on the host
 *        where @p pco_rcv resides.
 *     -# Call @b recvmsg() on @p rcv socket passing enough room to
 *        @a msg_control field of @c msghdr structure.
 *     -# Check that there is @c cmsghdr structure with @a cmsg_level equals
 *        to @c IPPROTO_IP and @a cmsg_type set to @c IP_TTL or @c IP_RECVTTL.
 *     -# Check that the value obtained from @c cmsghdr structure equals to
 *        @p new_ttl.
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# If IUT accepts optlen > 1 for tested options,
 *    check that attempt to set @c IP_MULTICAST_TTL = 256 fails and does not
 *    change the option value:
 *     -# Call @b setsockopt() on @p snd socket with @c IP_MULTICAST_TTL
 *        socket option and @a option_value parameter equals to @c 256.
 *     -# Check that the function returns @c -1 and sets @b errno
*         to @c EINVAL.
 *     -# Call @b getsockopt() on @p snd socket with @c IP_MULTICAST_TTL
 *        socket option and check that its value equals to
 *        @p multicast_ttl_val.
 * -# Call @b setsockopt() on @p snd socket with @c IP_MULTICAST_TTL
 *        socket option and @a option_value parameter equals to @c -1.
 * -# Report the result of the function:
 *        - If the function returns @c -1 report value of @b errno;
 *        - Otherwise, function returns @c 0.
 *          See @ref sockopts_ip_multicast_ttl_2 "note 2". In this case call 
 *          @b getsockopt() on @p snd socket with @c IP_MULTICAST_TTL 
 *          socket option and check that its value the same as 
 *          @p ttl_multicast_init.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p rcv and @p snd sockets.
 * 
 * @note
 * -# @anchor sockopts_ip_multicast_ttl_1
 *    Some implementations can use @c IP_RECVTTL as the value of @a cmsg_type
 *    field of @c cmsghdr structure, so that it is better to check @a
 *    cmsg_type field of each structure again @c IP_TTL and @c IP_RECVTTL
 *    values and report actual value.
 * -# @anchor sockopts_ip_multicast_ttl_2
 *    On Linux @c -1 as the value of @c IP_MULTICAST_TTL option means set it 
 *    to the default value.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/ip_multicast_ttl"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "multicast.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#else
#define IP_DEFAULT_MULTICAST_TTL 1
#endif

#define TST_VEC        1
#define TST_CMSG_LEN   300

/**
 * Check received TTL value.
 *
 * @param pco           PCO to receive data
 * @param s             socket to receive data
 * @param buf           buffer to receive
 * @param buf_len       length of buffer
 * @param expected_ttl  expected TTL value
 *
 * The function jumps on error or TTL value mismatch, returning void.
 */
void
check_ttl(rcf_rpc_server *pco, int s, void *buf, int buf_len, int expected_ttl)
{
    rpc_msghdr          rx_msghdr;
    uint8_t             cmsg_buf[TST_CMSG_LEN];
    struct rpc_iovec    rx_vector;
    struct cmsghdr     *cmsg = NULL;
    int                *optptr = NULL;

    rx_vector.iov_base = buf;
    rx_vector.iov_len = rx_vector.iov_rlen = buf_len;

    memset(&rx_msghdr, 0, sizeof(rx_msghdr));
    rx_msghdr.msg_iovlen = rx_msghdr.msg_riovlen = TST_VEC;
    rx_msghdr.msg_iov = &rx_vector;
    rx_msghdr.msg_control = cmsg_buf;
    rx_msghdr.msg_controllen = TST_CMSG_LEN;
    rx_msghdr.msg_cmsghdr_num = 1;

    memset(cmsg_buf, 0, TST_CMSG_LEN);
    if (rpc_recvmsg(pco, s, &rx_msghdr, 0) != buf_len)
        TEST_FAIL("Unexpected length of the received datagram.");

    cmsg = sockts_msg_lookup_control_data(&rx_msghdr, SOL_IP, IP_TTL);
    if (cmsg == NULL)
        cmsg = sockts_msg_lookup_control_data(&rx_msghdr, SOL_IP, IP_RECVTTL);

    if (cmsg == NULL)
        TEST_VERDICT("IP_TTL option, ancillary data on rcv socket "
                     "is not received");

    optptr = (int *) CMSG_DATA(cmsg);
    if (*optptr != expected_ttl)
        TEST_FAIL("Returned unexpected TTL value:%d, "
                  "expected:%d ", *optptr, expected_ttl);
}

int
main(int argc, char *argv[])
{
    int             sent = 0;
    rcf_rpc_server *pco_snd = NULL;
    rcf_rpc_server *pco_rcv = NULL;
    int             snd = -1;
    int             rcv = -1;

    struct sockaddr_storage     wild_addr;
    const struct sockaddr      *mult_addr;

    const struct if_nameindex  *rcv_if;
    const struct sockaddr      *rcv_addr = NULL;

    const struct if_nameindex  *snd_if;
    const struct sockaddr      *snd_addr;

    void                       *tx_buf = NULL;
    void                       *rx_buf = NULL;
    size_t                      buf_len;

    int                         multicast_ttl_init;
    int                         multicast_ttl_val;
    int                         ttl_val;
    int                         optval;
    te_bool                     use_route;
    te_bool                     connect;
    cfg_handle                  route_handle1 = CFG_HANDLE_INVALID;
    cfg_handle                  route_handle2 = CFG_HANDLE_INVALID;
    int                         i;
    int                         af;
    int                         route_prefix;
    int                         packet_number;
    tarpc_joining_method        method;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_snd);
    TEST_GET_PCO(pco_rcv);
    TEST_GET_ADDR(pco_rcv, rcv_addr);
    TEST_GET_ADDR(pco_snd, snd_addr);
    TEST_GET_ADDR_NO_PORT(mult_addr);
    TEST_GET_IF(rcv_if);
    TEST_GET_IF(snd_if);
    TEST_GET_BOOL_PARAM(use_route);
    TEST_GET_BOOL_PARAM(connect);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);

    
    SIN(mult_addr)->sin_port = SIN(rcv_addr)->sin_port;

    VERB("Test params: rcv_addr:%s", te_sockaddr2str(rcv_addr));

    tx_buf = sockts_make_buf_dgram(&buf_len);
    rx_buf = te_make_buf_by_len(buf_len);

    snd = rpc_socket(pco_snd, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rcv = rpc_socket(pco_rcv, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    memcpy(&wild_addr, mult_addr, te_sockaddr_get_size(mult_addr));
    te_sockaddr_set_wildcard(SA(&wild_addr));

    rpc_bind(pco_rcv, rcv, SA(&wild_addr));

    ttl_val = 0;
    rpc_getsockopt(pco_snd, snd, RPC_IP_TTL, &ttl_val);
    rpc_getsockopt(pco_snd, snd, RPC_IP_MULTICAST_TTL, &multicast_ttl_val);

    if (multicast_ttl_val != IP_DEFAULT_MULTICAST_TTL)
        TEST_FAIL("Default multicast TTL is %d instead of %d",
                  multicast_ttl_val, IP_DEFAULT_MULTICAST_TTL);

    multicast_ttl_init = multicast_ttl_val;

    rpc_setsockopt_int(pco_rcv, rcv, RPC_IP_RECVTTL, 1);

    /* Change TTL values */
    ttl_val = ((ttl_val + 6) < 256)? ttl_val + 6: ttl_val - 6;
    multicast_ttl_val = ((multicast_ttl_val + 3) < 256)?
                        multicast_ttl_val + 3: multicast_ttl_val - 3;

    rpc_setsockopt_check_int(pco_snd, snd, RPC_IP_MULTICAST_TTL,
                             multicast_ttl_val);
    rpc_setsockopt_check_int(pco_snd, snd, RPC_IP_TTL, ttl_val);

    rpc_mcast_join(pco_rcv, rcv, mult_addr, rcv_if->if_index, method);

    /* Set default multicasting interfaces on pco_snd and pco_rcv */
    if (use_route)
    {
        af = AF_INET;
        route_prefix = te_netaddr_get_size(af) * 8;

        CHECK_RC(tapi_cfg_add_route(pco_rcv->ta, af,
            te_sockaddr_get_netaddr(mult_addr), route_prefix,
            te_sockaddr_get_netaddr(rcv_addr), NULL, 0, 0, 0, 0, 0, 0, 0,
            &route_handle2));

        CHECK_RC(tapi_cfg_add_route(pco_snd->ta, af,
            te_sockaddr_get_netaddr(mult_addr), route_prefix,
            te_sockaddr_get_netaddr(snd_addr), NULL, NULL, 0, 0, 0, 0, 0, 0,
            &route_handle1));
    }
    else
    {
        struct tarpc_mreqn mreq;
        
        memset(&mreq, 0, sizeof(mreq));
        mreq.type = OPT_IPADDR;
        memcpy(&mreq.address, te_sockaddr_get_netaddr(snd_addr),
               sizeof(struct in_addr));
        rpc_setsockopt(pco_snd, snd, RPC_IP_MULTICAST_IF, &mreq);
        rpc_bind(pco_snd, snd, snd_addr);

        memcpy(&mreq.address, te_sockaddr_get_netaddr(rcv_addr),
               sizeof(struct in_addr));
        rpc_setsockopt(pco_rcv, rcv, RPC_IP_MULTICAST_IF, &mreq);
    }

    TAPI_WAIT_NETWORK;

    if (connect)
        rpc_connect(pco_snd, snd, mult_addr);

    for (i = 0; i < packet_number; i++)
    {
        if (connect)
            RPC_SEND(sent, pco_snd, snd, tx_buf, buf_len, 0);
        else
            RPC_SENDTO(sent, pco_snd, snd, tx_buf, buf_len, 0, mult_addr);
        check_ttl(pco_rcv, rcv, rx_buf, buf_len, multicast_ttl_val);
    }

    if (connect)
        rpc_connect(pco_snd, snd, rcv_addr);

    for (i = 0; i < packet_number; i++)
    {
        if (connect)
            RPC_SEND(sent, pco_snd, snd, tx_buf, buf_len, 0);
        else
            RPC_SENDTO(sent, pco_snd, snd, tx_buf, buf_len, 0, rcv_addr);
        check_ttl(pco_rcv, rcv, rx_buf, buf_len, ttl_val);
    }

    RPC_AWAIT_IUT_ERROR(pco_snd);
    rc = rpc_setsockopt_int(pco_snd, snd, RPC_IP_MULTICAST_TTL, 256);
    if (rc != -1)
        TEST_FAIL("rpc_setsockopt() unexpected behaviour, expected "
                  "return code -1");
    CHECK_RPC_ERRNO(pco_snd, RPC_EINVAL,
                    "While setting socket IP_MULTICAST_TTL"
                    " option to 256 setsockopt() on 'snd' "
                    " socket returns -1, but");

    optval = 0;
    rpc_getsockopt(pco_snd, snd, RPC_IP_MULTICAST_TTL, &optval);
    if (optval != multicast_ttl_val)
        TEST_FAIL("Returned multicast TTL(256) value failure; "
                  "expected:%d, returned:%d", multicast_ttl_val, optval);

    RPC_AWAIT_IUT_ERROR(pco_snd);
    rc = rpc_setsockopt_int(pco_snd, snd, RPC_IP_MULTICAST_TTL, -1);
    if (rc == 0)
    {
        optval = 0;
        rpc_getsockopt(pco_snd, snd, RPC_IP_MULTICAST_TTL, &optval);

        if (optval != multicast_ttl_init)
        {
            if (optval == 0xff)
                RING("IP_MULTICAST_TTL has been successfully set to 255");
            else
                TEST_FAIL("Returned multicast TTL(-1) value failure; "
                           "expected:%d, returned:%d", multicast_ttl_init,
                           optval);
        }
    }
    else if (rc == -1)
        VERB("RPC setsockopt(IP_MULTICAST_TTL=256) on 'snd' socket "
             "failed RPC_errno=%X", TE_RC_GET_ERROR(RPC_ERRNO(pco_snd)));
    else
        TEST_FAIL("rpc_setsockopt() unexpected behaviour, expected "
                  "return code -1");

    TEST_SUCCESS;

cleanup:
    tapi_cfg_del_route(&route_handle1);
    tapi_cfg_del_route(&route_handle2);

    CLEANUP_RPC_CLOSE(pco_snd, snd);
    CLEANUP_RPC_CLOSE(pco_rcv, rcv);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
