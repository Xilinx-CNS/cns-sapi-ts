/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-ipv6_ipv4_pktinfo Using IP_PKTINFO/IPV6_RECVPKTINFO on IPv6 socket receiving IPv4 packets
 *
 * @objective Check what happens if @c IP_PKTINFO and/or @c IPV6_RECVPKTINFO
 *            is enabled on an IPv6 socket which can receive both IPv4 and IPv6
 *            traffic.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_p2p_ip4_ip6
 * @param ip_pktinfo        If @c TRUE, enable @c IP_PKTINFO option on IUT
 *                          socket.
 * @param ipv6_recvpktinfo  If @c TRUE, enable @c IPV6_RECVPKTINFO option
 *                          on IUT socket.
 * @param addr_type         Address to which packet is sent from Tester:
 *                          - @c specific (unicast)
 *                          - @c multicast
 *                          - @c broadcast
 * @param send_ipv4         If @c TRUE, send a packet from IPv4 socket,
 *                          otherwise send it from IPv6 socket.
 * @param method            Method of joining a multicast group (should be
 *                          used only if @p addr_type is @c multicast):
 *                          - @c add_drop
 *                          - @c join_leave
 *                          - @c none
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ipv6_ipv4_pktinfo"

#include "sockapi-test.h"
#include "sockopts_common.h"
#include "multicast.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    tapi_env_net               *net = NULL;
    const struct sockaddr      *iut_addr6 = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct if_nameindex  *iut_if;
    const struct if_nameindex  *tst_if;
    int                         iut_s = -1;
    int                         tst_s = -1;
    te_bool                     ip_pktinfo;
    te_bool                     ipv6_recvpktinfo;
    sockts_addr_type            addr_type;
    te_bool                     send_ipv4;
    tarpc_joining_method        method = TARPC_MCAST_ADD_DROP;

    struct sockaddr_storage     dst_addr;
    struct sockaddr_storage     bind_addr;
    unsigned int                iut_if_parent_index;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(ip_pktinfo);
    TEST_GET_BOOL_PARAM(ipv6_recvpktinfo);
    SOCKTS_GET_ADDR_TYPE(addr_type);
    TEST_GET_BOOL_PARAM(send_ipv4);
    if (addr_type == SOCKTS_ADDR_MCAST)
        TEST_GET_MCAST_METHOD(method);

    CHECK_RC(sockts_get_if_parent_index(
                               pco_iut,
                               iut_if->if_name,
                               &iut_if_parent_index));

    switch (addr_type)
    {
        case SOCKTS_ADDR_SPEC:

            if (send_ipv4)
                tapi_sockaddr_clone_exact(iut_addr, &dst_addr);
            else
                tapi_sockaddr_clone_exact(iut_addr6, &dst_addr);

            break;

        case SOCKTS_ADDR_BCAST:

            if (!send_ipv4)
                TEST_FAIL("IPv6 does not support broadcast addresses");

            tapi_sockaddr_clone_exact(iut_addr, &dst_addr);
            SIN(&dst_addr)->sin_addr.s_addr = net->ip4bcast.sin_addr.s_addr;
            break;

        case SOCKTS_ADDR_MCAST:

            if (send_ipv4)
                tapi_sockaddr_clone_exact(iut_addr, &dst_addr);
            else
                tapi_sockaddr_clone_exact(iut_addr6, &dst_addr);

            te_sockaddr_set_multicast(SA(&dst_addr));

            break;

        default:

            TEST_FAIL("Not supported address type");
    }

    tapi_sockaddr_clone_exact(iut_addr6, &bind_addr);
    te_sockaddr_set_wildcard(SA(&bind_addr));
    te_sockaddr_set_port(SA(&dst_addr), te_sockaddr_get_port(iut_addr6));

    TEST_STEP("Create a datagram IPv6 socket on IUT.");
    iut_s = rpc_socket(pco_iut, RPC_PF_INET6, RPC_SOCK_DGRAM,
                       RPC_PROTO_DEF);

    TEST_STEP("Create a datagram Tester socket on IUT (IPv4 if "
              "@p send_ipv4 is @c TRUE and IPv6 otherwise).");
    tst_s = rpc_socket(pco_tst, (send_ipv4 ? RPC_PF_INET : RPC_PF_INET6),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Set @c IPV6_V6ONLY option to @c 0 for IUT socket.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_V6ONLY, 0);

    TEST_STEP("Enable or disable @c IP_PKTINFO option on IUT socket "
              "according to @p ip_pktinfo.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_PKTINFO,
                            (ip_pktinfo ? 1 : 0));
    if (rc < 0)
    {
        TEST_VERDICT("Setting IP_PKTINFO failed with errno %r",
                     RPC_ERRNO(pco_iut));
    }

    TEST_STEP("Enable or disable @c IPV6_RECVPKTINFO option on IUT socket "
              "according to @p ipv6_recvpktinfo.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_RECVPKTINFO,
                            (ipv6_recvpktinfo ? 1 : 0));
    if (rc < 0)
    {
        TEST_VERDICT("Setting IPV6_RECVPKTINFO failed with errno %r",
                     RPC_ERRNO(pco_iut));
    }

    TEST_STEP("Bind IUT socket to wildcard address.");
    rpc_bind(pco_iut, iut_s, SA(&bind_addr));

    if (addr_type == SOCKTS_ADDR_MCAST)
    {
        TEST_STEP("If @p addr_type is @c multicast, set outgoing interface "
                  "for multicast packets to @p tst_if for Tester socket, "
                  "and join IUT socket to a tested multicast group "
                  "according to @p method.");

        sockts_set_multicast_if(pco_tst, tst_s, dst_addr.ss_family,
                                tst_if->if_index);

        rpc_mcast_join(pco_iut, iut_s, SA(&dst_addr), iut_if->if_index,
                       method);

    }
    else if (addr_type == SOCKTS_ADDR_BCAST)
    {
        TEST_STEP("If @p addr_type is @c broadcast, set @c SO_BROADCAST on "
                  "Tester socket.");
        rpc_setsockopt_int(pco_tst, tst_s, RPC_SO_BROADCAST, 1);
    }

    TEST_STEP("Send data from Tester socket to an address chosen according "
              "to @p addr_type. Check that IUT socket receives the data. "
              "Check that @c IPV6_PKTINFO control message is received for "
              "the packet if and only if @c IPV6_RECVPKTINFO was enabled. "
              "Check that @c IP_PKTINFO control message is received if and "
              "only if @c IP_PKTINFO option was enabled and IPv4 packet "
              "was received.");
    CHECK_RC(sockts_send_recv_check_pktinfo(pco_tst, tst_s, pco_iut, iut_s,
                                            iut_addr, SA(&dst_addr),
                                            addr_type,
                                            iut_if->if_index,
                                            iut_if_parent_index,
                                            ip_pktinfo, ipv6_recvpktinfo,
                                            ""));

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
