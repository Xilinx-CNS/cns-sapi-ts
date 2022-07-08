/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-pktinfo_ip4_ip6_alternate Receiving in turns IP_PKTINFO and IPV6_PKTINFO control messages
 *
 * @objective Check what happens if we receive a few packets on IPv6 socket
 *            from IPv4 destination, switching between enabling
 *            @c IP_PKTINFO and @c IPV6_RECVPKTINFO before receiving the
 *            next packet.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 * @param addr_type         Address to which packets are sent from Tester:
 *                          - @c specific (unicast)
 *                          - @c multicast
 *                          - @c broadcast
 * @param method            Method of joining a multicast group (should be
 *                          used only if @p addr_type is @c multicast):
 *                          - @c add_drop
 *                          - @c join_leave
 *                          - @c none
 * @param pkts_num          Number of packets to send:
 *                          - @c 3
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/pktinfo_ip4_ip6_alternate"

#include "sockapi-test.h"
#include "sockopts_common.h"
#include "multicast.h"

/**
 * Enable IP_PKTINFO or IPV6_RECVPKTINFO on a socket.
 *
 * @param rpcs            RPC server handle.
 * @param s               Socked FD.
 * @param ipv4            If TRUE, enable IP_PKTINFO and disable
 *                        IPV6_RECVPKTINFO; otherwise do the opposite.
 * @param vpref           Prefix to use in verdicts.
 */
static void
set_pktinfo(rcf_rpc_server *rpcs, int s, te_bool ipv4, const char *vpref)
{
    int ip4_opt = 0;
    int ip6_opt = 0;
    int rc;

    if (ipv4)
        ip4_opt = 1;
    else
        ip6_opt = 1;

    RPC_AWAIT_ERROR(rpcs);
    rc = rpc_setsockopt_int(rpcs, s, RPC_IP_PKTINFO, ip4_opt);
    if (rc < 0)
    {
        TEST_VERDICT("%s: failed to set IP_PKTINFO to %d",
                     vpref, ip4_opt);
    }

    RPC_AWAIT_ERROR(rpcs);
    rc = rpc_setsockopt_int(rpcs, s, RPC_IPV6_RECVPKTINFO, ip6_opt);
    if (rc < 0)
    {
        TEST_VERDICT("%s: failed to set IPV6_RECVPKTINFO to %d",
                     vpref, ip6_opt);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    tapi_env_net               *net = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    sockts_addr_type            addr_type;
    tarpc_joining_method        method = TARPC_MCAST_ADD_DROP;
    int                         pkts_num;

    struct sockaddr_storage     dst_addr;
    struct sockaddr_storage     bind_addr;
    unsigned int                iut_if_parent_index;

    int iut_s = -1;
    int tst_s = -1;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_ADDR_TYPE(addr_type);
    if (addr_type == SOCKTS_ADDR_MCAST)
        TEST_GET_MCAST_METHOD(method);
    TEST_GET_INT_PARAM(pkts_num);

    CHECK_RC(sockts_get_if_parent_index(
                               pco_iut,
                               iut_if->if_name,
                               &iut_if_parent_index));

    tapi_sockaddr_clone_exact(iut_addr, &dst_addr);
    switch (addr_type)
    {
        case SOCKTS_ADDR_SPEC:
            break;

        case SOCKTS_ADDR_BCAST:
            SIN(&dst_addr)->sin_addr.s_addr = net->ip4bcast.sin_addr.s_addr;
            break;

        case SOCKTS_ADDR_MCAST:
            te_sockaddr_set_multicast(SA(&dst_addr));
            break;

        default:

            TEST_FAIL("Not supported address type");
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.ss_family = AF_INET6;
    te_sockaddr_set_wildcard(SA(&bind_addr));
    te_sockaddr_set_port(SA(&bind_addr),
                         te_sockaddr_get_port(iut_addr));

    TEST_STEP("Create a datagram IPv6 socket on IUT, bind it to "
              "wildcard address with the same port as in @p iut_addr.");
    iut_s = rpc_socket(pco_iut, RPC_PF_INET6, RPC_SOCK_DGRAM,
                       RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_V6ONLY, 0);
    rpc_bind(pco_iut, iut_s, SA(&bind_addr));

    TEST_STEP("Create a datagram IPv4 socket on Tester, bind it to "
              "@p tst_addr.");
    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM,
                       RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

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

    TEST_STEP("Send @p pkts_num packets from the Tester socket to "
              "an address chosen according to @p addr_type; receive "
              "each packet from the IUT socket after sending it.");
    for (i = 0; i < pkts_num; i++)
    {
        te_bool ipv4_opt;
        char    vpref[1024] = "";

        TE_SPRINTF(vpref, "Packet %d", i + 1);

        TEST_SUBSTEP("Before sending a packet, switch between "
                     "enabling @c IP_PKTINFO and @c IPV6_RECVPKTINFO "
                     "options on the IUT socket. For the first packet "
                     "enable @c IP_PKTINFO.");
        ipv4_opt = (i % 2 == 0 ? TRUE : FALSE);
        set_pktinfo(pco_iut, iut_s, ipv4_opt, vpref);

        TEST_SUBSTEP("After sending a packet, receive it on the IUT "
                     "socket with @b recvmsg(). Check that control message "
                     "is received which corresponds to the option enabled "
                     "for the IUT socket this time.");
        CHECK_RC(sockts_send_recv_check_pktinfo(pco_tst, tst_s,
                                                pco_iut, iut_s,
                                                iut_addr, SA(&dst_addr),
                                                addr_type,
                                                iut_if->if_index,
                                                iut_if_parent_index,
                                                ipv4_opt, !ipv4_opt,
                                                vpref));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
