/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id: source_join.c 73400 2012-02-03 07:45:29Z yuran $
 */

/** @page multicast-source_join IP_ADD/DROP_SOURCE_MEMBERSHIP usecases
 *
 * @objective Check that after joining multicast group using 
 *            @c IP_ADD_SOURCE_MEMBERSHIP or @c MCAST_JOIN_SOURCE_GROUP
 *            socket receives only packets with specified source address.
 *
 * @type Conformance.
 *
 * @param net1              IP network from which to allocate addresses
 * @param pco_tst           PCO on Tester
 * @param tst_if            Interface on Tester
 * @param tst_addr1         Tester address
 * @param pco_iut           PCO on IUT
 * @param iut_if            IUT interface connected to Tester
 * @param iut_addr          IUT address
 * @param mcast_addr        Multicast address
 * @param method            Method used to join multicast group
 * @param packet_number     Number of datagrams to send for reliability
 * @param sock_func         Socket creation function
 *
 * @par Scenario:
 * -# Allocate a new IP address in @p net1 for @p tst_addr2.
 * -# Remove all addresses from @p tst_if.
 * -# Create @c SOCK_DGRAM socket on @p pco_iut.
 * -# Bind IUT socket to @p iut_addr.
 * -# Join @p mcast_addr group with @p tst_addr1 source using @p method.
 * -# Create socket on @p pco_tst, bind it to @p tst_addr1 or @p tst_addr2
 *    and send a multicast packet two times from different tester
 *    addresses. Perform the following steps for @p tst_addr1 and
 *    @p tst_addr2 successively:
 * -#     Add @p tst_addr1 or @p tst_addr2 address to @p tst_if in
 *        dependence on iteration.
 * -#     Create socket on @p pco_tst.
 * -#     Bind it to @p tst_addr1 or @p tst_addr2 address in dependence on
 *        iteration.
 * -#     Send multicast packet from the socket.
 * -#     Close the socket.
 * -#     Delete all addresses fro @p tst_if.
 * -# Check that socket on @p pco_iut receives packet only from
 *    @p tst_addr1.
 * -# Leave @p mcast_addr group.
 * -# Roll-back addresses on @p tst_if.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/source_join"

#include "sockapi-test.h"
#include "mcast_lib.h"
#include "multicast.h"

static void
send_packet(rcf_rpc_server *pco_tst, const struct if_nameindex *tst_if,
            const struct sockaddr *tst_addr, int prefix,
            const struct sockaddr *mcast_addr, int data_len)
{
    struct tarpc_mreqn  mreq;
    cfg_handle          cfgh;

    char    sendbuf[data_len];
    int     sock    = -1;

    /**
     * There is a bug in linux version >= 3.2 and < 3.11. 
     */
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           tst_addr, prefix, TRUE, &cfgh));
    TAPI_WAIT_NETWORK;

    sock = rpc_socket(pco_tst, rpc_socket_domain_by_addr(mcast_addr),
                      RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst, sock, tst_addr);

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
           sizeof(mreq.address));
    rpc_setsockopt(pco_tst, sock, RPC_IP_MULTICAST_IF, &mreq);

    rpc_sendto(pco_tst, sock, sendbuf, sizeof(sendbuf), 0, mcast_addr);

    RPC_CLOSE(pco_tst, sock);

    tapi_cfg_save_del_if_ip4_addresses(pco_tst->ta,
        tst_if->if_name, NULL, FALSE, NULL, NULL, NULL, NULL);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *mcast_addr = NULL;
    const struct sockaddr *tst_addr1 = NULL;
    struct sockaddr       *tst_addr2 = NULL;
    int                    iut_s = -1;

    struct sockaddr_storage from;
    socklen_t               fromlen;

    int                     first_addr;
    int                     second_addr;
    int                     strange_addr;

    const struct if_nameindex   *iut_if;
    const struct if_nameindex   *tst_if;
    tapi_env_net           *net1 = NULL;

    char                  *recvbuf = NULL;
    int                    data_len = 512;
    int                    i;
    int                    packet_number;
    tarpc_joining_method   method;

    sockts_socket_func  sock_func;

    struct sockaddr    *saved_addrs;
    int                *saved_prefixes;
    te_bool            *saved_broadcasts;
    int                 saved_count;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_tst, tst_addr1);
    TEST_GET_NET(net1);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_INT_PARAM(packet_number);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    recvbuf = te_make_buf_by_len(2 * data_len);

    CHECK_RC(tapi_env_allocate_addr(net1,
        domain_rpc2h(rpc_socket_domain_by_addr(tst_addr1)),
        &tst_addr2, NULL));

    CHECK_RC(tapi_cfg_save_del_if_ip4_addresses(pco_tst->ta,
        tst_if->if_name, NULL, FALSE, &saved_addrs, &saved_prefixes,
        &saved_broadcasts, &saved_count));

    iut_s = sockts_socket(sock_func, pco_iut,
                          rpc_socket_domain_by_addr(mcast_addr),
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_iut, iut_s, mcast_addr);
    rpc_mcast_source_join(pco_iut, iut_s, mcast_addr, tst_addr1,
                          iut_if->if_index, method);

    for (i = 0; i < packet_number; i++)
    {
        first_addr = 0;
        second_addr = 0;
        strange_addr = 0;

        send_packet(pco_tst, tst_if, tst_addr1, net1->ip4pfx, mcast_addr,
                    data_len);
        send_packet(pco_tst, tst_if, tst_addr2, net1->ip4pfx, mcast_addr,
                    data_len);

        TAPI_WAIT_NETWORK;

        fromlen = sizeof(from);
        RPC_AWAIT_IUT_ERROR(pco_iut);
        while (rpc_recvfrom(pco_iut, iut_s, recvbuf, data_len * 2,
                            RPC_MSG_DONTWAIT, (struct sockaddr *)&from,
                            &fromlen) != -1)
        {
            if (te_sockaddrcmp((struct sockaddr *)&from, fromlen,
                               tst_addr1,
                               te_sockaddr_get_size(tst_addr1)) == 0)
                first_addr++;
            else if (te_sockaddrcmp((struct sockaddr *)&from, fromlen,
                                    tst_addr2,
                                    te_sockaddr_get_size(tst_addr2)) == 0)
                second_addr++;
            else
                strange_addr++;
            fromlen = sizeof(from);
            RPC_AWAIT_IUT_ERROR(pco_iut);
        }

        if (first_addr != 1)
            TEST_VERDICT("Incorrect number of packets were received from "
                         "the first address");
        else if (second_addr > 0)
            TEST_VERDICT("Packets were received from the second address");
        else if (strange_addr > 0)
            TEST_VERDICT("Packets were received from the strange address");
    }

    rpc_mcast_source_leave(pco_iut, iut_s, mcast_addr, tst_addr1,
                           iut_if->if_index, method);

    TEST_SUCCESS;

cleanup:
    free(recvbuf);
    free(tst_addr2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CHECK_RC(tapi_cfg_restore_if_ip4_addresses(pco_tst->ta,
        tst_if->if_name, saved_addrs, saved_prefixes,
        saved_broadcasts, saved_count));

    TEST_END;
}
