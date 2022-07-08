/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-sendmsg_pktinfo Using IP_PKTINFO/IPV6_PKTINFO with sendmsg() or sendmmsg() to set outgoing interface
 *
 * @objective Check that using of @c IP_PKTINFO / @c IPV6_PKTINFO with
 *            sendmsg() or sendmmsg() is taken into account in routing the
 *            outgoing packet.
 *
 * @type Conformance.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_two_nets_iut_first
 *                      - @ref arg_types_env_two_nets_iut_second
 *                      - @ref arg_types_env_two_nets_iut_first_ipv6
 *                      - @ref arg_types_env_two_nets_iut_second_ipv6
 * @param data_len      Length of data to be sent:
 *                      - @c 120
 * @param use_sendmmsg  Whether to use @b sendmmsg() instead of
 *                      @b sendmsg()
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/sendmsg_pktinfo"

#include "sockapi-test.h"

#define TST_CMSG_LEN   300

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_tst1;
    rcf_rpc_server            *pco_tst2;
    rcf_rpc_server            *pco_iut;
    int                        tst1_s = -1;
    int                        tst2_s = -1;
    int                        iut_s = -1;
    const struct sockaddr     *iut_addr1 = NULL;
    const struct sockaddr     *iut_addr2 = NULL;
    const struct sockaddr     *alien_addr = NULL;
    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *iut_if2 = NULL;
    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;
    char                      *sendbuf = NULL;
    char                      *recvbuf = NULL;
    cfg_handle                 ah1 = CFG_HANDLE_INVALID;
    cfg_handle                 ah2 = CFG_HANDLE_INVALID;
    cfg_handle                 rh1 = CFG_HANDLE_INVALID;
    cfg_handle                 rh2 = CFG_HANDLE_INVALID;

    rpc_msghdr                 tx_msghdr = { .msg_name = NULL };
    struct msghdr              msg;
    struct rpc_iovec           send_buf_iov;
    uint8_t                    cmsg_buf[TST_CMSG_LEN];
    struct in_pktinfo         *pktinfo;
    struct in6_pktinfo        *pktinfo6;
    rpc_socket_domain          domain;
    te_bool                    ipv4;

    size_t                     addr_len;
    struct cmsghdr            *cmsg;

    int     data_len;
    int     af;
    int     prefix;
    te_bool sock_readable;
    te_bool use_sendmmsg;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, alien_addr);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_BOOL_PARAM(use_sendmmsg);

    if (iut_addr1->sa_family == AF_INET)
        ipv4 = TRUE;
    else
        ipv4 = FALSE;

    domain = rpc_socket_domain_by_addr(iut_addr1);
    sendbuf = te_make_buf_by_len(data_len);
    recvbuf = te_make_buf_by_len(data_len);

    TEST_STEP("Create UDP sockets @b iut_s on @p pco_iut, @b tst1_s "
              "on @p pco_tst1 and @b tst2_s on @p pco_tst2.");
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM,
                        RPC_IPPROTO_UDP);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM,
                        RPC_IPPROTO_UDP);
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM,
                       RPC_IPPROTO_UDP);

    af = alien_addr->sa_family;
    prefix = te_netaddr_get_bitsize(af);

    TEST_STEP("Assign @p alien_addr address to @p tst1_if and @p tst2_if.");
    CHECK_RC(cfg_add_instance_fmt(&ah1,
                                  CFG_VAL(INTEGER, prefix),
                                  "/agent:%s/interface:%s/net_addr:%s",
                                  pco_tst1->ta, tst1_if->if_name,
                                  te_sockaddr_get_ipstr(alien_addr)));
    CHECK_RC(cfg_add_instance_fmt(&ah2,
                                  CFG_VAL(INTEGER, prefix),
                                  "/agent:%s/interface:%s/net_addr:%s",
                                  pco_tst2->ta, tst2_if->if_name,
                                  te_sockaddr_get_ipstr(alien_addr)));

    TEST_STEP("Bind @b tst1_s and @b tst2_s to @p alien_addr.");
    rpc_bind(pco_tst1, tst1_s, alien_addr);
    rpc_bind(pco_tst2, tst2_s, alien_addr);


    TEST_STEP("On IUT add a route to @p alien_addr via @p iut_if2 with "
              "metric @c 3.");
    if (tapi_cfg_add_route(pco_iut->ta, af,
                           te_sockaddr_get_netaddr(alien_addr), prefix,
                           NULL, iut_if2->if_name, NULL,
                           0, 3, 0, 0, 0, 0, &rh2) != 0)
        TEST_FAIL("Cannot add route to 'alien_addr' via 'iut_if1'");

    TEST_STEP("On IUT add a route to @p alien_addr via @p iut_if1 with "
              "metric @c 4.");
    if (tapi_cfg_add_route(pco_iut->ta, af,
                           te_sockaddr_get_netaddr(alien_addr), prefix,
                           NULL, iut_if1->if_name, NULL,
                           0, 4, 0, 0, 0, 0, &rh1) != 0)
        TEST_FAIL("Cannot add route to 'alien_addr' via 'iut_if1'");

    CFG_WAIT_CHANGES;

    /* Construct msghdr */
    memset(&tx_msghdr, 0, sizeof(tx_msghdr));
    tx_msghdr.msg_iovlen = tx_msghdr.msg_riovlen = 1;
    /* Construct iov */
    send_buf_iov.iov_base = sendbuf;
    send_buf_iov.iov_rlen = send_buf_iov.iov_len = data_len;
    tx_msghdr.msg_iov = &send_buf_iov;
    /* Construct cmsg */
    memset(cmsg_buf, 0, sizeof(cmsg_buf));
    tx_msghdr.msg_control = cmsg_buf;
    tx_msghdr.msg_controllen = CMSG_SPACE(ipv4 ?
                                            sizeof(struct in_pktinfo) :
                                            sizeof(struct in6_pktinfo));
    tx_msghdr.msg_cmsghdr_num = 1;

    /* Bug 56027: don't use type cast rpc_msghdr -> 'struct msghdr'! */
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = tx_msghdr.msg_control;
    msg.msg_controllen = tx_msghdr.msg_controllen;
    cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);

    /* Construct in_pktinfo / in6_pktinfo */
    if (ipv4)
    {
        cmsg->cmsg_level = SOL_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        pktinfo = (struct in_pktinfo *) CMSG_DATA(cmsg);
        pktinfo->ipi_ifindex = rpc_if_nametoindex(pco_iut,
                                                  iut_if1->if_name);
    }
    else
    {
        cmsg->cmsg_level = SOL_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        pktinfo6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
        pktinfo6->ipi6_ifindex = rpc_if_nametoindex(pco_iut,
                                                    iut_if1->if_name);
    }

    /* Construct msg_name */
    addr_len = te_sockaddr_get_size(alien_addr);
    tx_msghdr.msg_name = malloc(addr_len);
    memcpy(tx_msghdr.msg_name, alien_addr, addr_len);
    tx_msghdr.msg_namelen = tx_msghdr.msg_rnamelen = addr_len;
    tx_msghdr.msg_flags = 0;

    TEST_STEP("Send data from @p iut_s to @p alien_addr with help of "
              "@b sendmsg() (if @p use_sendmmsg is @c FALSE) or "
              "@b sendmmsg() (if @p use_sendmmsg is @c TRUE). In "
              "control data pass @c IP_PKTINFO (for IPv4) or "
              "@c IPV6_PKTINFO (for IPv6) message with interface "
              "index set to index of @p iut_if1.");
    if (use_sendmmsg)
        rpc_sendmmsg_as_sendmsg(pco_iut, iut_s, &tx_msghdr, 0);
    else
        rpc_sendmsg(pco_iut, iut_s, &tx_msghdr, 0);

    TEST_STEP("Wait for a while and check that only @p tst1_s socket "
              "became readable.");

    TAPI_WAIT_NETWORK;

    RPC_GET_READABILITY(sock_readable, pco_tst2, tst2_s, 1);
    if (sock_readable)
        TEST_VERDICT("Tester2 received datagram for Tester1");

    RPC_GET_READABILITY(sock_readable, pco_tst1, tst1_s, 1);
    if (!sock_readable)
        TEST_VERDICT("Tester1 cannot receive the datagram destined to it");

    TEST_STEP("Receive and check data on @b tst1_s.");
    RPC_AWAIT_ERROR(pco_tst1);
    rc = rpc_recv(pco_tst1, tst1_s, recvbuf, data_len, 0);
    if (rc < 0)
    {
        TEST_VERDICT("recv() unexpectedly failed with errno %r",
                     RPC_ERRNO(pco_tst1));
    }
    else if (rc != data_len || memcmp(sendbuf, recvbuf, data_len) != 0)
    {
        TEST_VERDICT("recv() returned unexpected data");
    }

    TEST_SUCCESS;

cleanup:
    free(sendbuf);
    free(recvbuf);

    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    cfg_del_instance(ah1, FALSE);
    cfg_del_instance(ah2, FALSE);
    if (rh1 != CFG_HANDLE_INVALID)
        tapi_cfg_del_route(&rh1);
    if (rh2 != CFG_HANDLE_INVALID)
        tapi_cfg_del_route(&rh2);

    free(tx_msghdr.msg_name);

    TEST_END;
}
