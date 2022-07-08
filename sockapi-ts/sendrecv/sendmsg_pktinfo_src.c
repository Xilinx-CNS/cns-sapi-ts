/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-sendmsg_pktinfo_src Using IP_PKTINFO/IPV6_PKTINFO with sendmsg()/sendmmsg() to set source address
 *
 * @objective Check that address passed in @c IP_PKTINFO / @c IPV6_PKTINFO
 *            control message to @b sendmsg() / @b sendmmsg() affects
 *            source address of the sent packet.
 *
 * @type Conformance.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_2addr
 *                      - @ref arg_types_env_peer2peer_2addr_ipv6
 * @param data_len      Length of data to send in a packet, in bytes:
 *                      - @c 120
 * @param packet_num    Number of packets to send:
 *                      - @c 10
 * @param use_sendmmsg  Whether to use @b sendmmsg() instead of @b
 *                      sendmsg()
 *
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/sendmsg_pktinfo_src"

#include "sockapi-test.h"

#define TST_CMSG_LEN   300

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_tst;
    rcf_rpc_server            *pco_iut;
    int                        tst_s = -1;
    int                        iut_s = -1;
    const struct sockaddr     *iut_addr1 = NULL;
    const struct sockaddr     *iut_addr2 = NULL;
    struct sockaddr_storage    iut_addr2_port;
    const struct sockaddr     *tst_addr1 = NULL;
    char                      *sendbuf = NULL;
    char                      *recvbuf = NULL;

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
    int                        data_len;

    struct sockaddr_storage from;
    socklen_t               fromlen;

    int     i;
    te_bool first = FALSE;
    int     packet_num;
    te_bool use_sendmmsg = FALSE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR_NO_PORT(iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr1);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_num);
    TEST_GET_BOOL_PARAM(use_sendmmsg);

    domain = rpc_socket_domain_by_addr(iut_addr1);
    if (iut_addr1->sa_family == AF_INET)
        ipv4 = TRUE;
    else
        ipv4 = FALSE;

    sendbuf = te_make_buf_by_len(data_len);
    CHECK_NOT_NULL(recvbuf = (char *)malloc(data_len));

    TEST_STEP("Let @b iut_addr2_port store the same address as "
              "@p iut_addr2 but with port from @p iut_addr1.");
    tapi_sockaddr_clone_exact(iut_addr2, &iut_addr2_port);
    te_sockaddr_set_port(SA(&iut_addr2_port),
                         *te_sockaddr_get_port_ptr(iut_addr1));

    TEST_STEP("Create @b tst_s socket on Tester.");
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM,
                       RPC_IPPROTO_UDP);

    TEST_STEP("Bind @b tst_s socket to @b tst_addr1.");
    rpc_bind(pco_tst, tst_s, tst_addr1);

    TEST_STEP("Create @b iut_s socket on IUT, bind it to @b iut_addr2_port.");
    if ((iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                            RPC_PROTO_DEF, TRUE, FALSE,
                                            SA(&iut_addr2_port))) < 0)
        TEST_FAIL("Cannot create SOCK_DGRAM 'iut_s' socket");

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

    /* Construct in_pktinfo */
    if (ipv4)
    {
        cmsg->cmsg_level = SOL_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        pktinfo = (struct in_pktinfo *) CMSG_DATA(cmsg);
    }
    else
    {
        cmsg->cmsg_level = SOL_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        pktinfo6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
    }
    /* Construct msg_name */
    addr_len = te_sockaddr_get_size(tst_addr1);
    tx_msghdr.msg_name = malloc(addr_len);
    memcpy(tx_msghdr.msg_name, tst_addr1, addr_len);
    tx_msghdr.msg_namelen = tx_msghdr.msg_rnamelen = addr_len;
    tx_msghdr.msg_flags = 0;

    TEST_STEP("For @p packet_num times send a packet from @b iut_s "
              "to @b tst_addr1, using @b sendmsg() if @p use_sendmmsg "
              "is @c FALSE or @b sendmmsg() otherwise.");
    for (i = 0; i < packet_num; i++)
    {
        TEST_SUBSTEP("Each time pass an @c IP_PKTINFO (for IPv4) or "
                     "@c IPV6_PKTINFO (for IPv6) control message. For the "
                     "first packet set @b ipi_spec_dst or @b ipi6_addr in "
                     "the control message to an address from @p iut_addr1, "
                     "for the second packet - from @b iut_addr2_port, for "
                     "the third - from @p iut_addr1, and so on, changing "
                     "address in the control message for each new packet.");

        first = (i % 2) ? TRUE : FALSE;
        if (ipv4)
        {
            pktinfo->ipi_spec_dst =
                *(struct in_addr *)te_sockaddr_get_netaddr((first) ?
                                                    iut_addr1 :
                                                    SA(&iut_addr2_port));
        }
        else
        {
            memcpy(&pktinfo6->ipi6_addr,
                   te_sockaddr_get_netaddr(first ?
                                              iut_addr1 :
                                              SA(&iut_addr2_port)),
                   sizeof(pktinfo6->ipi6_addr));
        }

        if (use_sendmmsg)
            rpc_sendmmsg_as_sendmsg(pco_iut, iut_s, &tx_msghdr, 0);
        else
            rpc_sendmsg(pco_iut, iut_s, &tx_msghdr, 0);

        TEST_SUBSTEP("Each time receive a packet on @b tst_s with help of "
                     "@b recvfrom(), checking that it returns the same "
                     "source address as the address passed in "
                     "@c IP_PKTINFO or @c IPV6_PKTINFO control message "
                     "when sending.");

        fromlen = sizeof(from);
        memset(&from, 0, sizeof(from));
        rc = rpc_recvfrom(pco_tst, tst_s, recvbuf, data_len, 0,
                          (struct sockaddr *)&from, &fromlen);

        if (rc != (int)data_len)
            TEST_VERDICT("Only part of sent data is received");
        if (memcmp(recvbuf, sendbuf, data_len) != 0)
            TEST_VERDICT("Received data are not equal to sent");

        if (te_sockaddrcmp((struct sockaddr *)&from, fromlen,
                           (first ? iut_addr1 : SA(&iut_addr2_port)),
                           te_sockaddr_get_size(iut_addr1)) != 0)
        {
            TEST_VERDICT("Invalid peer address was returned by recvfrom() "
                         "on IUT");
        }
    }

    TEST_SUCCESS;

cleanup:
    free(sendbuf);
    free(recvbuf);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(tx_msghdr.msg_name);

    TEST_END;
}
