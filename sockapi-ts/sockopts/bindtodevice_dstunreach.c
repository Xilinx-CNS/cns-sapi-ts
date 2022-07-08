/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-bindtodevice_dstunreach Sending datagram to the receiver bound to another interface
 *
 * @objective Check that receiver side sends ICMP destination unreachable
 *            message if receiving socket is bound to an another interface
 *            with @c SO_BINDTODEVICE socket option.
 *
 * @type conformance
 *
 * @reference MAN 7 socket
 *
 * @param pco_iut        PCO on IUT
 * @param create_if      Whether to create the second IUT interface.
 *                       If @c FALSE, IUT should already have it.
 *
 * If @p create_if is @c FALSE:
 * @param pco_tst1       PCO on TESTER1
 * @param pco_tst2       PCO on TESTER2 or TESTER1
 * @param iut_if1        Network interface via which @p pco_iut
 *                       and @p pco_tst1 will be connected
 * @param iut_if2        Network interface via which @p pco_iut
 *                       and @p pco_tst2 will be connected
 * @param tst1_if        Network interface via which @p pco_tst1
 *                       and @p pco_iut will be connected
 * @param tst2_if        Network interface via which @p pco_tst2
 *                       and @p pco_iut will be connected
 * @param iut_addr1      IP address assigned to @p iut_if1
 * @param iut_addr2      IP address assigned to @p iut_if2
 * @param tst1_addr      IP address assigned to @p tst1_if
 * @param tst2_addr      IP address assigned to @p tst2_if
 *
 * If @p create_if is @c TRUE:
 * @param if_type        Interface type:
 *                       - @c vlan
 *                       - @c macvlan
 *                       - @c ipvlan
 * @param vlan_id        ID of VLAN to be created
 * @param bind_to_if     If @c TRUE, bind IUT socket to newly
 *                       created interface; otherwise bind it
 *                       to @p iut_if
 * @param pco_tst        PCO on TESTER
 * @param iut_if         Network interface via which @p pco_iut
 *                       and @p pco_tst will be connected
 * @param tst_if         Network interface via which @p pco_tst
 *                       and @p pco_iut will be connected
 * @param iut_addr       IP address assigned to @p iut_if
 * @param tst_addr       IP address assigned to @p tst_if
 *
 * @htmlonly
  <pre>

  --------------------   |----- NET 1 ----- { tst1 }
  |      iut_if1+    |---|
  | IUT              |
  |      iut_if2+    |---|
  --------------------   |----- NET 2 ----- { tst2 }

  </pre>

  @endhtmlonly
 *
 *
 * @par Test sequence:
 *
 * @note On some systems it is allowed to get the value of @c SO_BINDTODEVICE
 *       socket option, but on Linux it is not supported yet.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/bindtodevice_dstunreach"

#include "sockapi-test.h"

#include "sockapi-ts_net_conns.h"

#if HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#include <linux/icmpv6.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#include "vlan_common.h"

#define TST_BUF_SIZE      444
#define TST_CMSG_LEN      300
#define TST_RCV_BUF_LEN   500

int
main(int argc, char *argv[])
{
    rcf_rpc_server           *pco_iut;
    rcf_rpc_server           *pco_tst;
    rcf_rpc_server           *pco_tst1;
    rcf_rpc_server           *pco_tst2;

    int                       iut_s = -1;
    int                       tst1_s = -1;
    int                       tst2_s = -1;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *iut_if2 = NULL;
    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr    *iut_addr;
    const struct sockaddr    *iut_addr1;
    const struct sockaddr    *iut_addr2;
    const struct sockaddr    *tst_addr;
    const struct sockaddr    *tst1_addr;
    const struct sockaddr    *tst2_addr;

    struct sockaddr_storage   wild_addr;
    struct sockaddr_storage   aux2_addr;

    uint16_t                  port;

    struct sockaddr_storage   msg_name;
    socklen_t                 msg_namelen = sizeof(msg_name);
    char                      rcv_buf[TST_RCV_BUF_LEN];
    struct rpc_iovec          rx_vector;
    uint8_t                   cmsg_buf[TST_CMSG_LEN];
    struct cmsghdr           *cmsg;
    rpc_msghdr                rx_msghdr;

    struct sock_extended_err *optptr;
    int                       optval;

    char                      tx_buf[TST_BUF_SIZE];
    char                      rx_buf[TST_BUF_SIZE];
    int                       snt;
    int                       rcv;

    te_bool             create_if = FALSE;
    te_bool             bind_to_if = FALSE;
    te_interface_kind   if_type;
    int                 vlan_id;
    te_bool             force_ip6 = FALSE;

    sockts_net_conns  conns = SOCKTS_NET_CONNS_INIT;

    te_bool     test_failed = FALSE;

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(create_if);

    TEST_STEP("If @p create_if is @c TRUE, create additional interface "
              "on IUT, choosing its type according to @p if_type. If "
              "@p bind_to_if is @c TRUE, let @b iut_if1 be the new "
              "interface and @b iut_if2 - the old one; otherwise let "
              "@b iut_if1 be the old interface and @b iut_if2 - the new "
              "one. Let @b iut_addr1 be the IP address assigned to "
              "@b iut_if1, and @b tst1_addr - address from the same "
              "network on peer. Let @b iut_addr2 be the address assigned "
              "to @b iut_if2, and @b tst2_addr - the address from the "
              "same network on peer. "
              "Let @b pco_tst1 = @b pco_tst2 = @b pco_tst.");

    TEST_STEP("If @p create_if is @c FALSE, get @b pco_tst1, @b pco_tst2, "
              "@b iut_if1, @b iut_if2 and related IP addresses from the "
              "environment.");

    if (!create_if)
    {
        TEST_GET_PCO(pco_tst1);
        TEST_GET_PCO(pco_tst2);
        TEST_GET_ADDR(pco_iut, iut_addr1);
        TEST_GET_ADDR(pco_iut, iut_addr2);
        TEST_GET_ADDR(pco_tst1, tst1_addr);
        TEST_GET_ADDR(pco_tst2, tst2_addr);
        TEST_GET_IF(iut_if1);
        TEST_GET_IF(iut_if2);
        if (rpc_socket_domain_by_addr(iut_addr1) == RPC_PF_INET6)
            force_ip6 = TRUE;
    }
    else
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_iut, iut_addr);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_IF(iut_if);
        TEST_GET_IF(tst_if);
        TEST_GET_BOOL_PARAM(bind_to_if);
        TEST_GET_TE_INTERFACE_KIND_PARAM(if_type);
        TEST_GET_INT_PARAM(vlan_id);

        sockts_configure_net_conns(pco_iut, pco_tst, iut_if, tst_if,
                                   vlan_id, -1, iut_addr->sa_family,
                                   if_type, &conns);

        pco_tst1 = pco_tst2 = pco_tst;

        if (bind_to_if)
        {
            iut_if2 = iut_if;
            iut_addr2 = iut_addr;
            tst2_addr = tst_addr;

            iut_if1 = &conns.conn1.iut_new_if;

            iut_addr1 = conns.conn1.iut_addr;
            tst1_addr = conns.conn1.tst_addr;
        }
        else
        {
            iut_if1 = iut_if;
            iut_addr1 = iut_addr;
            tst1_addr = tst_addr;

            iut_if2 = &conns.conn1.iut_new_if;

            iut_addr2 = conns.conn1.iut_addr;
            tst2_addr = conns.conn1.tst_addr;
        }

        CFG_WAIT_CHANGES;
        if (rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET6)
            force_ip6 = TRUE;
    }


    port = te_sockaddr_get_port(iut_addr1);

    tapi_sockaddr_clone_exact(iut_addr1, &wild_addr);
    te_sockaddr_set_wildcard(SA(&wild_addr));
    te_sockaddr_set_port(SA(&wild_addr), port);

    tapi_sockaddr_clone_exact(iut_addr2, &aux2_addr);
    te_sockaddr_set_port(SA(&aux2_addr), port);

    TEST_STEP("Create an UDP socket iut_s on IUT, and two UDP sockets "
              "tst1_s on @b pco_tst1 and tst2_s on @b pco_tst2.");

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst2_addr),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Set @c IP_RECVERR or @c IPV6_RECVERR socket option "
              "according to socket domain for tst2_s.");
    optval = 1;
    rpc_setsockopt(pco_tst2, tst2_s,
                   force_ip6 ? RPC_IPV6_RECVERR : RPC_IP_RECVERR,
                   &optval);

    TEST_STEP("Bind iut_s to wildcard address; bind tst1_s to "
              "@b tst1_addr, and tst2_s to @b tst2_addr.");
    rpc_bind(pco_iut, iut_s, SA(&wild_addr));
    rpc_bind(pco_tst1, tst1_s, tst1_addr);
    rpc_bind(pco_tst2, tst2_s, tst2_addr);

    TEST_STEP("Connect tst1_s to iut_addr1, and tst2_s to iut_addr2 "
              "(using the same port as that to which iut_s is bound).");
    rpc_connect(pco_tst1, tst1_s, iut_addr1);
    rpc_connect(pco_tst2, tst2_s, SA(&aux2_addr));

    TEST_STEP("Use @c SO_BINDTODEVICE to bind iut_s to @b iut_if1.");
    rpc_bind_to_device(pco_iut, iut_s, iut_if1->if_name);

    TEST_STEP("Call blocking recv() on iut_s.");
    pco_iut->op = RCF_RPC_CALL;
    rcv = rpc_recv(pco_iut, iut_s, rx_buf, TST_BUF_SIZE, 0);

    TEST_STEP("Send data from tst1_s.");
    RPC_SEND(snt, pco_tst1, tst1_s, tx_buf, TST_BUF_SIZE, 0);

    TEST_STEP("Check that recv() on IUT was unblocked and iut_s received "
              "data.");
    pco_iut->op = RCF_RPC_WAIT;
    rcv = rpc_recv(pco_iut, iut_s, rx_buf, TST_BUF_SIZE, 0);
    if (rcv != snt)
        TEST_FAIL("%d bytes received on 'iut_s', expected %d", rcv, snt);

    TEST_STEP("Send data from tst2_s. It should provoke ICMP message from IUT, "
              "as iut_s is bound with @c SO_BINDTODEVICE to @b iut_if1.");
    RPC_SEND(snt, pco_tst2, tst2_s, tx_buf, TST_BUF_SIZE, 0);

    rx_vector.iov_base = rcv_buf;
    rx_vector.iov_len = rx_vector.iov_rlen = TST_RCV_BUF_LEN;

    memset(&rx_msghdr, 0, sizeof(rx_msghdr));
    rx_msghdr.msg_iovlen = rx_msghdr.msg_riovlen = 1;
    rx_msghdr.msg_iov = &rx_vector;
    rx_msghdr.msg_control = cmsg_buf;
    rx_msghdr.msg_controllen = TST_CMSG_LEN;
    rx_msghdr.msg_cmsghdr_num = 1;
    rx_msghdr.msg_name = &msg_name;
    rx_msghdr.msg_namelen = rx_msghdr.msg_rnamelen = msg_namelen;
    rx_msghdr.msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;
    memset(cmsg_buf, 0, TST_CMSG_LEN);

    TAPI_WAIT_NETWORK;

    TEST_STEP("With help of recvmsg() with @c MSG_ERRQUEUE flag check that "
              "tst2_s got expected ICMP destination unreachable message "
              "in response.");

    RPC_AWAIT_IUT_ERROR(pco_tst2);
    rc = rpc_recvmsg(pco_tst2, tst2_s, &rx_msghdr,  RPC_MSG_ERRQUEUE);

    if (rc < 0)
    {
        TEST_VERDICT("recvmsg() unexpectedly failed with errno %r",
                     RPC_ERRNO(pco_tst2));
    }
    else if ((size_t)rc != TST_BUF_SIZE)
    {
        ERROR("Unexpected length of the returned data: %d, "
              "expected %d", rc, TST_BUF_SIZE);
        if (rc > 0)
            ERROR_VERDICT("Unexpected length of the returned data: %s "
                          "than expected",
                          rc > TST_BUF_SIZE ? "larger" : "smaller");
        else
            ERROR_VERDICT("No data was returned");

        test_failed = TRUE;
    }

    if (memcmp(rcv_buf, tx_buf, rc))
    {
        ERROR_VERDICT("Received data does not match sent one");
        test_failed = TRUE;
    }

    if (te_sockaddrcmp(SA(&msg_name), rx_msghdr.msg_namelen,
                       SA(&aux2_addr),
                       te_sockaddr_get_size(SA(iut_addr2))) != 0)
    {
        ERROR("Returned message name:%s is not the same as "
              "address for the second interface on pco_iut:%s ",
              te_sockaddr2str(SA(&msg_name)),
              te_sockaddr2str(SA(&aux2_addr)));
        ERROR_VERDICT("recvmsg() returned incorrect address");
        test_failed = TRUE;
    }

    sockts_check_msg_flags(&rx_msghdr, RPC_MSG_ERRQUEUE);
    /* Check returned ancillary data */
    if (force_ip6)
        cmsg = sockts_msg_lookup_control_data(&rx_msghdr, SOL_IPV6, IPV6_RECVERR);
    else
        cmsg = sockts_msg_lookup_control_data(&rx_msghdr, SOL_IP, IP_RECVERR);

    if (cmsg == NULL)
        TEST_VERDICT("Ancillary data on rcv socket is not received");

    optptr = (struct sock_extended_err *) CMSG_DATA(cmsg);
    VERB("sock_extended_err - ee_errno:%d, ee_origin:%d, ee_type:%d, "
         "ee_code:%d, ee_pad:%d, ee_info:%d, ee_data:%d", optptr->ee_errno,
         optptr->ee_origin, optptr->ee_type, optptr->ee_code,
         optptr->ee_pad, optptr->ee_info, optptr->ee_data);

    if (force_ip6)
    {
        if ((optptr->ee_errno != ECONNREFUSED) ||
            (optptr->ee_origin != SO_EE_ORIGIN_ICMP6) ||
            (optptr->ee_type != ICMPV6_DEST_UNREACH) ||
            (optptr->ee_code != ICMPV6_PORT_UNREACH) ||
            (optptr->ee_pad != 0))
            TEST_VERDICT("Returned unexpected values of ancillary data");
    }
    else
    {
        if ((optptr->ee_errno != ECONNREFUSED) ||
            (optptr->ee_origin != SO_EE_ORIGIN_ICMP) ||
            (optptr->ee_type != ICMP_DEST_UNREACH) ||
            (optptr->ee_code != ICMP_PORT_UNREACH) ||
            (optptr->ee_pad != 0))
            TEST_VERDICT("Returned unexpected values of ancillary data");
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    if (create_if)
    {
        CLEANUP_CHECK_RC(sockts_destroy_net_conns(&conns));
    }

    if (force_ip6 && create_if)
    {
        /* Avoid FAILED neigbor entries on IPv6, see OL bug 9774 */
        CLEANUP_CHECK_RC(sockts_ifs_down_up(pco_iut, iut_if,
                                            pco_tst, tst_if, NULL));
    }

    TEST_END;
}

