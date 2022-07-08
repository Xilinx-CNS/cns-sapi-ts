/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-ip_pktinfo Usage of IP_PKTINFO (IPV6_RECVPKTINFO) socket option
 *
 * @objective Check that when @c IP_PKTINFO (@c IPV6_RECVPKTINFO) socket
 *            option is enabled on the socket, @b recvmsg() returns
 *            @c IP_PKTINFO (@c IPV6_PKTINFO) ancillary message with
 *            some information about the incoming packet.
 *
 * @type conformance
 *
 * @reference MAN 7 ip
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_mcast
 *                      - @ref arg_types_env_peer2peer_mcast_lo
 *                      - @ref arg_types_env_peer2peer_mcast_ipv6
 *                      - @ref arg_types_env_peer2peer_mcast_lo_ipv6
 *                      - @ref arg_types_env_peer2peer_2addr
 *                      - @ref arg_types_env_peer2peer_2addr_lo
 *                      - @ref arg_types_env_peer2peer_2addr_ipv6
 *                      - @ref arg_types_env_peer2peer_2addr_lo_ipv6
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_lo
 * @param addr_type     Address to which packet is sent:
 *                      - @c specific (unicast)
 *                      - @c multicast
 *                      - @c broadcast
 * @param method        Method of joining a multicast group (should be
 *                      used only if @p addr_type is @c multicast):
 *                      - @c add_drop
 *                      - @c join_leave
 *                      - @c none
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ip_pktinfo"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "multicast.h"
#include "sockopts_common.h"

/** How many times to send/receive data */
#define TST_ITER       3

/**
 * Send some data from Tester, receive it on IUT. Check whether
 * IP_PKTINFO/IPV6_PKTINFO control message was received as expected.
 *
 * @param pco_iut       RPC server on IUT.
 * @param iut_s         IUT socket.
 * @param pco_tst       RPC server on Tester.
 * @param tst_s         Tester socket.
 * @param addr_type     Destination address type.
 * @param dst_addr      Destination address.
 * @param iut_addr      The first address assigned to IUT interface
 *                      (used only for IPv4).
 * @param iut_if_index  IUT interface index.
 * @param ip_pktinfo    Whether IP_PKTINFO option is enabled.
 * @param unexp_cmsg    If FALSE, print verdict if unexpected control
 *                      message was encountered, and set this parameter
 *                      to TRUE to avoid printing the same verdict
 *                      again.
 * @param vstr          Message to print in verdicts.
 */
static void
test_send_recv(rcf_rpc_server *pco_iut, int iut_s,
               rcf_rpc_server *pco_tst, int tst_s,
               sockts_addr_type addr_type,
               const struct sockaddr *dst_addr,
               const struct sockaddr *iut_addr,
               unsigned int iut_if_index,
               te_bool ip_pktinfo,
               te_bool *unexp_cmsg,
               const char *vstr)
{
    char        tx_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t      tx_buf_len;
    char        rx_buf[sizeof(tx_buf) * 2];
    ssize_t     rx_buf_len;
    int         rc;
    int         rc_aux;

    rpc_msghdr          *msg = NULL;
    struct cmsghdr      *cmsg = NULL;
    te_bool              oth_cmsg = FALSE;

    tx_buf_len = rand_range(1, sizeof(tx_buf));
    te_fill_buf(tx_buf, tx_buf_len);

    rx_buf_len = sizeof(rx_buf);
    msg = sockts_make_msghdr(-1, -1, &rx_buf_len, SOCKTS_CMSG_LEN);

    RPC_SENDTO(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0, dst_addr);
    TAPI_WAIT_NETWORK;
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_recvmsg(pco_iut, iut_s, msg, RPC_MSG_DONTWAIT);
    if (rc < 0)
    {
        TEST_VERDICT("%s: recvmsg() failed unexpectedly with "
                     "errno %r", vstr, RPC_ERRNO(pco_iut));
    }

    rc_aux = iovecs_to_buf(msg->msg_iov, msg->msg_iovlen, rx_buf,
                           MIN(rc, sizeof(rx_buf)));
    if (rc_aux != rc || rc != (int)tx_buf_len ||
        memcmp(rx_buf, tx_buf, tx_buf_len) != 0)
    {
        TEST_VERDICT("%s: recvmsg() returned unexpected data", vstr);
    }

    if (dst_addr->sa_family == AF_INET)
    {
        cmsg = sockts_msg_lookup_control_data_ext(msg, SOL_IP,
                                                  IP_PKTINFO,
                                                  &oth_cmsg);
        if (cmsg != NULL)
        {
            RING("IP_PKTINFO control message was received: %s",
                 in_pktinfo2str(SOCKTS_PKTINFO(cmsg)));
        }
    }
    else
    {
        cmsg = sockts_msg_lookup_control_data_ext(msg, SOL_IPV6,
                                                  IPV6_PKTINFO,
                                                  &oth_cmsg);
        if (cmsg != NULL)
        {
            RING("IPV6_PKTINFO control message was received: %s",
                 in6_pktinfo2str(SOCKTS_PKTINFO6(cmsg)));
        }
    }

    if (oth_cmsg)
    {
        if (!*unexp_cmsg)
        {
            ERROR_VERDICT("%s: unexpected control message(s) was "
                          "encountered", vstr);
            *unexp_cmsg = TRUE;
        }
    }

    if (ip_pktinfo && cmsg == NULL)
    {
        TEST_VERDICT("%s: expected control message was not received",
                     vstr);
    }
    else if (!ip_pktinfo && cmsg != NULL)
    {
        TEST_VERDICT("%s: IP_PKTINFO/IPV6_PKTINFO control message "
                     "was unexpectedly received", vstr);
    }
    else if (cmsg != NULL)
    {
        if (dst_addr->sa_family == AF_INET)
        {
            CHECK_RC(
                sockts_check_in_pktinfo(SOCKTS_PKTINFO(cmsg), dst_addr,
                                        (addr_type == SOCKTS_ADDR_SPEC),
                                        iut_addr, iut_if_index, 0, ""));
        }
        else
        {
            CHECK_RC(
                sockts_check_in6_pktinfo(SOCKTS_PKTINFO6(cmsg), dst_addr,
                                         iut_if_index, 0, ""));
        }
    }

    sockts_free_msghdr(msg);
}

int
main(int argc, char *argv[])
{
    int             i;
    tapi_env_net   *net = NULL;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    struct sockaddr_storage     wildcard_addr;
    struct sockaddr_storage     aux_addr;
    const struct sockaddr      *dst_addr;
    const struct sockaddr      *iut_addr;
    const struct sockaddr      *mcast_addr;
    const struct sockaddr      *iut_addr1;
    const struct sockaddr      *iut_addr2;
    const struct if_nameindex  *iut_if;
    const struct if_nameindex  *tst_if;

    te_bool                     unexp_cmsg_verdict = FALSE;
    int                         opt_val;
    rpc_socket_domain           domain;
    rpc_sockopt                 opt;
    const char                 *opt_name;

    sockts_addr_type            addr_type;
    tarpc_joining_method        method = TARPC_MCAST_ADD_DROP;

    TEST_START;
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_iut);
    TEST_GET_NET(net);
    SOCKTS_GET_ADDR_TYPE(addr_type);
    if (addr_type == SOCKTS_ADDR_SPEC)
    {
        TEST_GET_ADDR(pco_iut, iut_addr1);
        TEST_GET_ADDR(pco_iut, iut_addr2);
        iut_addr = iut_addr1;
    }
    else
    {
        TEST_GET_ADDR(pco_iut, iut_addr);
        if (addr_type == SOCKTS_ADDR_MCAST)
        {
            TEST_GET_ADDR(pco_iut, mcast_addr);
            TEST_GET_MCAST_METHOD(method);
        }
    }
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    switch (addr_type)
    {
        case SOCKTS_ADDR_SPEC:

            dst_addr = iut_addr2;
            break;

        case SOCKTS_ADDR_MCAST:

            dst_addr = mcast_addr;
            break;

        case SOCKTS_ADDR_BCAST:

            if (iut_addr->sa_family == AF_INET6)
                TEST_FAIL("IPv6 does not support broadcast addresses");

            dst_addr = SA(&aux_addr);
            SIN(dst_addr)->sin_family = AF_INET;
            SIN(dst_addr)->sin_addr.s_addr = net->ip4bcast.sin_addr.s_addr;
            SIN(dst_addr)->sin_port = SIN(iut_addr)->sin_port;
            break;

        default:

            TEST_FAIL("Not supported address type");
    }

    if (iut_addr->sa_family == AF_INET)
        opt = RPC_IP_PKTINFO;
    else
        opt = RPC_IPV6_RECVPKTINFO;

    opt_name = sockopt_rpc2str(opt);

    if (addr_type == SOCKTS_ADDR_MCAST && iut_if == tst_if)
    {
        CHECK_RC(tapi_sh_env_set(pco_tst, "EF_FORCE_SEND_MULTICAST", "0",
                                 TRUE, TRUE));
    }

    domain = rpc_socket_domain_by_addr(iut_addr);

    RING("Test params: dst_addr: %s, if_name: %s, if_index: %d",
         te_sockaddr2str(dst_addr), iut_if->if_name, iut_if->if_index);

    TEST_STEP("Create a pair of @c SOCK_DGRAM sockets on @p pco_iut "
              "and @p pco_tst.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind IUT socket to wildcard address.");
    tapi_sockaddr_clone_exact(dst_addr, &wildcard_addr);
    te_sockaddr_set_wildcard(SA(&wildcard_addr));
    rpc_bind(pco_iut, iut_s, SA(&wildcard_addr));

    TEST_STEP("Obtain value of @c IP_PKTINFO/@c IPV6_RECVPKTINFO option "
              "on IUT socket, check that it is @c 0.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_getsockopt(pco_iut, iut_s, opt, &opt_val);
    if (rc != 0)
    {
        TEST_VERDICT("getsockopt(%s) failed with errno %r",
                     opt_name, RPC_ERRNO(pco_iut));
    }
    if (opt_val != 0)
        RING_VERDICT("Default value of %s option is not 0", opt_name);

    if (addr_type == SOCKTS_ADDR_MCAST)
    {
        TEST_STEP("If @p addr_type is @c multicast, set outgoing interface "
                  "for multicast packets to @p tst_if for Tester socket, "
                  "and join IUT socket to a tested multicast group "
                  "according to @p method.");

        sockts_set_multicast_if(pco_tst, tst_s, dst_addr->sa_family,
                                tst_if->if_index);
        rpc_mcast_join(pco_iut, iut_s, dst_addr, iut_if->if_index,
                       method);
    }
    else if (addr_type == SOCKTS_ADDR_BCAST)
    {
        TEST_STEP("If @p addr_type is @c broadcast, set @c SO_BROADCAST on "
                  "Tester socket.");

        rpc_setsockopt_int(pco_tst, tst_s, RPC_SO_BROADCAST, 1);
    }

    TEST_STEP("Set value of @c IP_PKTINFO/@c IPV6_RECVPKTINFO option on "
              "IUT socket to @c 1, check that @b getsockopt() returns "
              "updated value.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s, opt, 1);
    if (rc < 0)
    {
        TEST_VERDICT("Failed to set %s option to 1, errno %r", opt_name,
                     RPC_ERRNO(pco_iut));
    }

    opt_val = 0;
    rpc_getsockopt(pco_iut, iut_s, opt, &opt_val);
    if (opt_val != 1)
    {
        TEST_VERDICT("The value of %s socket option is not "
                     "updated by setsockopt() function", opt_name);
    }

    TEST_STEP("A few times send data from Tester socket to address "
              "determined by @p addr_type. Each time receive data on "
              "IUT and check that @c IP_PKTINFO (@c IPV6_PKTINFO) "
              "control message is retrieved with correct fields values.");

    for (i = 0; i < TST_ITER; i++)
    {
        test_send_recv(pco_iut, iut_s, pco_tst, tst_s, addr_type,
                       dst_addr, iut_addr, iut_if->if_index,
                       TRUE, &unexp_cmsg_verdict,
                       "Checking recvmsg() with enabled option");
    }

    TEST_STEP("Set value of @c IP_PKTINFO/@c IPV6_RECVPKTINFO option on "
              "IUT socket to @c 0.");
    rpc_setsockopt_int(pco_iut, iut_s, opt, 0);

    TEST_STEP("Call @b getsockopt() to check that tested option value was "
              "updated.");
    opt_val = 1;
    rpc_getsockopt(pco_iut, iut_s, opt, &opt_val);
    if (opt_val != 0)
    {
        TEST_VERDICT("The value of %s socket option is not reset to 0 "
                     "by setsockopt() function", opt_name);
    }

    TEST_STEP("Send data from Tester socket to the same address one more "
              "time, check that no control message is retrieved by "
              "@b recvmsg() on IUT socket.");

    unexp_cmsg_verdict = FALSE;
    test_send_recv(pco_iut, iut_s, pco_tst, tst_s, addr_type,
                   dst_addr, iut_addr, iut_if->if_index,
                   FALSE, &unexp_cmsg_verdict,
                   "Checking recvmsg() with disabled option");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
