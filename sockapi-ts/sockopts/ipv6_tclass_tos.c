/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-ipv6_tclass_tos Using IPV6_TCLASS and IP_TOS on the same socket
 *
 * @objective Check that if both @c IPV6_TCLASS and @c IP_TOS are set to
 *            different values on an IPv6 socket, then if the socket is
 *            used to send data to IPv4 destination, TOS field is set to
 *            the value of @c IP_TOS, and if the socket is used to send
 *            data to IPv6 destination, Traffic Class field is set to the
 *            value of @c IPV6_TCLASS.
 *
 * @type conformance
 *
 * @param env             Environment:
 *                        - @ref arg_types_env_p2p_ip4_ip6
 * @param sock_type       IUT socket type:
 *                        - @c udp (connected UDP socket)
 *                        - @c udp_notconn (not connected UDP socket)
 *                        - @c tcp_active (actively established TCP
 *                          connection)
 *                        - @c tcp_passive (passively established TCP
 *                          connection)
 *                        - @c tcp_passive_close (passively established
 *                          TCP connection, listener is closed after
 *                          @b accept())
 * @param precedence_bits   If @c TRUE, set IP precedence bits (3 most
 *                          significant ones) to nonzero for @c IP_TOS;
 *                          otherwise set them to zero
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ipv6_tclass_tos"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "tapi_udp.h"
#include "tapi_ip_common.h"
#include "sockopts_common.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr     *tst_addr6 = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *iut_addr6 = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct if_nameindex *tst_if = NULL;

    sockts_socket_type    sock_type;
    rpc_socket_type       rpc_sock_type;
    te_bool               precedence_bits;

    struct sockaddr_storage bind_addr1;
    struct sockaddr_storage bind_addr2;
    struct sockaddr_storage src_addr1;
    struct sockaddr_storage src_addr2;
    struct sockaddr_storage dst_addr1;
    struct sockaddr_storage dst_addr2;

    int   iut_s1 = -1;
    int   iut_s2 = -1;
    int   tst_s1 = -1;
    int   tst_s2 = -1;
    int   iut_listener = -1;
    int   tst_listener1 = -1;
    int   tst_listener2 = -1;

    unsigned int tclass = 0;
    unsigned int tos = 0;
    te_bool      test_failed = FALSE;

    csap_handle_t         csap_ip6 = CSAP_INVALID_HANDLE;
    csap_handle_t         csap_ip4 = CSAP_INVALID_HANDLE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, tst_addr6);
    TEST_GET_BOOL_PARAM(precedence_bits);

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    tapi_sockaddr_clone_exact(iut_addr6, &src_addr1);
    tapi_sockaddr_clone_exact(iut_addr, &src_addr2);
    if (sock_type != SOCKTS_SOCK_TCP_ACTIVE)
    {
        te_sockaddr_set_port(SA(&src_addr2),
                             te_sockaddr_get_port(SA(&src_addr1)));
    }

    tapi_sockaddr_clone_exact(SA(&src_addr1), &bind_addr1);
    te_sockaddr_set_wildcard(SA(&bind_addr1));

    tapi_sockaddr_clone_exact(SA(&bind_addr1), &bind_addr2);
    te_sockaddr_set_port(SA(&bind_addr2),
                         te_sockaddr_get_port(SA(&src_addr2)));

    tapi_sockaddr_clone_exact(tst_addr6, &dst_addr1);
    tapi_sockaddr_clone_exact(tst_addr, &dst_addr2);
    te_sockaddr_ip4_to_ip6_mapped(SA(&dst_addr2));

    TEST_STEP("Create two CSAPs on Tester - one for capturing IPv6 packets "
              "and another one for capturing IPv4 packets.");

    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                        pco_tst->ta, 0, tst_if->if_name,
                        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                        NULL, NULL, AF_INET6,
                        (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                        TAD_SA2ARGS(tst_addr6,
                                    SA(&src_addr1)),
                        &csap_ip6));

    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                        pco_tst->ta, 0, tst_if->if_name,
                        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                        NULL, NULL, AF_INET,
                        (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                        TAD_SA2ARGS(tst_addr,
                                    SA(&src_addr2)),
                        &csap_ip4));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_ip6, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_ip4, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Create two peer sockets on Tester, choosing their type "
              "according to @p sock_type: IPv6 peer bound to "
              "@p tst_addr6 (@b tst_s1) and IPv4 peer bound to "
              "@p tst_addr (@b tst_s2).");

    tst_s1 = rpc_socket(pco_tst, RPC_PF_INET6, rpc_sock_type,
                        RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s1, tst_addr6);

    tst_s2 = rpc_socket(pco_tst, RPC_PF_INET, rpc_sock_type,
                        RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s2, tst_addr);

    TEST_STEP("Create an IPv6 socket on IUT, choosing its type according "
              "to @p sock_type; @b bind() it to wildcard address, "
              "and set @c IPV6_TCLASS and @c IP_TOS socket options for it "
              "to different values.");

    iut_s1 = rpc_socket(pco_iut, RPC_PF_INET6,
                        rpc_sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s1, SA(&bind_addr1));

    sockts_random_tclass_tos(&tclass, &tos, precedence_bits);
    rpc_setsockopt_int(pco_iut, iut_s1, RPC_IPV6_TCLASS, tclass);
    rpc_setsockopt_int(pco_iut, iut_s1, RPC_IP_TOS, tos);

    TEST_STEP("If required by @b sock_type, establish connection:");
    if (sock_type == SOCKTS_SOCK_TCP_PASSIVE ||
        sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL)
    {
        TEST_SUBSTEP("In case of passive TCP connection establishment "
                     "call @b listen() on the IUT socket, @b connect() "
                     "from peer sockets on Tester, @b accept() "
                     "connections on IUT. Save the accepted socket "
                     "connected to @b tst_s1 in @b iut_s1, and the "
                     "accepted socket connected to @b tst_s2 in "
                     "@b iut_s2.");

        iut_listener = iut_s1;
        iut_s1 = -1;
        rpc_listen(pco_iut, iut_listener, -1);

        rpc_connect(pco_tst, tst_s1, SA(&src_addr1));
        RPC_AWAIT_ERROR(pco_iut);
        iut_s1 = rpc_accept(pco_iut, iut_listener, NULL, NULL);
        if (iut_s1 < 0)
        {
            TEST_VERDICT("accept() for IPv6 connection failed with errno %r",
                         RPC_ERRNO(pco_iut));
        }

        rpc_connect(pco_tst, tst_s2, SA(&src_addr2));
        RPC_AWAIT_ERROR(pco_iut);
        iut_s2 = rpc_accept(pco_iut, iut_listener, NULL, NULL);
        if (iut_s2 < 0)
        {
            TEST_VERDICT("accept() for IPv4 connection failed with errno %r",
                         RPC_ERRNO(pco_iut));
        }

        if (sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL)
            RPC_CLOSE(pco_iut, iut_listener);
    }
    else if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
    {
        TEST_SUBSTEP("In case of active TCP connection establishment, "
                     "call @b listen() on Tester sockets. Create "
                     "the second IUT IPv6 socket of the same type, "
                     "@b bind() it to wildcard address, set "
                     "@c IPV6_TCLASS and @c IPV6_TOS to the same "
                     "values on it. @b connect() from the first IUT "
                     "socket (@b iut_s1) to @b tst_s1, and from the "
                     "second IUT socket (@b iut_s2) to @b tst_s2. "
                     "@b accept() connections on Tester.");

        rpc_listen(pco_tst, tst_s1, -1);
        rpc_listen(pco_tst, tst_s2, -1);

        iut_s2 = rpc_socket(pco_iut, RPC_PF_INET6,
                            rpc_sock_type, RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s2, SA(&bind_addr2));

        rpc_setsockopt_int(pco_iut, iut_s2, RPC_IPV6_TCLASS, tclass);
        rpc_setsockopt_int(pco_iut, iut_s2, RPC_IP_TOS, tos);

        rpc_connect(pco_iut, iut_s1, SA(&dst_addr1));
        tst_listener1 = tst_s1;
        tst_s1 = rpc_accept(pco_tst, tst_listener1, NULL, NULL);

        rpc_connect(pco_iut, iut_s2, SA(&dst_addr2));
        tst_listener2 = tst_s2;
        tst_s2 = rpc_accept(pco_tst, tst_listener2, NULL, NULL);
    }
    else
    {
        TEST_SUBSTEP("In case of UDP, let @b iut_s2 = @b iut_s1 refer "
                     "to the same already created IUT socket.");
        iut_s2 = iut_s1;
    }

    TEST_STEP("Send data from @b iut_s1 to @b tst_addr6. Receive and check "
              "data on @b tst_s1. Check that in all IUT packets captured "
              "by CSAP the Traffic Class field is set to the value of "
              "@c IPV6_TCLASS socket option.");

    if (sock_type == SOCKTS_SOCK_UDP)
        rpc_connect(pco_iut, iut_s1, SA(&dst_addr1));
    sockts_send_check_field(pco_iut, iut_s1, pco_tst, tst_s1,
                            sock_type, SA(&dst_addr1),
                            "Traffic Class",
                            "pdus.1.#ip6.traffic-class.plain",
                            "IPV6_TCLASS", tclass,
                            "IP_TOS", tos,
                            csap_ip6, &test_failed,
                            "Sending to IPv6 destination");

    TEST_STEP("Send data from @b iut_s2 to @b tst_addr. Receive and check "
              "data on @b tst_s2. Check that in all IUT packets captured "
              "by CSAP the TOS field is set to the value of "
              "@c IP_TOS socket option.");

    if (sock_type == SOCKTS_SOCK_UDP)
        rpc_connect(pco_iut, iut_s2, SA(&dst_addr2));
    sockts_send_check_field(pco_iut, iut_s2, pco_tst, tst_s2,
                            sock_type, SA(&dst_addr2),
                            "Type Of Service",
                            "pdus.1.#ip4.type-of-service.plain",
                            "IP_TOS", tos,
                            "IPV6_TCLASS", tclass,
                            csap_ip4, &test_failed,
                            "Sending to IPv4 destination");

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (iut_s2 != iut_s1)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_listener);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_listener1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_listener2);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                           csap_ip6));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                           csap_ip4));

    TEST_END;
}
