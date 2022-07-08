/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-ipv6_tclass Setting traffic class with IPV6_TCLASS option
 *
 * @objective Check that if @c IPV6_TCLASS option is set on a socket,
 *            outgoing packets have IPv6 Traffic Class set to
 *            its value.
 *
 * @type conformance
 *
 * @param env           Environment:
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type     IUT socket type:
 *                      - @c udp (connected UDP socket)
 *                      - @c udp_notconn (not connected UDP socket)
 *                      - @c tcp_active (actively established TCP
 *                        connection)
 *                      - @c tcp_passive (passively established TCP
 *                        connection)
 *                      - @c tcp_passive_close (passively established
 *                        TCP connection, listener is closed after
 *                        @b accept())
 * @param with_cmsg     If @c TRUE, IP_TOS would be sent with cmsg,
 *                      otherwise setsockopt would be used
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ipv6_tclass"

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

    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *tst_if = NULL;

    sockts_socket_type    sock_type;
    rpc_socket_type       rpc_sock_type;
    te_bool               with_cmsg;
    int                   iut_s = -1;
    int                   iut_listener = -1;
    int                   tst_s = -1;
    unsigned int          tclass;
    unsigned int          tos;

    csap_handle_t         csap = CSAP_INVALID_HANDLE;
    te_bool               test_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(with_cmsg);

    rpc_sock_type = sock_type_sockts2rpc(sock_type);
    sockts_random_tclass_tos(&tclass, &tos, FALSE);

    TEST_STEP("Create a socket on IUT, choosing its type according to "
              "@p sock_type.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       rpc_sock_type, RPC_PROTO_DEF);

    if (!with_cmsg)
    {
        TEST_STEP("If @p with_cmsg is @c FALSE set @c IPV6_TCLASS option "
                  "to a random value on the IUT socket.");
        rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_TCLASS, tclass);
    }

    TEST_STEP("Create a peer socket on Tester.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       rpc_sock_type, RPC_PROTO_DEF);

    TEST_STEP("Create a CSAP on Tester to capture packets sent from "
              "IUT.");
    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                        pco_tst->ta, 0, tst_if->if_name,
                        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                        NULL, NULL, AF_INET6,
                        (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                        TAD_SA2ARGS(tst_addr,
                                    iut_addr),
                        &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Establish connection if required by @p sock_type. "
              "If @b accept() is called, accepted socket is checked "
              "in the following steps.");
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, FALSE, TRUE, NULL,
                      &iut_s, &tst_s, &iut_listener,
                      SOCKTS_SOCK_FUNC_SOCKET);

    TEST_STEP("Send a few packets from the IUT socket, "
              "if @p with_cmsg is @c TRUE send with sendmsg and set "
              "@c IPV6_TCLASS inside cmsg. Receive "
              "them on peer. Capture packets with CSAP, check "
              "that @b traffic-class field is set to the same value "
              "to which @c IPV6_TCLASS option was set before.");
    sockts_send_check_field_cmsg(pco_iut, pco_tst, iut_s, tst_s,
                                 tst_addr, csap,
                                 "Traffic Class",
                                 "pdus.1.#ip6.traffic-class.plain",
                                 "IPV6_TCLASS", tclass, "IP_TOS", 0,
                                 with_cmsg, IPPROTO_IPV6, IPV6_TCLASS, tclass,
                                 &test_failed,
                                 "Sending data after IPV6_TCLASS is set");

    TEST_STEP("Set @c IP_TOS option on the "
              "IUT socket to a value different from that "
              "which was used for @c IPV6_TCLASS.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_TOS, tos);
    TEST_STEP("Perform sending again in the same way, "
              "check that traffic-class field "
              "has the same value in sent packets.");
    sockts_send_check_field_cmsg(pco_iut, pco_tst, iut_s, tst_s,
                                 tst_addr, csap,
                                 "Traffic Class",
                                 "pdus.1.#ip6.traffic-class.plain",
                                 "IPV6_TCLASS", tclass, "IP_TOS", 0,
                                 with_cmsg, IPPROTO_IPV6, IPV6_TCLASS, tclass,
                                 &test_failed,
                                 "Sending data after setting IP_TOS");

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_listener);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                           csap));

    TEST_END;
}
