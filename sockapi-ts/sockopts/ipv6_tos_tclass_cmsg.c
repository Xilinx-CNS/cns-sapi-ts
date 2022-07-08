/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-ipv6_tos_tclass_cmsg Setting DSCP (Type Of Service) with IP_TOS/IPV6_TCLASS option
 *
 * @objective Check possible interactions between @c IP_TOS and @c IPV6_TCLASS
 *            when they are set via socket options and/or cmsg
 *
 * @type conformance
 *
 * @param env               Environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type         IUT socket type:
 *                          - @c udp (connected UDP socket)
 *                          - @c udp_notconn (not connected UDP socket)
 * @param set_sockopt_tclass    If @c TRUE, set @c IPV6_TCLASS to a random value with @b setsockopt
 * @param set_sockopt_tos       If @c TRUE, set @c IP_TOS to a random value with @b setsockopt
 * @param set_cmsg_tclass       If @c TRUE, set @c IPV6_TCLASS to a random value with @b cmsg
 * @param set_cmsg_tos          If @c TRUE, set @c IP_TOS to a random value with @b cmsg
 *
 * @par Test sequence:
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ipv6_tos_tclass_cmsg"

#include "sockapi-test.h"
#include "tapi_tcp.h"
#include "tapi_udp.h"
#include "tapi_ip_common.h"
#include "sockopts_common.h"

static void
build_cmsg(struct cmsghdr *cmsg,
           int cmsg_level, int cmsg_type,
           int cmsg_data)
{
    cmsg->cmsg_level = cmsg_level;
    cmsg->cmsg_type = cmsg_type;
    cmsg->cmsg_len = CMSG_LEN(sizeof(cmsg_data));
    memcpy(CMSG_DATA(cmsg), &cmsg_data, sizeof(cmsg_data));
}

static void
build_cmsg_header(rpc_msghdr *msg,
                  int tos, int tclass)
{
    struct cmsghdr *cmsg = rpc_cmsg_firsthdr(msg);

    if (tos != 0)
    {
        build_cmsg(cmsg, IPPROTO_IP, IP_TOS, tos);
        cmsg = rpc_cmsg_nxthdr(msg, cmsg);
    }

    if (tclass != 0)
        build_cmsg(cmsg, IPPROTO_IPV6, IPV6_TCLASS, tclass);
}

static void
test_send_two_cmsg(rcf_rpc_server *pco_iut,
                   rcf_rpc_server *pco_tst,
                   int iut_s, int tst_s,
                   const struct sockaddr *tst_addr,
                   csap_handle_t csap,
                   int cmsg_tos, int cmsg_tclass,
                   int expected_value,
                   const char *field_name,
                   const char *field_labels,
                   const char *exp_value_name,
                   te_bool is_ipv6,
                   te_bool *test_failed)
{
        rpc_msghdr             *msg;
        ssize_t                 buflen = 256;
        socklen_t               addrlen = te_sockaddr_get_size(tst_addr);
        char                    rx_buf[buflen];
        int                     rc = 0;
        int                     ctrllen = 0;
        int                     control_len = 0;

        if (cmsg_tclass != 0)
        {
            ctrllen++;
            expected_value = is_ipv6 ? cmsg_tclass : expected_value;
        }
        if (cmsg_tos != 0)
        {
            ctrllen++;
            expected_value = is_ipv6 ? expected_value : cmsg_tos;
        }

        control_len = ctrllen * CMSG_SPACE(sizeof(cmsg_tos));

        msg = sockts_make_msghdr(addrlen, 1, &buflen, control_len);
        memset(msg->msg_control, 0, control_len);
        memcpy(msg->msg_name, tst_addr, addrlen);
        msg->msg_cmsghdr_num = ctrllen;

        build_cmsg_header(msg, cmsg_tos, cmsg_tclass);

        rpc_sendmsg(pco_iut, iut_s, msg, 0);

        rc = rpc_recv(pco_tst, tst_s, rx_buf,
                      sizeof(rx_buf), 0);

        if (rc != buflen)
            TEST_VERDICT("Only part of data received");

        if (memcmp(msg->msg_iov->iov_base, rx_buf, buflen))
            TEST_VERDICT("Invalid data received");

        sockts_check_field(pco_tst, field_name, field_labels,
                           exp_value_name, expected_value,
                           "", 0,
                           csap, test_failed, "Test send");
}

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
    int                   iut_s = -1;
    int                   iut_listener = -1;
    int                   tst_s = -1;

    csap_handle_t         csap = CSAP_INVALID_HANDLE;
    te_bool               test_failed = FALSE;

    te_bool set_sockopt_tclass;
    te_bool set_sockopt_tos;
    te_bool set_cmsg_tclass;
    te_bool set_cmsg_tos;

    int sockopt_tclass = 0;
    int sockopt_tos = 0;
    int cmsg_tclass = 0;
    int cmsg_tos = 0;

    int expected_value = 0;

    const char *field_name;
    const char *field_labels;
    const char *exp_value_name;

    te_bool is_ipv6;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(set_sockopt_tclass);
    TEST_GET_BOOL_PARAM(set_sockopt_tos);
    TEST_GET_BOOL_PARAM(set_cmsg_tclass);
    TEST_GET_BOOL_PARAM(set_cmsg_tos);

    TEST_STEP("Generate random IP_TOS and IPV6_TCLASS values. "
              "A new random value will be used for each setting of "
              "IP_TOS/IPV6_TCLASS via @b setsockopt() or cmsg.");
    if (set_sockopt_tclass)
    {
        sockopt_tclass = sockts_random_tclass_or_tos(FALSE);
        RING("IPV6_TCLASS to set with setsockopt: %d", sockopt_tclass);
    }
    if (set_sockopt_tos)
    {
        sockopt_tos = sockts_random_tclass_or_tos(FALSE);
        RING("IP_TOS to set with setsockopt: %d", sockopt_tos);
    }
    if (set_cmsg_tclass)
    {
        cmsg_tclass = sockts_random_tclass_or_tos(FALSE);
        RING("IPV6_TCLASS to send with cmsg: %d", cmsg_tclass);
    }
    if (set_cmsg_tos)
    {
        cmsg_tos = sockts_random_tclass_or_tos(FALSE);
        RING("IP_TOS to send with cmsg: %d", cmsg_tos);
    }

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    TEST_STEP("Create a socket on IUT, choosing its type according to "
              "@p sock_type.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       rpc_sock_type, RPC_PROTO_DEF);

    if (rpc_socket_domain_by_addr(tst_addr) == RPC_PF_INET)
    {
        field_name = "Type Of Service";
        field_labels = "pdus.1.#ip4.type-of-service.plain";
        exp_value_name = "IP_TOS";
        expected_value = sockopt_tos;
        is_ipv6 = FALSE;
    }
    else
    {
        field_name = "Traffic Class";
        field_labels = "pdus.1.#ip6.traffic-class.plain";
        exp_value_name = "IPV6_TCLASS";
        expected_value = sockopt_tclass;
        is_ipv6 = TRUE;
    }

    if (sockopt_tclass != 0 && is_ipv6)
    {
        TEST_STEP("If @p set_sockopt_tclass and IPv6 is in use "
                  "set @c IPV6_TCLASS with @b setsockopt.");
        rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_TCLASS, sockopt_tclass);
    }

    if (sockopt_tos != 0)
    {
        TEST_STEP("If @p set_sockopt_tos "
                  "set @c IP_TOS with @b setsockopt.");
        rpc_setsockopt_int(pco_iut, iut_s, RPC_IP_TOS, sockopt_tos);
    }

    TEST_STEP("Create a peer socket on Tester.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       rpc_sock_type, RPC_PROTO_DEF);

    TEST_STEP("Create a CSAP on Tester to capture packets sent from "
              "IUT.");
    CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                        pco_tst->ta, 0, tst_if->if_name,
                        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                        NULL, NULL, is_ipv6 ? AF_INET6 : AF_INET,
                        (rpc_sock_type == RPC_SOCK_STREAM ?
                            IPPROTO_TCP : IPPROTO_UDP),
                        TAD_SA2ARGS(tst_addr,
                                    iut_addr),
                        &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Establish connection if required by @p sock_type.");
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, FALSE, TRUE, NULL,
                      &iut_s, &tst_s, &iut_listener,
                      SOCKTS_SOCK_FUNC_SOCKET);

    TEST_STEP("Send message with cmsg header build based on "
              "@p set_cmsg_tos and @p set_cmsg_tclass. "
              "Receive it on TST, check that @c IPV6_TCLASS in case of IPv6 "
              "or @c IP_TOS in case of IPv4 are correct.");
    test_send_two_cmsg(pco_iut, pco_tst, iut_s, tst_s,
                       tst_addr, csap, cmsg_tos, cmsg_tclass,
                       expected_value, field_name, field_labels,
                       exp_value_name, is_ipv6, &test_failed);

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
