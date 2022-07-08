/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-ipv6_send_ip Sending data from IPv6 socket to IPv6 and IPv4 destinations
 *
 * @objective Check that UDP IPv6 socket bound to wildcard address can send
 *            data both to IPv6 and IPv4 destinations.
 *
 * @type Conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_p2p_ip4_ip6
 * @param ipv4_mapped   If @c TRUE, send data to IPv4-mapped IPv6 address
 *                      instead of IPv4 address.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/ipv6_send_ip"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *iut_addr6 = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr6 = NULL;
    const struct sockaddr      *tst_addr = NULL;
    int                         iut_s6 = -1;
    int                         tst_s6 = -1;
    int                         tst_s4 = -1;
    int                         opt_val;
    te_bool                     ipv4_mapped;
    unsigned int                i;

    struct sockaddr_storage iut_bind_addr6;
    struct sockaddr_storage iut_src_addr;
    struct sockaddr_storage tst_dst_addr;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr6);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(ipv4_mapped);

    tapi_sockaddr_clone_exact(iut_addr6, &iut_bind_addr6);
    te_sockaddr_set_wildcard(SA(&iut_bind_addr6));

    tapi_sockaddr_clone_exact(iut_addr, &iut_src_addr);
    SIN(&iut_src_addr)->sin_port = CONST_SIN6(iut_addr6)->sin6_port;

    tapi_sockaddr_clone_exact(tst_addr, &tst_dst_addr);
    if (ipv4_mapped)
        CHECK_RC(te_sockaddr_ip4_to_ip6_mapped(SA(&tst_dst_addr)));

    TEST_STEP("Create IPv6 datagram socket on IUT, disable @c IPV6_V6ONLY "
              "option for it and bind it to wildcard address.");

    iut_s6 = rpc_socket(pco_iut, RPC_PF_INET6, RPC_SOCK_DGRAM,
                        RPC_PROTO_DEF);

    opt_val = 0;
    rpc_setsockopt(pco_iut, iut_s6, RPC_IPV6_V6ONLY, &opt_val);

    rpc_bind(pco_iut, iut_s6, SA(&iut_bind_addr6));

    TEST_STEP("Create IPv6 and IPv4 sockets on Tester, bind them to "
              "@p tst_addr6 and @p tst_addr.");

    tst_s6 = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_DGRAM,
                                        RPC_PROTO_DEF, FALSE,
                                        FALSE, tst_addr6);
    tst_s4 = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_DGRAM,
                                        RPC_PROTO_DEF, FALSE,
                                        FALSE, tst_addr);

    /*
     * Unfortunately Doxygen does not create a reference for a constant
     * defined in test, so it makes no sense to define the number here.
     */
    TEST_STEP("Do the following steps 5 times:");
    for (i = 0; i < 5; i++)
    {
        TEST_SUBSTEP("Send data from IUT socket to @p tst_addr6, check "
                     "that IPv6 socket on Tester receives data from IPv6 "
                     "IUT address.");

        CHECK_RC(sockts_test_send(pco_iut, iut_s6, pco_tst, tst_s6,
                                  iut_addr6, tst_addr6, RPC_PF_INET6, TRUE,
                                  "Sending to IPv6 peer"));

        TEST_SUBSTEP("Send data from IUT socket to @p tst_addr or to "
                     "corresponding IPv4-mapped IPv6 address (if "
                     "@p ipv4_mapped is @c TRUE). Check that IPv4 socket "
                     "on Tester receives data from IPv4 IUT address.");

        CHECK_RC(sockts_test_send(pco_iut, iut_s6, pco_tst, tst_s4,
                                  SA(&iut_src_addr), SA(&tst_dst_addr),
                                  RPC_PF_INET, TRUE,
                                  "Sending to IPv4 peer"));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s6);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s6);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s4);

    TEST_END;
}
