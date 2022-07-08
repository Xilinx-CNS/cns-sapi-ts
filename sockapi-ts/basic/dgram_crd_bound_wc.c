/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of basic Socket API
 */

/** @page basic-dgram_crd_bound_wc Connect/reconnect/disconnect UDP socket bound to wildcard address
 *
 * @objective Connect/reconnect/disconnect UDP socket bound to wildcard
 *            address and check @b getsockname()/getpeername() output.
 *
 * @type conformance
 *
 * @param env   Testing environment:
                - @ref arg_types_env_two_nets_all
 *
 * @par Test sequence:
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "basic/dgram_crd_bound_wc"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst1 = NULL;
    rcf_rpc_server    *pco_tst2 = NULL;

    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;

    struct sockaddr_storage wild_addr;

    struct sockaddr_storage name;
    socklen_t               namelen = sizeof(name);

    struct sockaddr        unspec_addr;
    socklen_t              unspec_addr_len = sizeof(unspec_addr);

    int      iut_s = -1;

    /* Preambule */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR_NO_PORT(iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    memset(&unspec_addr, 0, unspec_addr_len);
    unspec_addr.sa_family = AF_UNSPEC;

    memset(&wild_addr, 0, sizeof(wild_addr));
    wild_addr.ss_family = iut_addr1->sa_family;
    te_sockaddr_set_wildcard(SA(&wild_addr));
    te_sockaddr_set_port(SA(&wild_addr), te_sockaddr_get_port(iut_addr1));
    te_sockaddr_set_port(SA(iut_addr2), te_sockaddr_get_port(iut_addr1));

    TEST_STEP("Create @c SOCK_DGRAM socket @b iut_s on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind @b iut_s to wildcard address.");
    rpc_bind(pco_iut, iut_s, SA(&wild_addr));

    TEST_STEP("Connect @b iut_s to @p tst1_addr.");
    rpc_connect(pco_iut, iut_s, tst1_addr);

    TEST_STEP("Call @b getsockname() on @b iut_s and check that "
              "the function returns @p iut_addr1.");
    namelen = sizeof(name);
    rpc_getsockname(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp(SA(&name), namelen,
                       iut_addr1, te_sockaddr_get_size(iut_addr1)) != 0)
        TEST_FAIL("getsockname() returned unexpected address");

    TEST_STEP("Call @b getpeername() on @b iut_s and check that "
              "the function returns @p tst1_addr.");
    namelen = sizeof(name);
    rpc_getpeername(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp(SA(&name), namelen,
                       tst1_addr, te_sockaddr_get_size(tst1_addr)) != 0)
        TEST_FAIL("getpeername() returned unexpected address");

    TEST_STEP("Connect @b iut_s to @p tst2_addr.");
    rpc_connect(pco_iut, iut_s, tst2_addr);

    TEST_STEP("Call @b getsockname() on @b iut_s and check that "
              "the function returns address @p iut_addr1.");
    namelen = sizeof(name);
    rpc_getsockname(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp(SA(&name), namelen,
                       iut_addr1, te_sockaddr_get_size(iut_addr1)) == 0)
    {
        RING_VERDICT("Reconnect to the peer from another subnet does "
                     "not change socket local address");
    }
    else if (te_sockaddrcmp(SA(&name), namelen,
                            iut_addr2, te_sockaddr_get_size(iut_addr2)) == 0)
    {
        RING_VERDICT("Reconnect to the peer from another subnet changes "
                     "socket local address to the address from the subnet");
    }
    else
    {
        TEST_VERDICT("Reconnect changes socket local address in "
                     "unexpected way");
    }

    TEST_STEP("Call @b getpeername() on @b iut_s and check that "
              "the function returns address @p tst2_addr.");
    namelen = sizeof(name);
    rpc_getpeername(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp(SA(&name), namelen,
                       tst2_addr, te_sockaddr_get_size(tst2_addr)) != 0)
    {
        TEST_FAIL("getpeername() returned unexpected address after "
                  "second connect()");
    }

    TEST_STEP("Connect @b iut_s with family @c AF_UNSPEC (disconnect).");
    rpc_connect(pco_iut, iut_s, &unspec_addr);

    TEST_STEP("Call @b getsockname() on @b iut_s and check "
              "thet the function returns wildcard address.");
    namelen = sizeof(name);
    rpc_getsockname(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp_no_ports(SA(&wild_addr), sizeof(struct sockaddr_storage),
                                SA(&name), namelen))
    {
        TEST_FAIL("getsockname() returned non-zero address "
                  "after disconnect");
    }
    if (te_sockaddr_get_port(CONST_SA(&name)) == 0)
    {
        RING_VERDICT("Disconnect resets local port to zero");
    }
    else if (te_sockaddr_get_port(CONST_SA(&name)) !=
             te_sockaddr_get_port(SA(&wild_addr)))
    {
        TEST_VERDICT("Disconnect changes local port to another");
    }

    TEST_STEP("Call @b getpeername() on @b iut_s and check "
              "that it returned @c -1 and @p errno on @p pco_iut "
              "is set to @c ENOTCONN.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    namelen = sizeof(name);
    rc = rpc_getpeername(pco_iut, iut_s, SA(&name), &namelen);
    if (rc != -1)
        TEST_FAIL("getpeername() is expected to return -1");
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN,
                        "getpeername() returned -1, but");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
