/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of basic Socket API
 */

/** @page basic-dgram_crd_bound_lb Connect/reconnect/disconnect of datagram socket bound to loopback address
 *
 * @objective Connect/reconnect/disconnect UDP socket bound to loopback
 *            address and check @b getsockname()/getpeername() output.
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_tst
 *              - @ref arg_types_env_peer2peer_ipv6
 *              - @ref arg_types_env_peer2peer_tst_ipv6
 *
 * @par Test sequence:
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "basic/dgram_crd_bound_lb"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;

    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *iut_addr = NULL;

    struct sockaddr_storage name;
    socklen_t               namelen;
    uint16_t                local_port;

    struct sockaddr_storage wild_addr;
    struct sockaddr_storage loop_addr;

    struct sockaddr_storage unspec_addr;
    socklen_t               unspec_addr_len = sizeof(unspec_addr);

    int      iut_s = -1;
    te_bool  reconnect_failed;

    /* Preambule */
    TEST_START;

    RING("%s: start went fine", __FUNCTION__);

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memset(&wild_addr, 0, sizeof(wild_addr));
    wild_addr.ss_family = iut_addr->sa_family;
    te_sockaddr_set_wildcard(SA(&wild_addr));
    te_sockaddr_set_port(SA(&wild_addr), 0);
    memset(&loop_addr, 0, sizeof(loop_addr));
    loop_addr.ss_family = iut_addr->sa_family;
    te_sockaddr_set_loopback(SA(&loop_addr));
    te_sockaddr_set_port(SA(&loop_addr), te_sockaddr_get_port(iut_addr));

    memset(&unspec_addr, 0, unspec_addr_len);
    unspec_addr.ss_family = AF_UNSPEC;

    TEST_STEP("Create @c SOCK_DGRAM socket @b iut_s on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Connect @b iut_s to @b loop_addr.");
    rpc_connect(pco_iut, iut_s, SA(&loop_addr));

    TEST_STEP("Call @b getsockname() on @b iut_s and check that "
              "the function returns "
              "@b loop_addr (not considering port number).");
    namelen = sizeof(name);
    rpc_getsockname(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp_no_ports(
            SA(&loop_addr), sizeof(struct sockaddr_storage),
            SA(&name), namelen) != 0)
        TEST_FAIL("getsockname() returned unexpected address after connect()");
    local_port = te_sockaddr_get_port(CONST_SA(&name));

    TEST_STEP("Call @b getpeername() on @b iut_s and check that "
              "the function returns @b loop_addr");
    namelen = sizeof(name);
    rpc_getpeername(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp(SA(&name), namelen,
                       SA(&loop_addr), sizeof(loop_addr)) != 0)
    {
        ERROR("%d: getpeername() returned address %s",
              __LINE__, te_sockaddr2str(SA(&name)));
        TEST_FAIL("expected one is %s", te_sockaddr2str(SA(&loop_addr)));
    }

    TEST_STEP("Connect @b iut_s to @p tst_addr, check that "
              "@b connect() returns @c -1 and errno is set to EINVAL. "
              "For IPv6 connect should not fail.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (rc == -1)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "connect() failed, but");
        reconnect_failed = TRUE;
    }
    else
    {
        RING_VERDICT("Successfully reconnected to tst_addr");
        reconnect_failed = FALSE;
    }

    TEST_STEP("Call @b getsockname() on @b iut_s and check that "
              "the function returns "
              "@b loop_addr (not considering port number).");
    namelen = sizeof(name);
    rpc_getsockname(pco_iut, iut_s, SA(&name), &namelen);

    if (reconnect_failed &&
        te_sockaddrcmp_no_ports(
            SA(&loop_addr), sizeof(struct sockaddr_storage),
            SA(&name), namelen) != 0)
    {
        TEST_FAIL("getsockname() returned unexpected address %s after "
                  "connect() try");
    }

    TEST_STEP("Call @b getpeername() on @p iut_s and check that "
              "the function returns @b loop_addr "
              "(or IUT unicast address for IPv6).");
    namelen = sizeof(name);
    rpc_getpeername(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp(SA(&name), namelen,
                       reconnect_failed ? SA(&loop_addr) : tst_addr,
                       reconnect_failed ?
                           te_sockaddr_get_size(SA(&loop_addr)) :
                           te_sockaddr_get_size(tst_addr)) != 0)
    {
        TEST_FAIL("getpeername() returned unexpected address after "
                  "connect() try");
    }

    TEST_STEP("Connect @b iut_s with family @c AF_UNSPEC (disconnect).");
    rpc_connect(pco_iut, iut_s, CONST_SA(&unspec_addr));

    TEST_STEP("Call @b getsockname() on @b iut_s and check "
              "that the function returns wildcard address.");
    namelen = sizeof(name);
    rpc_getsockname(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp_no_ports(
            SA(&wild_addr), sizeof(struct sockaddr_storage),
            SA(&name), namelen) != 0)
    {
        TEST_FAIL("getsockname() returned non-zero address "
                  "after disconnect");
    }
    if (te_sockaddr_get_port(CONST_SA(&name)) == 0)
        RING_VERDICT("Disconnect resets local port to zero");
    else if (te_sockaddr_get_port(CONST_SA(&name)) != local_port)
        TEST_VERDICT("Disconnect changes local port to another");

    TEST_STEP("Call @b getpeername() on @b iut_s and check "
              "that it returned @c -1 and @p errno on @p pco_iut "
              "is set to @c ENOTCONN.");
    namelen = sizeof(name);
    RPC_AWAIT_IUT_ERROR(pco_iut);
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
