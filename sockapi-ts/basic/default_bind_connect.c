/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-default_bind_connect Default bind() during connect()
 *
 * @objective Check that @b connect() call for non-bound socket performs
 *            @b bind() for it automatically to system-chosen unused port and
 *            appropriate IP address.
 *
 * @type Conformance, compatibility
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 *                  - @ref arg_types_env_peer2peer_ipv6
 *                  - @ref arg_types_env_peer2peer_tst_ipv6
 *                  - @ref arg_types_env_peer2peer_lo_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Scenario:
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/default_bind_connect"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;

    int                     sock_iut = -1;
    int                     sock_tst = -1;
    int                     sock_acc = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    struct sockaddr_storage loc_addr;
    socklen_t               loc_addrlen;

    struct sockaddr_storage rcv_addr;
    socklen_t               rcv_addrlen;

    unsigned int            loc_port;
    unsigned int            rcv_port;

    rpc_socket_type         sock_type;
    te_bool                 test_failed = FALSE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Create a socket on IUT of type @p sock_type, do not "
              "bind it to any address. Socket domain should match "
              "address family of @p tst_addr.");
    sock_iut = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst_addr),
                          sock_type, RPC_PROTO_DEF);

    TEST_STEP("Create a socket on Tester of type @p sock_type, bind it "
              "to @p tst_addr.");
    sock_tst = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                          sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, sock_tst, tst_addr);

    TEST_STEP("If TCP sockets are tested, call @b listen() on Tester "
              "socket.");
    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_tst, sock_tst, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Call @b connect(@p tst_addr) on IUT socket.");
    rpc_connect(pco_iut, sock_iut, tst_addr);

    TEST_STEP("Retrieve address to which IUT socket was bound "
              "automatically due to @b connect() with @b getsockname().");
    loc_addrlen = sizeof(loc_addr);
    rpc_getsockname(pco_iut, sock_iut, SA(&loc_addr), &loc_addrlen);

    if (loc_addr.ss_family != tst_addr->sa_family)
    {
        TEST_VERDICT("getsockname() retured address with unexpected "
                     "family");
    }

    TEST_STEP("Check that retrieved address is not wildcard and port "
              "is not zero.");

    loc_port = te_sockaddr_get_port(SA(&loc_addr));

    if (te_sockaddr_is_wildcard(SA(&loc_addr)))
    {
        ERROR_VERDICT("getsockname() returned wildcard address");
        test_failed = TRUE;
    }
    if (loc_port == 0)
    {
        ERROR_VERDICT("getsockname() returned zero port");
        test_failed = TRUE;
    }

    TEST_STEP("If IPv6 is checked, check that retrieved address "
              "is not link-local.");

    if (loc_addr.ss_family == AF_INET6)
    {
        if (IN6_IS_ADDR_LINKLOCAL(&SIN6(&loc_addr)->sin6_addr))
        {
            ERROR_VERDICT("getsockname() returned link-local IPv6 "
                          "address");
            test_failed = TRUE;
        }
    }

    TEST_STEP("If TCP sockets are tested, call @b accept() on Tester "
              "socket to get address of IUT socket from the peer. "
              "Otherwise send some data from IUT socket and obtain "
              "peer address from @b recvfrom().");

    if (sock_type == RPC_SOCK_STREAM)
    {
        rcv_addrlen = sizeof(rcv_addr);
        sock_acc = rpc_accept(pco_tst, sock_tst, SA(&rcv_addr), &rcv_addrlen);
    }
    else
    {
        uint8_t       tx_buf[SOCKTS_MSG_DGRAM_MAX];
        uint8_t       rx_buf[SOCKTS_MSG_DGRAM_MAX];
        size_t        len;

        len = rand_range(1, sizeof(tx_buf));
        te_fill_buf(tx_buf, len);
        RPC_SEND(rc, pco_iut, sock_iut, tx_buf, len, 0);

        rcv_addrlen = sizeof(rcv_addr);
        rc = rpc_recvfrom(pco_tst, sock_tst, rx_buf, sizeof(rx_buf), 0,
                          SA(&rcv_addr), &rcv_addrlen);
        if (rc != (int)len || memcmp(tx_buf, rx_buf, len) != 0)
        {
            ERROR_VERDICT("recvfrom() returned unexpected data");
            test_failed = TRUE;
        }
    }

    TEST_STEP("Check that peer address obtained on Tester is the same "
              "as address returned by @b getsockname() on IUT.");

    if (te_sockaddrcmp_no_ports(SA(&loc_addr), loc_addrlen,
                                SA(&rcv_addr), rcv_addrlen) != 0)
    {
        ERROR_VERDICT("Address retrieved by getsockname() does not "
                      "match address retrieved by accept() or "
                      "recvfrom() on peer");
        test_failed = TRUE;
    }

    rcv_port = te_sockaddr_get_port(SA(&rcv_addr));
    if (loc_port != rcv_port)
    {
        ERROR_VERDICT("Port retrieved by getsockname() does not "
                      "match port retrieved by accept() or "
                      "recvfrom() on peer");
        test_failed = TRUE;
    }

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, sock_iut);

    CLEANUP_RPC_CLOSE(pco_tst, sock_tst);

    CLEANUP_RPC_CLOSE(pco_tst, sock_acc);

    TEST_END;
}

