/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-default_bind_sendto Default binding during sendto()
 *
 * @objective Check that @b sendto() call on non-bound datagram socket
 *            performs @b bind() for it automatically to system-chosen
 *            unused port and wildcard address.
 *
 * @type Conformance, compatibility
 *
 * @note
 *   This feature is not documented anywhere, but it works for IPv4/TCP
 *   sockets on Linux and BSD socket API implementations.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_tst
 *              - @ref arg_types_env_peer2peer_lo
 *              - @ref arg_types_env_peer2peer_ipv6
 *              - @ref arg_types_env_peer2peer_tst_ipv6
 *              - @ref arg_types_env_peer2peer_lo_ipv6
 *
 * @par Scenario:
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/default_bind_sendto"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    uint8_t                 tx_buf[SOCKTS_MSG_DGRAM_MAX];
    uint8_t                 rx_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t                  len;
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     sock_iut = -1;
    int                     sock_tst = -1;

    const struct sockaddr  *tst_addr;
    int                     af;
    int                     port_rcv;
    int                     port_loc;

    struct sockaddr_storage loc_addr;
    socklen_t               loc_addrlen;

    struct sockaddr_storage rcv_addr;
    socklen_t               rcv_addrlen;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);

    af = tst_addr->sa_family;

    TEST_STEP("Create @c SOCK_DGRAM socket on IUT.");
    sock_iut = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst_addr),
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Create @c SOCK_DGRAM socket on Tester, binding it to "
              "@p tst_addr.");
    sock_tst = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, sock_tst, tst_addr);

    len = rand_range(1, sizeof(tx_buf));
    te_fill_buf(tx_buf, len);

    TEST_STEP("Send some data from IUT socket to @p tst_addr with "
              "@b sendto().");
    RPC_SENDTO(rc, pco_iut, sock_iut, tx_buf, len, 0, tst_addr);

    TEST_STEP("Receive data on Tester socket with @b recvfrom().");

    rcv_addrlen = sizeof(rcv_addr);
    rc = rpc_recvfrom(pco_tst, sock_tst, rx_buf, sizeof(rx_buf), 0,
                      SA(&rcv_addr), &rcv_addrlen);
    if (rcv_addr.ss_family != af)
    {
        TEST_VERDICT("recvfrom() returned unexpected ss_family %d",
                     (int)rcv_addr.ss_family);
    }
    if (rc != (int)len || memcmp(tx_buf, rx_buf, len) != 0)
        TEST_VERDICT("recvfrom() returned unexpected data");

    TEST_STEP("Call @b getsockname() on IUT socket.");

    loc_addrlen = sizeof(loc_addr);
    rpc_getsockname(pco_iut, sock_iut, SA(&loc_addr), &loc_addrlen);

    TEST_STEP("Check that @b getsockname() reported the same port in "
              "address as the one reported by @b recvfrom().");

    if (loc_addr.ss_family != af)
    {
        TEST_VERDICT("getsockname() returned unexpected ss_family %d",
                     (int)loc_addr.ss_family);
    }

    port_rcv = te_sockaddr_get_port(SA(&rcv_addr));
    port_loc = te_sockaddr_get_port(SA(&loc_addr));

    if (port_loc == 0)
        TEST_VERDICT("Zero port was reported by getsockname()");

    if (port_rcv != port_loc)
    {
        TEST_VERDICT("Ports reported by recvfrom() and getsockname() "
                     "are different");
    }

    TEST_STEP("Also check that @b getsockname() returned wildcard "
              "address.");

    if (!te_sockaddr_is_wildcard(SA(&loc_addr)))
        RING_VERDICT("Address returned by getsockname() is not wildcard");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, sock_iut);
    CLEANUP_RPC_CLOSE(pco_tst, sock_tst);

    TEST_END;
}
