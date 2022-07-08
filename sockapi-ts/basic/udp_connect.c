/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-udp_connect UDP sockets re-connect
 *
 * @objective Check behaviour of Socket API in case of multiple calls of
 *            @b connect() method for UDP socket.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/udp_connect"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     sock_iut = -1;
    int                     sock_tst1 = -1;
    int                     sock_tst2 = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    struct sockaddr_storage tst_addr_aux;
    socklen_t               tst_addr_aux_len;

    struct sockaddr_storage rem_addr;
    socklen_t               rem_addrlen;

    te_bool                 sock_rdbl;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    tx_buf = sockts_make_buf_dgram(&buf_len);
    rx_buf = TE_ALLOC(buf_len);

    TEST_STEP("Create @c SOCK_DGRAM socket @b sock_iut on @b pco_iut.");
    sock_iut = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Create @c SOCK_DGRAM socket @b sock_tst1 on @b pco_tst.");
    sock_tst1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("@b bind() @b sock_iut and @b sock_tst1 to "
              "@p iut_addr and @p tst_addr correspondingly");
    rpc_bind(pco_iut, sock_iut, iut_addr);

    rpc_bind(pco_tst, sock_tst1, tst_addr);

    TEST_STEP("Call @b connect(@p tst_addr) on @b sock_iut");
    rpc_connect(pco_iut, sock_iut, tst_addr);

    TEST_STEP("Call @b getpeername() for @b sock_iut, check that it gets same "
              "IP address and port that was specified in @b connect().");
    rem_addrlen = sizeof(rem_addr);
    rpc_getpeername(pco_iut, sock_iut, SA(&rem_addr), &rem_addrlen);

    if (te_sockaddrcmp(tst_addr, te_sockaddr_get_size(tst_addr),
                       SA(&rem_addr), rem_addrlen) != 0)
    {
        TEST_VERDICT("After connect to tst_addr got peer name of socket "
                     "differs from the address passed to connect()");
    }

    TEST_STEP("@b send() data through @b sock_iut and check that this data "
              "is received on @b sock_tst1.");
    RPC_SEND(rc, pco_iut, sock_iut, tx_buf, buf_len, 0);

    rc = rpc_recv(pco_tst, sock_tst1, rx_buf, buf_len, 0);
    SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, buf_len, rc);

    TEST_STEP("Create new socket @b sock_tst2 on @p pco_tst and @b bind() "
              "it to the @p tst_addr with zero port. Obtain it's address "
              "together with automatically assigned port with "
              "@b getsockname(), saving it in @b tst_addr_aux");
    sock_tst2 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    tst_addr_aux_len = te_sockaddr_get_size(tst_addr);
    memcpy(&tst_addr_aux, tst_addr, tst_addr_aux_len);
    te_sockaddr_set_port(SA(&tst_addr_aux), htons(0));

    rpc_bind(pco_tst, sock_tst2, SA(&tst_addr_aux));

    tst_addr_aux_len = sizeof(tst_addr_aux);
    rpc_getsockname(pco_tst, sock_tst2, SA(&tst_addr_aux), &tst_addr_aux_len);

    TEST_STEP("Call @b connect(@b tst_addr_aux) on @b sock_iut.");
    rpc_connect(pco_iut, sock_iut, SA(&tst_addr_aux));

    TEST_STEP("Call @b getpeername() for @b sock_iut, check that it get "
              "same IP address and port that was specified in @b connect().");
    rem_addrlen = sizeof(rem_addr);
    rpc_getpeername(pco_iut, sock_iut, SA(&rem_addr), &rem_addrlen);

    if (te_sockaddrcmp(SA(&tst_addr_aux), tst_addr_aux_len,
                       SA(&rem_addr), rem_addrlen) != 0)
    {
        TEST_VERDICT("After connect to tst_addr_aux got peer name of socket "
                     "differs from the address passed to connect()");
    }

    TEST_STEP("@b send() data through @b sock_iut and check that this data "
              "is received on @b sock_tst2 and is not received on "
              "@b sock_tst1.");
    RPC_SEND(rc, pco_iut, sock_iut, tx_buf, buf_len, 0);

    rc = rpc_recv(pco_tst, sock_tst2, rx_buf, buf_len, 0);
    SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, buf_len, rc);

    RPC_GET_READABILITY(sock_rdbl, pco_tst, sock_tst1, 12);
    if (sock_rdbl)
    {
        TEST_VERDICT("The sock_tst1 became readable after sending data "
                     "to the sock_tst2");
    }

    memset(&tst_addr_aux, 0, sizeof(tst_addr_aux));
    tst_addr_aux.ss_family = AF_UNSPEC;

    TEST_STEP("Call @b connect() on @p sock_iut with @a ss_family set to "
              "@c AF_UNSPEC.");
    RPC_AWAIT_IUT_ERROR(pco_iut);

    /* This call returns zero on Linux Socket API and return @c -1 with */
    /* errno set to @c EAFNOSUPPORT on BSD Socket API. */
    rc = rpc_connect(pco_iut, sock_iut, SA(&tst_addr_aux));

    TEST_STEP("Check @b connect() either succeeds or fails with "
              "errno @c EAFNOSUPPORT.");
    if (rc == -1)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EAFNOSUPPORT,
            "connect() on UDP with AF_UNSPEC family in destination "
            "address returns -1, but");
    }

    TEST_STEP("Call @b getpeername() for @b sock_iut, check that it fails with "
              "@b errno @c ENOTCONN.");
    rem_addrlen = sizeof(rem_addr);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, sock_iut, SA(&rem_addr), &rem_addrlen);
    if (rc != -1)
    {
        TEST_VERDICT("getpeername() succeeded unexpectedly after connecting "
                     "to AF_UNSPEC address");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN,
            "getpeername() after UDP disconnect returns -1, but");
    }

    TEST_STEP("Check that @b send() for @p sock_iut fails with @b errno "
              "@c EDESTADDRREQ.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, sock_iut, tx_buf, buf_len, 0);
    if (rc != -1)
    {
        TEST_VERDICT("send() succeeded unexpectedly after connecting to "
                     "AF_UNSPEC address");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EDESTADDRREQ,
                        "send() after UDP disconnect returns -1, but");
    }

    TEST_STEP("Call @b sendto() for @b sock_iut to the socket address of "
              "@b sock_tst1, check that this data is received on "
              "@b sock_tst1.");
    RPC_SENDTO(rc, pco_iut, sock_iut, tx_buf, buf_len, 0, tst_addr);

    rc = rpc_recv(pco_tst, sock_tst1, rx_buf, buf_len, 0);
    SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, buf_len, rc);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, sock_iut);

    CLEANUP_RPC_CLOSE(pco_tst, sock_tst1);

    CLEANUP_RPC_CLOSE(pco_tst, sock_tst2);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
