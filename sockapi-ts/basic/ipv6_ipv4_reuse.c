/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-ipv6_ipv4_reuse Creating IPv6 sockets after closing IPv4 sockets of the same type or vice versa
 *
 * @objective Create IPv4 (IPv6) connected sockets, transmit data over
 *            them, close them and do the same for IPv6 (IPv4) sockets
 *            of the same type. Check that all works OK.
 *
 * @type conformance
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_p2p_ip4_ip6
 * @param sock_type   Socket type:
 *                    - @c udp
 *                    - @c udp_notconn
 *                    - @c tcp_active
 *                    - @c tcp_passive_close
 * @param conns_num   Number of connections (sockets):
 *                    - @c 3
 * @param ipv4_first  If @c TRUE, create IPv4 sockets the first time,
 *                    otherwise create IPv6 sockets firstly.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/ipv6_ipv4_reuse"

#include "sockapi-test.h"

/** A pair of connected sockets. */
typedef struct conn_descr {
    int                       iut_s;      /**< IUT socket */
    int                       tst_s;      /**< Tester socket */
    struct sockaddr_storage   iut_addr;   /**< Address of IUT socket */
    struct sockaddr_storage   tst_addr;   /**< Address of Tester socket */
} conn_descr;

/**
 * Create specified number of pairs of connected sockets and
 * check data transmission over them.
 *
 * @param conns         Pointer to array of conn_descr structures.
 * @param conns_num     Number of connections.
 * @param pco_iut       RPC server on IUT.
 * @param pco_tst       RPC server on Tester.
 * @param iut_addr      Network address on IUT.
 * @param tst_addr      Network address on Tester.
 * @param sock_type     Socket type.
 */
static void
create_check_conns(conn_descr *conns, int conns_num,
                   rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                   const struct sockaddr *iut_addr,
                   const struct sockaddr *tst_addr,
                   sockts_socket_type sock_type)
{
    int i;

    for (i = 0; i < conns_num; i++)
    {
        CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr,
                                     &conns[i].iut_addr));
        CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                     &conns[i].tst_addr));

        /*
         * SOCKTS_CONNECTION() may be used only from main() as
         * it may try to get an address from environment.
         */
        sockts_connection(pco_iut, pco_tst, SA(&conns[i].iut_addr),
                          SA(&conns[i].tst_addr), sock_type,
                          FALSE, FALSE, NULL,
                          &conns[i].iut_s, &conns[i].tst_s, NULL,
                          SOCKTS_SOCK_FUNC_SOCKET);
    }

    for (i = 0; i < conns_num; i++)
    {
        sockts_test_connection_ext(pco_iut, conns[i].iut_s,
                                   pco_tst, conns[i].tst_s,
                                   SA(&conns[i].tst_addr), sock_type);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *tst_addr6 = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *iut_addr6 = NULL;
    const struct sockaddr      *iut_addr = NULL;

    sockts_socket_type    sock_type;
    int                   conns_num;
    conn_descr           *conns;
    te_bool               ipv4_first;
    int                   i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr6);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(conns_num);
    TEST_GET_BOOL_PARAM(ipv4_first);

    CHECK_NOT_NULL(conns = TE_ALLOC(conns_num * sizeof(conn_descr)));

    TEST_STEP("Create @p conns_num IPv4 (if @p ipv4_first is @c TRUE) "
              "or IPv6 (if @p ipv4_first is @c FALSE) sockets on IUT "
              "and their peers on Tester, choosing socket type according "
              "to @p sock_type. Check that data can be transmitted in "
              "both directions between each IUT socket and its Tester "
              "peer.");

    create_check_conns(conns, conns_num, pco_iut, pco_tst,
                       (ipv4_first ? iut_addr : iut_addr6),
                       (ipv4_first ? tst_addr : tst_addr6),
                       sock_type);

    TEST_STEP("Close sockets, firstly closing Tester sockets so that "
              "in case of TCP @c TIME_WAIT state is avoided on IUT.");

    for (i = 0; i < conns_num; i++)
    {
        RPC_CLOSE(pco_tst, conns[i].tst_s);
    }

    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_STREAM)
        TAPI_WAIT_NETWORK;

    for (i = 0; i < conns_num; i++)
    {
        RPC_CLOSE(pco_iut, conns[i].iut_s);
    }

    TEST_STEP("Create again @p conns_num sockets of the same type on IUT "
              "and Tester, but this time if @p ipv4_first is @c TRUE, "
              "create IPv6 sockets, otherwise IPv4 sockets. Check that "
              "data can be transmitted in both directions between every "
              "IUT socket and its Tester peer.");

    create_check_conns(conns, conns_num, pco_iut, pco_tst,
                       (ipv4_first ? iut_addr6 : iut_addr),
                       (ipv4_first ? tst_addr6 : tst_addr),
                       sock_type);

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < conns_num; i++)
    {
        RPC_CLOSE(pco_tst, conns[i].tst_s);
        RPC_CLOSE(pco_iut, conns[i].iut_s);
    }
    free(conns);

    TEST_END;
}
