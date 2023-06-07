/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-accept_multiple Socket accepting ability robustness
 *
 * @objective Create many TCP connections, restart RPC servers, try to make
 *            a new TCP connection.
 *
 * @type conformance, robustness
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_ipv6
 * @param connections   Connections number:
 *                      - 200
 *                      - 2000
 *
 * @par Test sequence:
 * -# Create socket on IUT. Set @c SO_REUSEADDR option for it, bind it to
 *    @p iut_addr, listen for connections on a socket.
 * -# Create sockets on TESTER and make TCP connections with IUT. Maximum
 *    connections number is @p connections.
 * -# Restart IUT and TESTER RPC servers (don't close sockets).
 * -# Create again socket for listening on IUT.
 * -# Create socket on TESTER and try to connect to IUT during some time.
 * 
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/accept_multiple"

#include "sockapi-test.h"

#define WAIT_ACCEPT_MIN_S   30
#define WAIT_ACCEPT_MAX_S   120

/**
 * Create sockets and connect IUT and TST via TCP @p connections times
 * 
 * @param pco_iut       IUT RPC server
 * @param pco_tst       Tester RPC server
 * @param iut_addr      IUT address
 * @param connections   Connections number
 * @param close_sockets @c TRUE to close opened sockets
 */
static void
test_multiple_connection(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                         const struct sockaddr *iut_addr, int connections,
                         te_bool close_sockets)
{
    int iut_s = -1;
    int tst_s;
    int accept_s = -1;
    int i;
    int val = 1;

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_REUSEADDR, &val);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    for (i= 0; i < connections; i++)
    {
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

        if (sockts_connect_retry(pco_tst, tst_s, iut_addr,
                                 WAIT_ACCEPT_MIN_S, WAIT_ACCEPT_MAX_S) != 0)
        {
            RPC_CLOSE(pco_tst, tst_s);
            RPC_CLOSE(pco_iut, iut_s);
            TEST_STOP;
        }

        RPC_AWAIT_IUT_ERROR(pco_iut);
        pco_iut->timeout = 100000;
        if ((accept_s = rpc_accept(pco_iut, iut_s, NULL, NULL)) < 0)
        {
            CHECK_RPC_ERRNO_NOEXIT(pco_iut, RPC_EMFILE, val,
                                   "accept() returns -1, but");
            break;
        }

        if (close_sockets)
        {
            RPC_CLOSE(pco_iut, accept_s);
            RPC_CLOSE(pco_tst, tst_s);
        }
    }

    if (close_sockets)
        RPC_CLOSE(pco_iut, iut_s);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr;
    int                    connections;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_INT_PARAM(connections);

    test_multiple_connection(pco_iut, pco_tst, iut_addr, connections,
                             FALSE);
    CHECK_RC(rcf_rpc_server_restart(pco_iut));
    CHECK_RC(rcf_rpc_server_restart(pco_tst));

    test_multiple_connection(pco_iut, pco_tst, iut_addr, 1, TRUE);

    TEST_SUCCESS;

cleanup:
    TEST_END;
}
