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

/* Number of attempts to establish a connection */
#define WAIT_FOR_ACCEPTING 60

/**
 * Try to connect to IUT in loop
 * 
 * @param rpcs      RPC server
 * @param sock      Socket
 * @param iut_addr  Host address to connect it
 * 
 * @return Status code  @c 0 for success, @c -1 in casse of errors
 */
static int
test_connect_loop(rcf_rpc_server *rpcs, int sock,
                  const struct sockaddr *iut_addr)
{
    tarpc_timeval   tv = {0, 0};
    int             i;
    time_t          sec;

    rpc_gettimeofday(rpcs, &tv, NULL);

    for (i = 0; i < WAIT_FOR_ACCEPTING; i++)
    {
        RPC_AWAIT_IUT_ERROR(rpcs);
        rpcs->timeout = 100000;
        if (rpc_connect(rpcs, sock, iut_addr) == 0)
            break;

        if (RPC_ERRNO(rpcs) != RPC_ECONNREFUSED &&
            RPC_ERRNO(rpcs) != RPC_ETIMEDOUT)
        {
            ERROR_VERDICT("connect() fails after %d attempts with errno %s",
                          i, errno_rpc2str(RPC_ERRNO(rpcs)));
            return -1;
        }
        SLEEP(1);
    }

    sec = tv.tv_sec;
    rpc_gettimeofday(rpcs, &tv, NULL);
    sec = tv.tv_sec - sec;

    if (i != 0)
        RING("Connect attempts %d", i);

    if (i == WAIT_FOR_ACCEPTING)
    {
        ERROR_VERDICT("connect() fails after %d seconds with errno %s",
                      sec, errno_rpc2str(RPC_ERRNO(rpcs)));
        return -1;
    }

    else if (i > 0 && i < WAIT_FOR_ACCEPTING)
    {
        if (sec >= 30 && sec < 120)
            RING_VERDICT("Connection has been established after waiting "
                         "30-120 seconds");
        else
            ERROR_VERDICT("Connection has been established after waiting "
                          "%d seconds", sec);
    }

    return 0;
}

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

        if (test_connect_loop(pco_tst, tst_s, iut_addr) != 0)
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
