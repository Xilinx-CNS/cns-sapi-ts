/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2023 Advanced Micro Devices, Inc. */
/*
 * Socket API Test Suite
 * TCP
 */

/** @page tcp-tcp_server_restart Test which simulates TCP server restart
 *
 * @objective Accept many TCP connections, create new RPC server, accept a
 *            new connection there, check it, check unclosed connections on
 *            the original RPC server.
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 * @param accepted_num    Number of accepted connections
 * @param time_wait_num   Number of connections to call close on
 * @param closed_num      Number of connections to close
 *
 * @par Scenario:
 *
 * @author Boris Shleyfman <bshleyfman@oktet.co.il>
 */

#define TE_TEST_NAME  "tcp/tcp_server_restart"

#include "sockapi-test.h"

#define WAIT_ACCEPT_MIN_S   30
#define WAIT_ACCEPT_MAX_S   120

#define CONNECT_AND_ACCEPT(_pco_tst, _pco_iut, _tst_s, _iut_s,          \
                           _iut_addr, _accept_s)                        \
    do {                                                                \
        _tst_s = rpc_socket(_pco_tst,                                   \
                            rpc_socket_domain_by_addr(_iut_addr),       \
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);            \
        if (sockts_connect_retry(_pco_tst, _tst_s, _iut_addr,           \
                                 WAIT_ACCEPT_MIN_S,                     \
                                 WAIT_ACCEPT_MAX_S) != 0)               \
        {                                                               \
            RPC_CLOSE(_pco_tst, _tst_s);                                \
            RPC_CLOSE(_pco_iut, _iut_s);                                \
            TEST_STOP;                                                  \
        }                                                               \
        _accept_s = rpc_accept(_pco_iut, _iut_s, NULL, NULL);           \
    } while(0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rcf_rpc_server        *pco_iut_new = NULL;
    const struct sockaddr *iut_addr;
    int                    accepted_num;
    int                    time_wait_num;
    int                    closed_num;

    int  iut_s = -1;
    int  tst_s = -1;
    int  iut_new_s = -1;
    int  accept_s = -1;
    int  i;
    int *accepted_ss = NULL;
    int *connected_ss = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    /* Find a free port and set iut_addr to IUT's IP address */
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_INT_PARAM(accepted_num);
    TEST_GET_INT_PARAM(time_wait_num);
    TEST_GET_INT_PARAM(closed_num);

    accepted_ss = TE_ALLOC(accepted_num * sizeof(int));
    connected_ss = TE_ALLOC(accepted_num * sizeof(int));

    TEST_STEP("Create listening socket.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_REUSEADDR, 1);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Accept @p accepted_num connections.");
    for (i = 0; i < accepted_num; i++)
    {
        CONNECT_AND_ACCEPT(pco_tst, pco_iut, tst_s, iut_s, iut_addr,
                           accept_s);
        connected_ss[i] = tst_s;
        accepted_ss[i] = accept_s;
    }

    TEST_STEP("Close @p time_wait_num of accepted sockets on IUT to achieve"
              " TIME_WAIT state.");
    for (i = 0; i < time_wait_num; i++)
    {
        RPC_CLOSE(pco_iut, accepted_ss[i]);
        TAPI_WAIT_NETWORK;
        RPC_CLOSE(pco_tst, connected_ss[i]);
    }

    TEST_STEP("Close @p closed_num of connected sockets on Tester to"
              " achieve CLOSED state.");
    for (i = time_wait_num;
         i < time_wait_num + closed_num && i < accepted_num;
         i++)
    {
        RPC_CLOSE(pco_tst, connected_ss[i]);
        TAPI_WAIT_NETWORK;
        RPC_CLOSE(pco_iut, accepted_ss[i]);
    }

    TEST_STEP("Close listening socket.");
    RPC_CLOSE(pco_iut, iut_s);

    TEST_STEP("Create new RPC server.");
    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "iut_new", &pco_iut_new));
    CHECK_RC(rcf_rpc_setlibname(pco_iut_new, pco_iut->nv_lib));

    TEST_STEP("Create a listening socket on the new RPC server using the"
              " port that was used on the original IUT RPC server.");
    iut_new_s = rpc_socket(pco_iut_new, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_iut_new, iut_new_s, RPC_SO_REUSEADDR, 1);
    rpc_bind(pco_iut_new, iut_new_s, iut_addr);
    rpc_listen(pco_iut_new, iut_new_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Accept connection on the new RPC server and verify its"
              " connectivity.");
    CONNECT_AND_ACCEPT(pco_tst, pco_iut_new, tst_s, iut_new_s, iut_addr,
                       accept_s);
    sockts_test_connection(pco_iut_new, accept_s, pco_tst, tst_s);

    TEST_STEP("Check the connectivity of unclosed connections on the"
              " original IUT RPC server.");
    for (i = time_wait_num + closed_num; i < accepted_num; i++)
    {
        sockts_test_connection(pco_iut, accepted_ss[i], pco_tst,
                               connected_ss[i]);
    }

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < accepted_num; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, accepted_ss[i]);
        CLEANUP_RPC_CLOSE(pco_tst, connected_ss[i]);
    }
    CLEANUP_RPC_CLOSE(pco_iut_new, accept_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut_new, iut_new_s);
    if (pco_iut_new != NULL)
    {
        CHECK_RC(rcf_rpc_server_destroy(pco_iut_new));
    }
    free(accepted_ss);
    free(connected_ss);
    TEST_END;
}
