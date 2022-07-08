/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-three_pairs_three_stacks Multicast packets receiving from three pairs of stacks from three different stacks
 *
 * @objective Check possibility to receive multicast packets on three pairs
 * `          of stacks from three different stacks
 *
 * @type Conformance.
 *
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on Tester
 * @param tst_addr             Tester address
 * @param mcast_addr           Multicast address/es
 * @param iut_if               Interface on IUT
 * @param tst_if               Interface on Tester
 * @param packet_number        Number of datagrams to send for reliability.
 * @param sock_func            Socket creation function.
 * 
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/three_pairs_three_stacks"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#include "onload.h"

#include "extensions.h"

#define DATA_BULK 512
#define MAX_SOCK_NUM 10

#define TWO_SOCKS_IN_STACK(_rpcs, _sock1, _sock2, _addr4bind, _maddr, _name) \
do {                                                                    \
    int opt_val = 1;                                                    \
                                                                        \
    rpc_onload_set_stackname(pco_iut,                                   \
                             ONLOAD_ALL_THREADS,                        \
                             ONLOAD_SCOPE_GLOBAL,                       \
                             _name);                                    \
    _sock1 = sockts_socket(sock_func, _rpcs,                            \
                           rpc_socket_domain_by_addr(_addr4bind),       \
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);            \
    rpc_setsockopt(_rpcs, _sock1, RPC_SO_REUSEADDR, &opt_val);          \
    rpc_bind(_rpcs, _sock1, _addr4bind);                                \
    rpc_mcast_join(_rpcs, _sock1, _maddr, iut_if->if_index,             \
                   method);                                             \
    _sock2 = sockts_socket(sock_func, _rpcs,                            \
                           rpc_socket_domain_by_addr(_addr4bind),       \
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);            \
    rpc_setsockopt(_rpcs, _sock2, RPC_SO_REUSEADDR, &opt_val);          \
    rpc_bind(_rpcs, _sock2, _addr4bind);                                \
    rpc_mcast_join(_rpcs, _sock2, _maddr, iut_if->if_index,             \
                   method);                                             \
} while(0);

#define CHECK_ACC(_pco, _socks, _snum, _maddr, _verdict) \
do {                                                                 \
    mcast_listen_start(pco_iut, listener);                           \
                                                                     \
    for (j = 0; j < packet_number; j++)                              \
    {                                                                \
        rpc_sendto(pco_tst, tst_s, sendbuf, DATA_BULK, 0, _maddr); \
        MSLEEP(100);                                                 \
                                                                     \
        for (i = 0; i < _snum; i++)                                  \
        {                                                            \
            if (_socks[i] == -1)                                     \
                continue;                                            \
            RPC_CHECK_READABILITY(_pco, _socks[i], TRUE);            \
            rpc_recv(_pco, _socks[i], recvbuf, DATA_BULK, 0);        \
            MSLEEP(100);                                             \
            RPC_CHECK_READABILITY(_pco, _socks[i], FALSE);           \
        }                                                            \
    }                                                                \
                                                                     \
    rc = mcast_listen_stop(pco_iut, listener, NULL);                 \
    if (rc > 0)                                                      \
    RING_VERDICT("%sulticast packets were detected on iut_if %s",    \
                 (rc == packet_number) ? "All m" : "M", _verdict);   \
} while(0);

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;
    const struct sockaddr       *tst_addr = NULL;
    const struct sockaddr       *mcast_addr = NULL;
    int                          socks[MAX_SOCK_NUM];
    int                          tst_s = -1;

    struct sockaddr_storage  wildcard_addr;

    char                        *sendbuf = NULL;
    char                        *recvbuf = NULL;

    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;
    int                          packet_number;
    tarpc_joining_method         method;
    struct tarpc_mreqn           mreq;

    sockts_socket_func  sock_func;

    mcast_listener_t    listener;
    te_bool             listener_created = FALSE;

    int j;
    int i;

    int     sock_count = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    for (i = 0; i < MAX_SOCK_NUM; i++)
        socks[i] = -1;

    sendbuf = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = malloc(DATA_BULK));

    memcpy(&wildcard_addr, mcast_addr,
           te_sockaddr_get_size(SA(mcast_addr)));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));

    TEST_STEP("Create @c SOCK_DGRAM socket @p tst_s on @p pco_tst. Bind it to "
              "@p tst1_addr and set @c IP_MULTICAST_IF with index of @p tst_if.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst, tst_s, tst_addr);
    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_MREQN;
    mreq.ifindex = tst_if->if_index;
    rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);

    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst, iut_if, tst_s, mcast_addr);

    TEST_STEP("Create two @c SOCK_DGRAM sockets on @p pco_iut in one stack. Bind "
              "them to wildcard address with port of @p mcast_addr and join "
              "@p mcast_addr group on both.");
    TWO_SOCKS_IN_STACK(pco_iut, socks[sock_count], socks[sock_count + 1],
                       SA(&wildcard_addr), mcast_addr, "test1");
    sock_count += 2;

    listener = mcast_listener_init(pco_iut, iut_if, mcast_addr, NULL, 1);
    listener_created = TRUE;

    TEST_STEP("Send multicast packets from @p pco_tst to @p mcast_addr and "
              "check that both socket receives accelerated traffic.");
    CHECK_ACC(pco_iut, socks, sock_count, mcast_addr,
              " with one pair of sockets");

    TEST_STEP("Create new two @c SOCK_DGRAM sockets on @p pco_iut in new stack. "
              "Bind them to wildcard address with port of @p mcast_addr and join "
              "@p mcast_addr group on both.");
    TWO_SOCKS_IN_STACK(pco_iut, socks[sock_count], socks[sock_count + 1],
                       SA(&wildcard_addr), mcast_addr, "test2");
    sock_count += 2;

    TEST_STEP("Send multicast packets from @p pco_tst to @p mcast_addr and "
              "check that all four socket receives traffic.");
    CHECK_ACC(pco_iut, socks, sock_count, mcast_addr,
              " with two pairs of sockets");

    TEST_STEP("Create new two @c SOCK_DGRAM sockets on @p pco_iut in new stack. "
              "Bind them to wildcard address with port of @p mcast_addr and join "
              "@p mcast_addr group on both.");
    TWO_SOCKS_IN_STACK(pco_iut, socks[sock_count], socks[sock_count + 1],
                       SA(&wildcard_addr), mcast_addr, "test3");
    sock_count += 2;

    TEST_STEP("Send multicast packets from @p pco_tst to @p mcast_addr and "
              "check that all four socket receives traffic.");
    CHECK_ACC(pco_iut, socks, sock_count, mcast_addr,
              " with three pairs of sockets");

    TEST_SUCCESS;

cleanup:

    if (listener_created)
        mcast_listener_fini(pco_iut, listener);

    for (i = 0; i < sock_count; i++)
        CLEANUP_RPC_CLOSE(pco_iut, socks[i]);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
