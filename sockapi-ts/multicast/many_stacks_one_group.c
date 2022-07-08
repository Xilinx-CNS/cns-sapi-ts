/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-many_stacks_one_group Milticast replication test
 *
 * @objective Check possibility to receive packets on different stacks
 *
 * @type Conformance.
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst1              PCO on Tester1
 * @param pco_tst2              PCO on Tester2
 * @param tst1_addr             Tester1 address
 * @param tst2_addr             Tester2 address
 * @param mcast_addr            Multicast address/es
 * @param iut_if1               Interface on IUT
 * @param iut_if2               Interface on IUT
 * @param tst1_if               Interface on Tester1
 * @param tst2_if               Interface on Tester2
 * @param packet_number         Number of datagrams to send for reliability.
 * @param sock_func             Socket creation function.
 * 
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/many_stacks_one_group"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#include "onload.h"

#include "extensions.h"

#define DATA_BULK 512
#define MAX_SOCK_NUM 10

#define CREATE_JOIN(sock_func_, _rpcs, _sock, _addr4bind, _maddr) \
do {                                                                    \
    int opt_val = 1;                                                    \
    _sock = sockts_socket(sock_func_, _rpcs,                            \
                          rpc_socket_domain_by_addr(_addr4bind),        \
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);             \
    rpc_setsockopt(_rpcs, _sock, RPC_SO_REUSEADDR, &opt_val);           \
    rpc_bind(_rpcs, _sock, _addr4bind);                                 \
    rpc_mcast_join(_rpcs, _sock, _maddr, iut_if1->if_index,             \
                   method);                                             \
} while(0);

#define CHECK_ACC(_pco, _socks, _snum, _maddr, _verdict) \
do {                                                                 \
    mcast_listen_start(pco_iut, listener);                           \
                                                                     \
    for (j = 0; j < packet_number; j++)                              \
    {                                                                \
        rpc_sendto(pco_tst1, tst1_s, sendbuf, DATA_BULK, 0, _maddr); \
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
    rcf_rpc_server              *pco_child = NULL;
    rcf_rpc_server              *pco_tst1 = NULL;
    rcf_rpc_server              *pco_tst2 = NULL;
    const struct sockaddr       *tst1_addr = NULL;
    const struct sockaddr       *tst2_addr = NULL;
    const struct sockaddr       *mcast_addr = NULL;
    int                          socks[MAX_SOCK_NUM];
    int                          tst1_s = -1;
    int                          tst2_s = -1;
    int                          aux_socks[MAX_SOCK_NUM];

    struct sockaddr_storage  wildcard_addr;
    struct sockaddr_storage  aux_wildcard_addr;
    struct sockaddr_storage  aux_mcast_addr;

    char                        *sendbuf = NULL;
    char                        *recvbuf = NULL;

    const struct if_nameindex   *iut_if1 = NULL;
    const struct if_nameindex   *iut_if2 = NULL;
    const struct if_nameindex   *tst1_if = NULL;
    const struct if_nameindex   *tst2_if = NULL;
    int                          packet_number;
    tarpc_joining_method         method;
    struct tarpc_mreqn           mreq;

    mcast_listener_t    listener;
    te_bool             listener_created = FALSE;

    te_bool             kill_child = FALSE;

    int j;
    int i;

    int     sock_count = 0;
    int     aux_sock_count = 0;

    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    for (i = 0; i < MAX_SOCK_NUM; i++)
    {
        socks[i] = -1;
        aux_socks[i] = -1;
    }

    sendbuf = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = malloc(DATA_BULK));

    memcpy(&wildcard_addr, mcast_addr,
           te_sockaddr_get_size(SA(mcast_addr)));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));

    TEST_STEP("Create @c SOCK_DGRAM sockets @p tst1_s and tst2_s on @p pco_tst1 "
              "and @p pco_tst2 respectively. Bind them to @p tst1_addr and @p "
              "tst2_addr and set @c IP_MULTICAST_IF with index of @p tst1_if "
              "and @p tst2_if for those sockets.");
    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                        RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst1, tst1_s, tst1_addr);
    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_MREQN;
    mreq.ifindex = tst1_if->if_index;
    rpc_setsockopt(pco_tst1, tst1_s, RPC_IP_MULTICAST_IF, &mreq);

    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst2_addr),
                        RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst2, tst2_s, tst2_addr);
    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_MREQN;
    mreq.ifindex = tst2_if->if_index;
    rpc_setsockopt(pco_tst2, tst2_s, RPC_IP_MULTICAST_IF, &mreq);

    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst1, iut_if1, tst1_s, mcast_addr);
    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst2, iut_if2, tst2_s, mcast_addr);

    TEST_STEP("Create @c SOCK_DGRAM socket in the first stack and join it to @p "
              "mcast address");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL,
                             "test1");

    CREATE_JOIN(sock_func, pco_iut, socks[sock_count],
                SA(&wildcard_addr), mcast_addr);
    sock_count++;

    TEST_STEP("Create @c SOCK_DGRAM socket in the second stack and join it to @p "
              "mcast address");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL,
                             "test2");

    CREATE_JOIN(sock_func, pco_iut, socks[sock_count],
                SA(&wildcard_addr), mcast_addr);
    sock_count++;

    listener = mcast_listener_init(pco_iut, iut_if1, mcast_addr, NULL, 1);
    listener_created = TRUE;

    TEST_STEP("Check that both sockets receives packets from @p pco_tst1");
    CHECK_ACC(pco_iut, socks, sock_count, mcast_addr,
              "with two socket from different stack");

    TEST_STEP("Close the second socket and check that the first socket  "
              "receives accelerated traffic now.");
    RPC_CLOSE(pco_iut, socks[1]);

    CHECK_ACC(pco_iut, socks, sock_count, mcast_addr,
              "with closed socket from different stack");

    TEST_STEP("Create another socket in the second stack and check that both "
              "sockets receives multicast packets");
    CREATE_JOIN(sock_func, pco_iut, socks[sock_count],
                SA(&wildcard_addr), mcast_addr);
    sock_count++;

    CHECK_ACC(pco_iut, socks, sock_count, mcast_addr,
              "after opening another socket on the second stack");

    TEST_STEP("Create one more socket in the second stack and join it to auxiliary "
              "multicast group. Check that it receives multicast packets sent to "
              "this group.");
    CHECK_RC(tapi_sockaddr_clone(pco_iut, mcast_addr,
                                 &aux_mcast_addr));

    memcpy(&aux_wildcard_addr, &aux_mcast_addr,
           te_sockaddr_get_size(SA(mcast_addr)));
    te_sockaddr_set_wildcard(SA(&aux_wildcard_addr));

    CREATE_JOIN(sock_func, pco_iut, aux_socks[aux_sock_count],
                SA(&aux_wildcard_addr), SA(&aux_mcast_addr));
    aux_sock_count++;
    CHECK_ACC(pco_iut, aux_socks, aux_sock_count, SA(&aux_mcast_addr),
              "on auxiliary multicast address");

    TEST_STEP("Create the socket in the forked process ack and join it to main "
              "multicast group. Check three corresponding sockets receives traffic "
              "sent to the multicast group.");
    CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, "iut_child",
                                          &pco_child));
    kill_child = TRUE;

    rpc_onload_set_stackname(pco_child,
                             ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL,
                             "test3");

    CREATE_JOIN(sock_func, pco_child, socks[sock_count],
                SA(&wildcard_addr), mcast_addr);
    sock_count++;

    CHECK_ACC(pco_child, socks, sock_count, mcast_addr,
              "with third stack");

    TEST_STEP("Create system socket and join it to auxiliary "
              "multicast group. Check that it doesn't receives multicast packets sent to "
              "this group, but onload socket receives.");
    pco_iut->use_libc_once = TRUE;
    CREATE_JOIN(SOCKTS_SOCK_FUNC_SOCKET, pco_iut,
                aux_socks[aux_sock_count],
                SA(&aux_wildcard_addr), SA(&aux_mcast_addr));

    aux_sock_count++;
    CHECK_ACC(pco_iut, aux_socks, 1, SA(&aux_mcast_addr),
              "on auxiliary multicast address with additional kernel socket");
    RPC_CHECK_READABILITY(pco_iut, aux_socks[aux_sock_count - 1], FALSE);
    
    
    TEST_STEP("Destroy created process and check that the sockets from the first "
              "two stacks still receive multicast packets.");
    rcf_rpc_server_destroy(pco_child);
    kill_child = FALSE;
    socks[sock_count - 1] = -1;

    CHECK_ACC(pco_iut, socks, sock_count, mcast_addr,
              "after closing socket from third stack");

    TEST_STEP("Create one new socket in new stack and join it to the main "
              "multicast group. Use @c SO_BINDTODEVICE to bind it to another "
              "interface. Check that it doesn't receives multicast packets sent to "
              "this group via the main interface.");
    rpc_onload_set_stackname(pco_iut,
                             ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL,
                             "test4");
    
    CREATE_JOIN(sock_func, pco_iut, socks[sock_count],
                SA(&wildcard_addr), mcast_addr);
    sock_count++;
    rpc_bind_to_device(pco_iut, socks[sock_count - 1], iut_if2->if_name);

    CHECK_ACC(pco_iut, socks, (sock_count - 1), mcast_addr,
              "after adding the socket from the fourth stack");
    RPC_CHECK_READABILITY(pco_iut, socks[sock_count - 1], FALSE);

    rpc_sendto(pco_tst2, tst2_s, sendbuf, DATA_BULK, 0, mcast_addr);
    MSLEEP(100);
    for (i = 0; i < sock_count; i++)
        if (socks[i] != -1)
            RPC_CHECK_READABILITY(pco_iut, socks[i], FALSE);
    
    TEST_STEP("Join the main multicast group on additional interface on the socket "
              "from fourth stack and from the second one. Check that they are both "
              "receives packet.");
    rpc_mcast_join(pco_iut, socks[sock_count - 1], mcast_addr,
                   iut_if2->if_index, method);

    for (j = 0; j < packet_number; j++)
    {
        rpc_sendto(pco_tst2, tst2_s, sendbuf, DATA_BULK, 0, mcast_addr);
        MSLEEP(100);

        RPC_CHECK_READABILITY(pco_iut,socks[sock_count - 1], TRUE);
        rpc_recv(pco_iut, socks[sock_count - 1], recvbuf, DATA_BULK, 0);
        MSLEEP(100);
        RPC_CHECK_READABILITY(pco_iut, socks[sock_count - 1], FALSE);
    }
    for (i = 0; i < sock_count - 1; i++)
        if (socks[i] != -1)
            RPC_CHECK_READABILITY(pco_iut, socks[i], FALSE);

    rpc_mcast_join(pco_iut, socks[2], mcast_addr,
                   iut_if2->if_index, method);

    for (j = 0; j < packet_number; j++)
    {
        rpc_sendto(pco_tst2, tst2_s, sendbuf, DATA_BULK, 0, mcast_addr);
        MSLEEP(100);

        RPC_CHECK_READABILITY(pco_iut, socks[sock_count - 1], TRUE);
        RPC_CHECK_READABILITY(pco_iut, socks[2], TRUE);
        rpc_recv(pco_iut, socks[sock_count - 1], recvbuf, DATA_BULK, 0);
        rpc_recv(pco_iut, socks[2], recvbuf, DATA_BULK, 0);
        MSLEEP(100);
        RPC_CHECK_READABILITY(pco_iut, socks[sock_count - 1], FALSE);
        RPC_CHECK_READABILITY(pco_iut, socks[2], FALSE);
    }

    TEST_SUCCESS;

cleanup:

    if (listener_created)
        mcast_listener_fini(pco_iut, listener);

    for (i = 0; i < sock_count; i++)
        CLEANUP_RPC_CLOSE(pco_iut, socks[i]);
    for (i = 0; i < aux_sock_count; i++)
        CLEANUP_RPC_CLOSE(pco_iut, aux_socks[i]);

    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    if (kill_child)
        rcf_rpc_server_destroy(pco_child);

    TEST_END;
}
