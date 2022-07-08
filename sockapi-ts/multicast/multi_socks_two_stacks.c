/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-multi_socks_two_stacks Four sockets from two different stacks joined to the same and different multicast addresses
 *
 * @objective Check receive behaviour of four connected sockets from two
 *            different stacks join to the various multicast groups
 *
 * @type Conformance.
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on Tester1
 * @param pco_tst               PCO on Tester2
 * @param tst1_addr             Tester1 address
 * @param tst2_addr             Tester2 address
 * @param mcast_addr            Multicast address/es
 * @param iut_if1               Interface on IUT
 * @param iut_if2               Interface on IUT
 * @param tst1_if               Interface on Tester1
 * @param tst2_if               Interface on Tester2
 * @param packet_number         Number of datagrams to send for reliability.
 * @param diff_ifs              If it is @c TRUE join group on different
 *                              IUT interfaces
 * @param sock_func             Socket creation function
 * 
 * @par Scenario:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/multi_socks_two_stacks"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#define DATA_BULK 512

#define CREATE_JOIN_CONNECT(_rpcs, _sock, _mcast1, _mcast2) \
do {                                                                \
    _sock = sockts_socket(sock_func, _rpcs,                         \
                          rpc_socket_domain_by_addr(_mcast1),       \
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);         \
    rpc_setsockopt(_rpcs, _sock, RPC_SO_REUSEADDR, &opt_val);       \
    rpc_bind(_rpcs, _sock, _mcast1);                                \
    rpc_mcast_join(_rpcs, _sock, _mcast1, iut_if1->if_index,        \
                   method);                                         \
    rpc_mcast_join(_rpcs, _sock, _mcast2, iut_if1->if_index,        \
                   method);                                         \
    rpc_mcast_join(_rpcs, _sock, _mcast1, iut_if2->if_index,        \
                   method);                                         \
    rpc_connect(_rpcs, _sock, tst1_addr);                           \
} while(0);

/**
 * This macro checks that only certain sockets receives certain packets.
 *
 * rs       Array of sockets which sould be with received data
 * rs_num   Number of entries in rs array
 * nrs      Array of sockets which sould be without received data
 * nrs_num  Number of entries in nrs array
 * _lnum    Number of CSAP
 * _if_num  Interface number
 * _maddr   Multicast address to send to
 * _verdict Additional suffix for verdicts
 */
#define SEND_RECV_CHECK(rs, rs_num, nrs, nrs_num, _lnum, _if_num, _maddr,  \
                        _verdict)                                          \
do {                                                                       \
    int i,j;                                                               \
    int mis_pack[4];                                                       \
    int got_pack[4];                                                       \
    te_bool readable;                                                      \
                                                                           \
    memset(mis_pack, 0, sizeof(mis_pack));                                 \
    memset(got_pack, 0, sizeof(got_pack));                                 \
    if (_lnum != 0)                                                        \
        mcast_listen_start(pco_iut1, listener##_lnum);                     \
                                                                           \
    for (j = 0; j < packet_number; j++)                                    \
    {                                                                      \
        rpc_sendto(pco_tst##_if_num, tst##_if_num##_s, sendbuf,            \
                   DATA_BULK, 0, _maddr);                                  \
        MSLEEP(100);                                                       \
                                                                           \
        for (i = 0; i < nrs_num; i++)                                      \
        {                                                                  \
            RPC_GET_READABILITY(readable, nrs[i].pco, nrs[i].s, 1000);     \
            if (readable)                                                  \
            {                                                              \
                got_pack[i]++;                                             \
                rc = rpc_recv(nrs[i].pco, nrs[i].s, recvbuf,               \
                              DATA_BULK, 0);                               \
                if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)              \
                    TEST_VERDICT("Data verification failed");              \
                RPC_CHECK_READABILITY(nrs[i].pco, nrs[i].s, FALSE);        \
            }                                                              \
        }                                                                  \
                                                                           \
        for (i = 0; i < rs_num; i++)                                       \
        {                                                                  \
            RPC_GET_READABILITY(readable, rs[i].pco, rs[i].s, 1000);       \
            if (readable)                                                  \
            {                                                              \
                rc = rpc_recv(rs[i].pco, rs[i].s, recvbuf, DATA_BULK, 0);  \
                if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)              \
                    TEST_VERDICT("Data verification failed");              \
            }                                                              \
            else                                                           \
                mis_pack[i]++;                                             \
            RPC_CHECK_READABILITY(rs[i].pco, rs[i].s, FALSE);              \
        }                                                                  \
    }                                                                      \
    for (i = 0; i < nrs_num; i++)                                          \
        if (got_pack[i] > 0)                                               \
            RING_VERDICT("%s recieves %spackets sent to %s",               \
                         nrs[i].descr,                                     \
                         (got_pack[i] == packet_number) ? "all " :         \
                                                          "some ",         \
                         _verdict);                                        \
    for (i = 0; i < rs_num; i++)                                           \
        if (mis_pack[i] > 0)                                               \
        {                                                                  \
            RING_VERDICT("%sulticast packets sent to %s were missed",      \
                         (mis_pack[i] == packet_number) ? "All m" : "M",   \
                         _verdict);                                        \
            break;                                                         \
        }                                                                  \
    if (_lnum)                                                             \
    {                                                                      \
        rc = mcast_listen_stop(pco_iut1, listener##_lnum, NULL);           \
        if (rc > 0)                                                        \
            RING_VERDICT("%sulticast packets sent to %s were detected "    \
                         "on iut_if1",                                     \
                         (rc == packet_number) ? "All m" : "M",            \
                         _verdict);                                        \
    }                                                                      \
} while(0);

#define SET_DESCR(_num, _descr) \
    snprintf(nrs[_num].descr, sizeof(nrs[_num].descr), _descr);

struct pco_and_socket {
    rcf_rpc_server *pco;
    int             s;
    char            descr[64];
};

int
main(int argc, char *argv[])
{
    rpc_socket_domain           domain;
    rcf_rpc_server              *pco_iut1 = NULL;
    rcf_rpc_server              *pco_iut2 = NULL;
    rcf_rpc_server              *pco_iut3 = NULL;
    rcf_rpc_server              *pco_iut4 = NULL;
    rcf_rpc_server              *pco_tst1 = NULL;
    rcf_rpc_server              *pco_tst2 = NULL;
    const struct sockaddr       *tst1_addr = NULL;
    const struct sockaddr       *tst2_addr = NULL;
    const struct sockaddr       *mcast_addr1 = NULL;
    const struct sockaddr       *mcast_addr2 = NULL;
    const struct sockaddr       *mcast_addr3 = NULL;
    const struct sockaddr       *mcast_addr4 = NULL;
    int                          iut_s1 = -1;
    int                          iut_s2 = -1;
    int                          iut_s3 = -1;
    int                          iut_s4 = -1;
    int                          tst1_s = -1;
    int                          tst2_s = -1;

    struct pco_and_socket        rs[4];
    struct pco_and_socket        nrs[4];

    char                        *sendbuf = NULL;
    char                        *recvbuf = NULL;

    const struct if_nameindex   *iut_if1 = NULL;
    const struct if_nameindex   *iut_if2 = NULL;
    const struct if_nameindex   *tst1_if = NULL;
    const struct if_nameindex   *tst2_if = NULL;
    int                          packet_number;
    tarpc_joining_method         method;
    struct tarpc_mreqn           mreq;

    mcast_listener_t    listener0;
    mcast_listener_t    listener1;
    te_bool             listener1_created = FALSE;
    mcast_listener_t    listener2;
    te_bool             listener2_created = FALSE;

    int                 opt_val = 1;

    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_iut3);
    TEST_GET_PCO(pco_iut4);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_ADDR(pco_iut1, mcast_addr1);
    TEST_GET_ADDR(pco_iut1, mcast_addr2);
    TEST_GET_ADDR(pco_iut1, mcast_addr3);
    TEST_GET_ADDR(pco_iut1, mcast_addr4);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut1, pco_tst1, iut_if1,
                                           tst1_addr, mcast_addr1);
    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut1, pco_tst1, iut_if1,
                                           tst1_addr, mcast_addr2);
    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut1, pco_tst1, iut_if1,
                                           tst1_addr, mcast_addr3);
    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut1, pco_tst1, iut_if1,
                                           tst1_addr, mcast_addr4);
    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut1, pco_tst2, iut_if2,
                                           tst2_addr, mcast_addr1);
    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut1, pco_tst2, iut_if2,
                                           tst2_addr, mcast_addr2);
    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut1, pco_tst2, iut_if2,
                                           tst2_addr, mcast_addr3);
    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut1, pco_tst2, iut_if2,
                                           tst2_addr, mcast_addr4);

    sendbuf = te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = malloc(DATA_BULK));

    TEST_STEP("Create four @c SOCK_DGRAM sockets on four PCOs, bind them two (from "
              "different processes) to @p mcast_addr1 and two (from different "
              "processes) to @p mcast_addr3. Connect all off them to @p tst1_addr "
              "and join them to three appropriate multicast groups");
    CREATE_JOIN_CONNECT(pco_iut1, iut_s1, mcast_addr1, mcast_addr2);
    CREATE_JOIN_CONNECT(pco_iut2, iut_s2, mcast_addr3, mcast_addr4);
    CREATE_JOIN_CONNECT(pco_iut3, iut_s3, mcast_addr1, mcast_addr2);
    CREATE_JOIN_CONNECT(pco_iut4, iut_s4, mcast_addr3, mcast_addr4);

    TEST_STEP("Create @c SOCK_DGRAM sockets @p tst1_s and tst2_s on @p pco_tst1 "
              "and @p pco_tst2 respectively. Bind them to @p tst1_addr and @p "
              "tst2_addr and set @c IP_MULTICAST_IF with index of @p tst1_if "
              "and @p tst2_if for those sockets.");
    domain = rpc_socket_domain_by_addr(tst1_addr);
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst1, tst1_s, tst1_addr);
    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_MREQN;
    mreq.ifindex = tst1_if->if_index;
    rpc_setsockopt(pco_tst1, tst1_s, RPC_IP_MULTICAST_IF, &mreq);

    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst2, tst2_s, tst2_addr);
    mreq.ifindex = tst2_if->if_index;
    rpc_setsockopt(pco_tst2, tst2_s, RPC_IP_MULTICAST_IF, &mreq);

    TEST_STEP("Create CSAPs to check that multicast packets are accelerated.");
    listener1 = mcast_listener_init(pco_iut1, iut_if1, mcast_addr1,
                                    NULL, 1);
    listener1_created = TRUE;
    listener2 = mcast_listener_init(pco_iut1, iut_if1, mcast_addr3,
                                    NULL, 1);
    listener2_created = TRUE;

    TEST_STEP("Send multicast packets from both @p pco_tst1 and @p pco_tst2 and "
              "check that only certain sockets receives the packets.");
    rs[0].pco = pco_iut1;
    rs[0].s = iut_s1;
    nrs[0].pco = pco_iut2;
    nrs[0].s = iut_s2;
    SET_DESCR(0, "The second socket from the first stack");
    nrs[1].pco = pco_iut3;
    nrs[1].s = iut_s3;
    SET_DESCR(1, "The first socket from the second stack");
    nrs[2].pco = pco_iut4;
    nrs[2].s = iut_s4;
    SET_DESCR(2, "The second socket from the second stack");
    SEND_RECV_CHECK(rs, 1, nrs, 3, 1, 1, mcast_addr1, "mcast_addr1");

    nrs[3].pco = pco_iut1;
    nrs[3].s = iut_s1;
    SET_DESCR(3, "The first socket from the first stack");
    SEND_RECV_CHECK(rs, 0, nrs, 4, 0, 2, mcast_addr1, "");

    rs[0].pco = pco_iut2;
    rs[0].s = iut_s2;
    nrs[0].pco = pco_iut1;
    nrs[0].s = iut_s1;
    SET_DESCR(0, "The first socket from the first stack");
    nrs[1].pco = pco_iut3;
    nrs[1].s = iut_s3;
    SET_DESCR(1, "The first socket from the second stack");
    nrs[2].pco = pco_iut4;
    nrs[2].s = iut_s4;
    SET_DESCR(2, "The second socket from the second stack");
    SEND_RECV_CHECK(rs, 1, nrs, 3, 2, 1, mcast_addr3, "mcast_addr3");

    nrs[3].pco = pco_iut2;
    nrs[3].s = iut_s2;
    SET_DESCR(3, "The second socket from the first stack");
    SEND_RECV_CHECK(rs, 0, nrs, 4, 0, 2, mcast_addr3, "");

    SEND_RECV_CHECK(rs, 0, nrs, 4, 0, 1, mcast_addr2, "");
    SEND_RECV_CHECK(rs, 0, nrs, 4, 0, 2, mcast_addr2, "");
    SEND_RECV_CHECK(rs, 0, nrs, 4, 0, 1, mcast_addr4, "");
    SEND_RECV_CHECK(rs, 0, nrs, 4, 0, 2, mcast_addr4, "");

    TEST_STEP("Close sockets from the first stack and check that socket from the "
              "second one become to receive multicast packets via OS.");
    RPC_CLOSE(pco_iut1, iut_s1);
    RPC_CLOSE(pco_iut2, iut_s2);

    rs[0].pco = pco_iut3;
    rs[0].s = iut_s3;
    nrs[0].pco = pco_iut4;
    nrs[0].s = iut_s4;
    SET_DESCR(0, "The second socket from the second stack");
    SEND_RECV_CHECK(rs, 1, nrs, 1, 1, 1, mcast_addr1,
                    "mcast_addr1 after closing sockets from the "
                    "first stack");

    nrs[1].pco = pco_iut3;
    nrs[1].s = iut_s3;
    SET_DESCR(1, "The first socket from the second stack");
    SEND_RECV_CHECK(rs, 0, nrs, 2, 0, 2, mcast_addr1, "");

    rs[0].pco = pco_iut4;
    rs[0].s = iut_s4;
    nrs[0].pco = pco_iut3;
    nrs[0].s = iut_s3;
    SET_DESCR(0, "The first socket from the second stack");
    SEND_RECV_CHECK(rs, 1, nrs, 1, 2, 1, mcast_addr3,
                    "mcast_addr3 after closing sockets from the "
                    "first stack");

    nrs[1].pco = pco_iut4;
    nrs[1].s = iut_s4;
    SET_DESCR(1, "The second socket from the second stack");
    SEND_RECV_CHECK(rs, 0, nrs, 2, 0, 2, mcast_addr3, "");

    TEST_SUCCESS;

cleanup:

    if (listener1_created)
        mcast_listener_fini(pco_iut1, listener1);
    if (listener2_created)
        mcast_listener_fini(pco_iut1, listener2);

    free(sendbuf);
    free(recvbuf);

    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut3, iut_s3);
    CLEANUP_RPC_CLOSE(pco_iut4, iut_s4);

    TEST_END;
}
