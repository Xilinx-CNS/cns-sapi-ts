/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_two_interfaces Test SO_REUSEPORT option working on two interfaces
 *
 * @objective Test port sharing with SO_REUSEPORT across two interfaces.
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TST
 * @param thread_process    If new thread/process should be created
 * @param min_packet_size   Minimum packet size
 * @param max_packet_size   Maximum packet size
 * @param packets_num       Packets number
 * @param reuseport_first   Set SO_REUSEPORT for the first socket
 * @param reuseport_second  Set SO_REUSEPORT for the second socket
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_two_interfaces"

#include "sockapi-test.h"
#include "reuseport.h"

/**
 * Transmit some data over established connections
 * 
 * @param pco_iut        IUT RPC server
 * @param tst_iut        Tester RPC server
 * @param pco_iut_aux    Second IUT RPC server
 * @param iut_s1         First IUT socket
 * @param iut_s2         Second IUT socket
 * @param tst_s1         First tester socket
 * @param tst_s1         Second tester socket
 * @param len            Packet length to transmit
 * @param packets_num    Packets number to transmit
 */
static void
transmit_data(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_iut_aux,
              rcf_rpc_server *pco_tst, int iut_s1, int tst_s1, int iut_s2,
              int tst_s2, size_t len, int packets_num)
{
    int total;
    int res;
    int i;
    char *sndbuf = te_make_buf_by_len(len);
    char *rcvbuf = malloc(len);

#define SEND_RECV_CHECK(recv_rpcs, tst_s, iut_s) \
do {                                                            \
    memset(rcvbuf, 0, len);                                     \
    total = 0;                                                  \
    if (rpc_send(pco_tst, tst_s, sndbuf, len, 0) != (int)len)   \
        TEST_FAIL("send() transmitted not full packet");        \
    while (total != (int)len)                                   \
    {                                                           \
        if ((res = rpc_recv(recv_rpcs, iut_s, rcvbuf + total,   \
                            len - total, 0)) < 0)               \
            TEST_VERDICT("Data was not read completely");       \
        total += res;                                           \
    }                                                           \
    if (memcmp(sndbuf, rcvbuf, len) != 0)                       \
        TEST_FAIL("Received packet is corrupted!");             \
}                                                               \
while (0)

    for (i = 0; i < packets_num; i++)
    {
        SEND_RECV_CHECK(pco_iut, tst_s1, iut_s1);
        SEND_RECV_CHECK(pco_iut_aux, tst_s2, iut_s2);
    }

#undef SEND_RECV_CHECK

    free(sndbuf);
    free(rcvbuf);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut_aux = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;
    rpc_socket_type        sock_type;
    thread_process_type    thread_process = TP_NONE;

    te_bool reuseport_first;
    te_bool reuseport_second;
    int     min_packet_size;
    int     max_packet_size;
    int     packets_num;

    reuseport_socket_ctx s1 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s2 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s3 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s4 = REUSEPORT_SOCKET_CTX_INIT;

    int iut_s1 = -1;
    int iut_s2 = -1;
    int tst_s1 = -1;
    int tst_s2 = -1;

    uint16_t *port_ptr;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst1_addr);
    TEST_GET_ADDR(pco_tst, tst2_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(reuseport_first);
    TEST_GET_BOOL_PARAM(reuseport_second);
    TEST_GET_INT_PARAM(min_packet_size);
    TEST_GET_INT_PARAM(max_packet_size);
    TEST_GET_INT_PARAM(packets_num);
    TEST_GET_ENUM_PARAM(thread_process, THREAD_PROCESS);

    TEST_STEP("Both sockets should be bound to the same port.");
    port_ptr = te_sockaddr_get_port_ptr(SA(iut_addr2));
    *port_ptr = *te_sockaddr_get_port_ptr(SA(iut_addr1));

    TEST_STEP("Create new thread or process in dependence on argument "
              "@p thread_process.");
    init_aux_rpcs(pco_iut, &pco_iut_aux, thread_process);

    reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr1, tst1_addr, &s1);
    reuseport_init_socket_ctx(pco_iut_aux, pco_tst, iut_addr2, tst2_addr, &s2);

    TEST_STEP("Establish connection between two couples of sockets on IUT and "
              "tester.");
    if (sock_type == RPC_SOCK_STREAM && reuseport_first && reuseport_second)
    {
        reuseport_init_socket_ctx(pco_iut_aux, pco_tst, iut_addr1, tst1_addr, &s2);

        reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr2, tst2_addr, &s3);
        reuseport_init_socket_ctx(pco_iut_aux, pco_tst, iut_addr2, tst2_addr, &s4);
        reuseport_pair_connection(sock_type, &s1, &s2);
        reuseport_pair_connection(sock_type, &s3, &s4);
        SOCKTS_MOVE_FD(iut_s1, s1.iut_acc);
        SOCKTS_MOVE_FD(tst_s1, s1.tst_s);
        SOCKTS_MOVE_FD(iut_s2, s2.iut_acc);
        SOCKTS_MOVE_FD(tst_s2, s2.tst_s);

        sockts_test_connection(s3.pco_iut, s3.iut_acc, s3.pco_tst, s3.tst_s);
        sockts_test_connection(s4.pco_iut, s4.iut_acc, s4.pco_tst, s4.tst_s);
    }
    else if (sock_type == RPC_SOCK_STREAM && reuseport_first)
    {
        reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr1, tst1_addr, &s2);
        reuseport_pair_connection(sock_type, &s1, &s2);
        SOCKTS_MOVE_FD(iut_s1, s1.iut_acc);
        SOCKTS_MOVE_FD(tst_s1, s1.tst_s);

        GEN_CONNECTION(pco_iut_aux, pco_tst, sock_type, RPC_PROTO_DEF,
                       iut_addr2, tst2_addr, &iut_s2, &tst_s2);
    }
    else if (sock_type == RPC_SOCK_STREAM && reuseport_second)
    {
        GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                       iut_addr1, tst1_addr, &iut_s1, &tst_s1);

        reuseport_init_socket_ctx(pco_iut_aux, pco_tst, iut_addr2, tst2_addr, &s1);
        reuseport_init_socket_ctx(pco_iut_aux, pco_tst, iut_addr2, tst2_addr, &s2);
        reuseport_pair_connection(sock_type, &s1, &s2);
        SOCKTS_MOVE_FD(iut_s2, s2.iut_acc);
        SOCKTS_MOVE_FD(tst_s2, s2.tst_s);
    }
    else
    {
        reuseport_connection(pco_iut, pco_tst, sock_type, iut_addr1, tst1_addr,
                             reuseport_first, FALSE, &iut_s1, &tst_s1);
        reuseport_connection(pco_iut_aux, pco_tst, sock_type, iut_addr2,
                             tst2_addr, reuseport_second, FALSE, &iut_s2,
                             &tst_s2);
    }

    TEST_STEP("Transmit packets over established connections.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        sockts_test_connection(pco_iut, iut_s1, pco_tst, tst_s1);
        sockts_test_connection(pco_iut_aux, iut_s2, pco_tst, tst_s2);
    }
    else
        transmit_data(pco_iut, pco_iut_aux, pco_tst, iut_s1, tst_s1, iut_s2,
                      tst_s2, rand_range(min_packet_size, max_packet_size),
                      packets_num);

    TEST_SUCCESS;
cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut_aux, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    reuseport_close_pair(&s1, &s2);
    reuseport_close_pair(&s3, &s4);

    if (pco_iut != pco_iut_aux)
        rcf_rpc_server_destroy(pco_iut_aux);

    TEST_END;
}
