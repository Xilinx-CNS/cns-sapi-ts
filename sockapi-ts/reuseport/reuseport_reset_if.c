/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_reset_if SO_REUSEPORT working after NIC reset
 *
 * @objective  Check socket behavior with SO_REUSEPORT after NIC reset or
 *             putting it down/up.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param sock_type     Socket type
 * @param server        Determines is the TCP socket server or client
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_reset_if"

#include "sockapi-test.h"
#include "reuseport.h"
#include "onload.h"

#define PACKET_SIZE 500

/**
 * Determine position where interface should be reseted
 */
typedef enum {
    POS_AFTER_BIND = 0,   /**< After bind */
    POS_AFTER_CONNECTION, /**< After connection */
} reset_position;

#define RESET_POSITION  \
    { "after_bind", POS_AFTER_BIND },         \
    { "after_connetion", POS_AFTER_CONNECTION }

#define RESET_IUT_NIC(curr, req) \
do {                                                    \
    if (curr != req)                                    \
        break;                                          \
    sockts_reset_interface(pco_iut->ta,                 \
                           iut_if->if_name, mode);      \
    SLEEP(5);                                           \
} while(0)

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if = NULL;
    const struct sockaddr *iut_addr = NULL;
    struct sockaddr        iut_addr2;
    const struct sockaddr *tst_addr = NULL;
    struct sockaddr        tst_addr2;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    rpc_socket_type        sock_type;
    sockts_reset_mode      mode;
    reset_position         position;

    char    recvbuf[PACKET_SIZE] = {0,};
    char   *sendbuf = NULL;

    reuseport_socket_ctx s1 = REUSEPORT_SOCKET_CTX_INIT;
    reuseport_socket_ctx s2 = REUSEPORT_SOCKET_CTX_INIT;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ENUM_PARAM(mode, SOCKTS_RESET_MODE);
    TEST_GET_ENUM_PARAM(position, RESET_POSITION);
    TEST_GET_IF(iut_if);

    sendbuf = te_make_buf_by_len(PACKET_SIZE);

    reuseport_init_socket_ctx(pco_iut, pco_tst, iut_addr, tst_addr, &s1);
    memcpy(&iut_addr2, iut_addr, sizeof(iut_addr2));
    memcpy(&tst_addr2, tst_addr, sizeof(tst_addr2));
    TAPI_SET_NEW_PORT(pco_tst, &tst_addr2);
    reuseport_init_socket_ctx(pco_iut, pco_tst, &iut_addr2, &tst_addr2, &s2);

    TEST_STEP("Open UDP or TCP sockets in dependence on @p sock_type on IUT and "
              "tester.");
    s1.iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);
    s2.iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);

    TEST_STEP("Set SO_REUSEPORT for both.");
    rpc_setsockopt_int(pco_iut, s1.iut_s, RPC_SO_REUSEPORT, 1);
    rpc_setsockopt_int(pco_iut, s2.iut_s, RPC_SO_REUSEPORT, 1);

    TEST_STEP("Bind sockets.");
    rpc_bind(pco_iut, s1.iut_s, s1.iut_addr);
    rpc_bind(pco_iut, s2.iut_s, s2.iut_addr);

    TEST_STEP("Perform interface reset/restart here or later in dependence on "
              "@p position.");
    RESET_IUT_NIC(position, POS_AFTER_BIND);

    TEST_STEP("Receive connection by both TCP sockets or connect UDP sockets.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(s1.pco_iut, s1.iut_s, 1);
        rpc_listen(s2.pco_iut, s2.iut_s, 1);
        rpc_fcntl(s1.pco_iut, s1.iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);
        rpc_fcntl(s2.pco_iut, s2.iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);
        try_connect_pair(&s1, &s2);
    }
    else
    {
        s1.tst_s = rpc_socket(s1.pco_tst,
                              rpc_socket_domain_by_addr(s1.tst_addr),
                              RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_bind(s1.pco_tst, s1.tst_s, s1.tst_addr);
        rpc_connect(s1.pco_iut, s1.iut_s, s1.tst_addr);
        rpc_connect(s1.pco_tst, s1.tst_s, s1.iut_addr);

        s2.tst_s = rpc_socket(s2.pco_tst,
                              rpc_socket_domain_by_addr(s2.tst_addr),
                              RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_bind(s2.pco_tst, s2.tst_s, s2.tst_addr);
        rpc_connect(s2.pco_iut, s2.iut_s, s2.tst_addr);
        rpc_connect(s2.pco_tst, s2.tst_s, s2.iut_addr);
        s1.iut_acc = s1.iut_s;
        s1.iut_s = -1;
        s2.iut_acc = s2.iut_s;
        s2.iut_s = -1;
    }

    RESET_IUT_NIC(position, POS_AFTER_CONNECTION);

#define SEND_RECV_CHECK(snd_rpc, rcv_rpc, snd_s, rcv_s) \
do {                                                                       \
    if (rpc_send(snd_rpc, snd_s, sendbuf, PACKET_SIZE, 0) != PACKET_SIZE)  \
        TEST_FAIL("Only a part of packet has been transmitted");           \
    if (rpc_recv(rcv_rpc, rcv_s, recvbuf, PACKET_SIZE, 0) != PACKET_SIZE)  \
        TEST_FAIL("Only a part of packet has been received");              \
    if (memcmp(sendbuf, recvbuf, PACKET_SIZE) != 0)                        \
        TEST_FAIL("Received data differs from sent");                      \
} while (0)

    TEST_STEP("Send and receive packets across each socket.");
    SEND_RECV_CHECK(pco_iut, pco_tst, s1.iut_acc, s1.tst_s);
    SEND_RECV_CHECK(pco_tst, pco_iut, s1.tst_s, s1.iut_acc);

    memset(recvbuf, 0, PACKET_SIZE);
    SEND_RECV_CHECK(pco_iut, pco_tst, s2.iut_acc, s2.tst_s);
    SEND_RECV_CHECK(pco_tst, pco_iut, s2.tst_s, s2.iut_acc);

#undef SEND_RECV_CHECK

    TEST_SUCCESS;

cleanup:
    free(sendbuf);
    reuseport_close_pair(&s1, &s2);

    TEST_END;
}
