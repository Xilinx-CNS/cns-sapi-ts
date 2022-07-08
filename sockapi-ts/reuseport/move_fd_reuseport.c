/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 * 
 * $Id$
 */

/** @page reuseport-move_fd_reuseport  Try to use move_fd after setting SO_REUSEPORT
 *
 * @objective  Try to move a socket to other stack when SO_REUSEPORT option
 *             is used.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_addr      Network address on IUT
 * @param tst_addr      Network address on TESTER
 * @param socket_state  Socket state when move_fd() should be called
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/move_fd_reuseport"

#include "sockapi-test.h"
#include "onload.h"
#include "extensions.h"

#define STACK_NAME1  "foo"
#define STACK_NAME2 "bar"
#define PACKET_SIZE 500

#define TAPI_MOVE_FD_FAILURE_EXPECTED TRUE
#define TAPI_MOVE_FD_SUCCESS_EXPECTED FALSE

/**
 * Use different process or thread for the socket
 */
typedef enum {
    SOCK_FRESH = 0,
    SOCK_SETSOCKOPT,
    SOCK_BIND,
    SOCK_TCP_LISTEN,
    SOCK_TCP_ACCEPT,
    SOCK_TCP_ACCEPT_NEW,
    SOCK_CONNECT,
} socket_state_type;

#define SOCKET_STATE  \
    { "fresh", SOCK_FRESH },       \
    { "setsockopt", SOCK_SETSOCKOPT },   \
    { "bind", SOCK_BIND },   \
    { "tcp_listen", SOCK_TCP_LISTEN },   \
    { "tcp_accept", SOCK_TCP_ACCEPT },   \
    { "tcp_accept_new", SOCK_TCP_ACCEPT_NEW },   \
    { "connect", SOCK_CONNECT }

#define MOVE_FD(req_state, curr_state) \
do {                                                                       \
    if (req_state == curr_state)                                           \
    {                                                                      \
        TAPI_WAIT_NETWORK;                                                 \
        RPC_AWAIT_IUT_ERROR(pco_iut);                                      \
        rc = rpc_onload_move_fd(pco_iut, iut_s);                           \
        check_results(req_state, rc);                                      \
    }                                                                      \
} while(0)

static void
check_results(socket_state_type state, int rc)
{
    rc = - rc;
    if (rc != 0 && rc != EINVAL)
        TEST_FAIL("Moving fd failed with unexpected errno %s",
                  te_rc_err2str(te_rc_os2te(rc)));

    if (state < SOCK_BIND)
    {
        if (rc != 0)
            RING_VERDICT("Moving fd unexpectedly failed with -EINVAL");
    }
    else if (rc == 0)
        RING_VERDICT("Moving fd unexpectedly succeeded");
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rpc_socket_type        sock_type;
    socket_state_type      socket_state;

    tarpc_onload_stat ostat;
    char    recvbuf[PACKET_SIZE] = {0,};
    char   *sendbuf = NULL;

    int iut_s = -1;
    int iut_s2 = -1;
    int tst_s = -1;
    int acc_s = -1;
    int iut_s_aux = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ENUM_PARAM(socket_state, SOCKET_STATE);

    sendbuf = te_make_buf_by_len(PACKET_SIZE);

    TEST_STEP("Set stack name.");
    rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_GLOBAL, STACK_NAME1);

    TEST_STEP("Create socket and stack on IUT.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    iut_s2 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type, RPC_PROTO_DEF);

    TEST_STEP("Set new stackname and open new socket to create new stack on IUT.");
    rpc_onload_set_stackname(pco_iut, ONLOAD_ALL_THREADS,
                             ONLOAD_SCOPE_PROCESS, STACK_NAME2);
    iut_s_aux = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);
    rpc_onload_fd_stat(pco_iut, iut_s_aux, &ostat);
    if (!ostat_stack_name_match_str(&ostat, STACK_NAME2))
        TEST_FAIL("Failed to set a new stack name");

    TEST_STEP("Try to move the first IUT socket to the second stack. Place where "
              "the move_fd() is called dependence on @p socket_state.");
    MOVE_FD(socket_state, SOCK_FRESH);

    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_REUSEPORT, 1);
    rpc_setsockopt_int(pco_iut, iut_s2, RPC_SO_REUSEPORT, 1);
    MOVE_FD(socket_state, SOCK_SETSOCKOPT);

    TEST_STEP("Bind the tested socket.");
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_iut, iut_s2, iut_addr);
    MOVE_FD(socket_state, SOCK_BIND);

    TEST_STEP("Create and bind socket on tester.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("Establish connection for TCP sockets. If @p socket_state is "
                  "SOCK_CONNECT than IUT is client.");
        if (socket_state != SOCK_CONNECT)
        {
            int tmp_s;
            rpc_listen(pco_iut, iut_s, 1);
            rpc_listen(pco_iut, iut_s2, 1);
            MOVE_FD(socket_state, SOCK_TCP_LISTEN);
            rpc_connect(pco_tst, tst_s, iut_addr);
            TAPI_WAIT_NETWORK;

            rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);
            RPC_AWAIT_IUT_ERROR(pco_iut);
            acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
            rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, 0);
            if (acc_s == -1)
            {
                if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                    TEST_VERDICT("accept() failed with unexpected errno %r",
                                 RPC_ERRNO(pco_iut));
                acc_s = rpc_accept(pco_iut, iut_s2, NULL, 0);
            }
            MOVE_FD(socket_state, SOCK_TCP_ACCEPT);

            tmp_s = iut_s;
            iut_s = acc_s;
            MOVE_FD(socket_state, SOCK_TCP_ACCEPT_NEW);

            RPC_CLOSE(pco_iut, tmp_s);
        }
        else
        {
            rpc_listen(pco_tst, tst_s, 1);
            rpc_connect(pco_iut, iut_s, tst_addr);
            acc_s = rpc_accept(pco_tst, tst_s, NULL, 0);
            MOVE_FD(socket_state, SOCK_CONNECT);

            RPC_CLOSE(pco_tst, tst_s);
            tst_s = acc_s;
        }
    }
    else
    {
        TEST_STEP("Just call connect() for both IUT and tester sockets if "
                  "@p sock_type is @c SOCK_DGRAM.");
        rpc_connect(pco_iut, iut_s, tst_addr);
        TAPI_SET_NEW_PORT(pco_tst, tst_addr);
        rpc_connect(pco_iut, iut_s2, tst_addr);
        rpc_connect(pco_tst, tst_s, iut_addr);
        MOVE_FD(socket_state, SOCK_CONNECT);
    }

#define SEND_RECV_CHECK(snd_rpc, rcv_rpc, snd_s, rcv_s) \
do {                                                                       \
    if (rpc_send(snd_rpc, snd_s, sendbuf, PACKET_SIZE, 0) != PACKET_SIZE)  \
        TEST_FAIL("Only a part of packet has been transmitted");           \
    if (rpc_recv(rcv_rpc, rcv_s, recvbuf, PACKET_SIZE, 0) != PACKET_SIZE)  \
        TEST_FAIL("Only a part of packet has been received");              \
    if (memcmp(sendbuf, recvbuf, PACKET_SIZE) != 0)                        \
        TEST_FAIL("Received data differs from sent");                      \
} while (0)

    TEST_STEP("Send and receive packets.");
    SEND_RECV_CHECK(pco_iut, pco_tst, iut_s, tst_s);

    memset(recvbuf, 0, PACKET_SIZE);
    SEND_RECV_CHECK(pco_tst, pco_iut, tst_s, iut_s);

#undef SEND_RECV_CHECK

    TEST_SUCCESS;

cleanup:
    RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_iut, iut_s2);
    RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
