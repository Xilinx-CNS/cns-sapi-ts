/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/**
 * @page bnbvalue-send_connect_zero_addr Send and connect to all-zero address
 *
 * @objective Check behaviour when sending to all-zeros destination address
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type   Socket type:
 *                    - @c SOCK_STREAM
 *                    - @c SOCK_DGRAM
 * @param use_connect Use connect+send or sendto:
 *                    - @c TRUE
 *                    - @c FALSE
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 * @author Ekaterina Yaschenko <Ekaterina.Yaschenko@oktetlabs.ru>
 */

#include "sockapi-test.h"
#include "tapi_mem.h"

#define TE_TEST_NAME "bnbvalue/send_connect_zero_addr"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     tst_s = -1;
    int                     iut_s = -1;
    int                     accepted_s = -1;
    const struct sockaddr  *tst_addr = NULL;
    const struct sockaddr  *iut_addr = NULL;
    sockts_socket_type      sock_type;
    te_bool                 use_connect;
    struct sockaddr_storage addr;
    void                   *send_buf = NULL;
    void                   *recv_buf = NULL;
    size_t                  buf_len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(use_connect);

    if (sock_type != RPC_SOCK_DGRAM && sock_type != RPC_SOCK_STREAM)
        TEST_FAIL("Wrong value of @p sock_type parameter");

    if (sock_type == RPC_SOCK_STREAM && use_connect == FALSE)
        TEST_FAIL("Weird parameters");

    CHECK_NOT_NULL((send_buf = sockts_make_buf_dgram(&buf_len)));
    send_buf = te_make_buf_by_len(buf_len);

    recv_buf = tapi_malloc(buf_len);

    TEST_STEP("Create @p sock_type socket @b tst_s on TST");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);

    TEST_STEP("Bind @b tst_s to @b addr");
    tapi_sockaddr_clone_exact(tst_addr, &addr);
    te_sockaddr_set_wildcard(SA(&addr));
    rpc_bind(pco_tst, tst_s, SA(&addr));

    TEST_STEP("Create @p sock_type socket @b iut_s on IUT");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("If @p sock_type is @c SOCK_STREAM, then @b listen() "
                  "on peer Tester socket and check that it succeeds");
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
        if (rc == -1)
        {
            TEST_VERDICT("Listen() failed with %r on TST",
                         RPC_ERRNO(pco_tst));
        }
    }

    if (use_connect)
    {
        TEST_STEP("If @p use_connect is @c TRUE, then @b connect() IUT "
                  "socket to @b addr");
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s, SA(&addr));
        if (sock_type == RPC_SOCK_DGRAM)
        {
            TEST_SUBSTEP("If @p sock_type is @c SOCK_DGRAM, then check "
                         "that @b connect() succeeds");
            if (rc != 0)
            {
                TEST_VERDICT("Connect() failed with %r on IUT",
                             RPC_ERRNO(pco_iut));
            }
        }
        else
        {
            TEST_SUBSTEP("If @p sock_type is @c SOCK_STREAM, then check "
                         "that @b connect() fails with @c ECONNREFUSED "
                         "errno and terminate the testing");
            if (rc == -1)
            {
                CHECK_RPC_ERRNO(pco_iut, RPC_ECONNREFUSED,
                                "Connect() called with wildcard address "
                                "parameter returned %r errno",
                                RPC_ERRNO(pco_iut));
                TEST_SUCCESS;
            }
            ERROR_VERDICT("Connect() succeeded unexpectedly");
            TEST_SUBSTEP("If @b connect() succeeds instead, accept "
                         "connection on Tester and send/receive data "
                         "between connected sockets in both directions");
            RPC_AWAIT_IUT_ERROR(pco_tst);
            accepted_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
            if (accepted_s == -1)
            {
                TEST_VERDICT("Can't accept connection from IUT, "
                             "accept() returned %r errno",
                             RPC_ERRNO(pco_tst));
            }
            sockts_test_connection(pco_iut, iut_s, pco_tst, accepted_s);
            TEST_STOP;
        }
    }

    TEST_STEP("Send data to @b addr using @b send() if @p use_connect "
              "is @c TRUE and @b sendto() otherwise");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (use_connect)
        rc = rpc_send(pco_iut, iut_s, send_buf, buf_len, 0);
    else
        rc = rpc_sendto(pco_iut, iut_s, send_buf, buf_len, 0, SA(&addr));

    TEST_SUBSTEP("Check that sending function returns correct value");
    if (rc < 0 )
    {
        TEST_VERDICT("Sending function failed with %r on IUT",
                     RPC_ERRNO(pco_iut));
    }
    if (rc != buf_len)
    {
        TEST_VERDICT("Sending function sent less bytes than it "
                     "was expected to");
    }

    TEST_STEP("Check that receive fails with EAGAIN or EWOULDBLOCK");
    rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_recv(pco_tst, tst_s, recv_buf, buf_len, 0);
    if (rc < 0)
    {
        if (RPC_ERRNO(pco_tst) != RPC_EAGAIN &&
            RPC_ERRNO(pco_tst) != RPC_EWOULDBLOCK)
        {
            TEST_VERDICT("Recv() failed with %r errno instead of "
                         "@c RPC_EAGAIN or @c RPC_EWOULDBLOCK",
                         RPC_ERRNO(pco_tst));
        }
    }
    else
    {
        ERROR_VERDICT("Recv() succeeded unexpectedly");
        if (rc != buf_len || memcmp(send_buf, recv_buf, buf_len) != 0)
            TEST_VERDICT("Recv() returned unexpected data");
        TEST_STOP;
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, accepted_s);

    free(send_buf);
    free(recv_buf);

    TEST_END;
}
