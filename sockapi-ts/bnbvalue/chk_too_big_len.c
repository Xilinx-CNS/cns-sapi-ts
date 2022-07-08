/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-chk_too_big_len Too big length and _chk() functions
 *
 * @objective Check that _chk() functions abort the program when
 *            passed length argument is too big.
 *
 * @type conformance, robustness
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type       @c SOCK_DGRAM or @c SOCK_STREAM.
 * @param func            Function to check (these are functions
 *                        having __[func]_chk() version which
 *                        checks for too big length):
 *                        - @b read()
 *                        - @b recv()
 *                        - @b recvfrom()
 *                        - @b poll()
 *                        - @b ppoll()
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/chk_too_big_len"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut_child = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    int iut_s = -1;
    int tst_s = -1;

    char send_buf[SOCKTS_MSG_DGRAM_MAX];
    char recv_buf[SOCKTS_MSG_DGRAM_MAX];
    int send_len;
    int len_arg;

    rpc_socket_type sock_type;
    const char *func;

    struct sockaddr_storage from_addr;
    socklen_t from_len;
    struct rpc_pollfd pfd;

    pid_t iut_child_pid;
    rpc_wait_status st;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(func);

    TEST_STEP("Fork an auxiliary @b pco_iut_child on IUT to create "
              "a socket on it.");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_child",
                                 &pco_iut_child));
    iut_child_pid = rpc_getpid(pco_iut_child);

    TEST_STEP("Create a pair of connected sockets of type "
              "@p sock_type on IUT and Tester.");
    GEN_CONNECTION(pco_iut_child, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Send some data from the Tester socket.");
    send_len = rand_range(1, sizeof(send_buf));
    RPC_SEND(rc, pco_tst, tst_s, send_buf, send_len, 0);

    len_arg = rand_range(sizeof(recv_buf) + 1, RAND_MAX);

    TEST_STEP("Call @p func on the IUT socket on @b pco_iut_child, passing "
              "to it too big length (in case of receive function) or too "
              "big @b nfds (in case of @b poll() / @b ppoll()).");

    RPC_AWAIT_ERROR(pco_iut_child);

    if (strcmp(func, "read") == 0)
    {
        rc = rpc_read_gen(pco_iut_child, iut_s, recv_buf, len_arg,
                          sizeof(recv_buf));
    }
    else if (strcmp(func, "recv") == 0)
    {
        rc = rpc_recv_gen(pco_iut_child, iut_s, recv_buf, len_arg,
                          0, sizeof(recv_buf));
    }
    else if (strcmp(func, "recvfrom") == 0)
    {
        from_len = sizeof(from_addr);
        rc = rpc_recvfrom_gen(pco_iut_child, iut_s, recv_buf, len_arg,
                              0, SA(&from_addr), &from_len,
                              sizeof(recv_buf), from_len);
    }
    else
    {
        pfd.fd = iut_s;
        pfd.events = RPC_POLLIN;
        pfd.revents = 0;

        len_arg = rand_range(2, RPC_POLL_NFDS_MAX);

        if (strcmp(func, "poll") == 0)
        {
            rc = rpc_poll_gen(pco_iut_child, &pfd, len_arg,
                              -1, 1);
        }
        else
        {
            rc = rpc_ppoll_gen(pco_iut_child, &pfd, len_arg,
                               NULL, RPC_NULL, 1);
        }
    }

    TEST_STEP("Check that RPC call fails and @b pco_iut_child dies "
              "due to receiving @c SIGABRT.");

    if (rc < 0)
    {
        if (RPC_ERRNO(pco_iut_child) == TE_RC(TE_RCF_PCH, TE_ERPCDEAD))
        {
            iut_s = -1;

            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_waitpid(pco_iut, iut_child_pid, &st, 0);
            if (rc < 0)
            {
                TEST_VERDICT("waitpid() failed with errno %r for a dead "
                             "IUT process", RPC_ERRNO(pco_iut));
            }
            else if (st.flag != RPC_WAIT_STATUS_CORED ||
                     st.value != RPC_SIGABRT)
            {
                TEST_VERDICT("waitpid() returned unexpected status for a "
                             "dead IUT process: %s 0x%x",
                             wait_status_flag_rpc2str(st.flag),
                             st.value);
            }

            CHECK_RC(rcf_rpc_server_finished(pco_iut_child));
        }
        else
        {
            TEST_VERDICT("%s() failed with unexpected error " RPC_ERROR_FMT,
                         func, RPC_ERROR_ARGS(pco_iut_child));
        }
    }
    else
    {
        TEST_VERDICT("%s() succeeded unexpectedly", func);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut_child, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_child));

    TEST_END;
}
