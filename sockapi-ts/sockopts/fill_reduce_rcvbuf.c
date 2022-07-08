/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-fill_reduce_rcvbuf Changing size of receive buffer after filling it
 *
 * @objective Check what happens when @c SO_RCVBUF is reduced on a TCP
 *            socket after filling receive buffer, and then more data
 *            is sent from peer.
 *
 * @type conformance, robustness
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type       Socket type:
 *                        - @c tcp_active
 *                        - @c tcp_passive
 *                        - @c tcp_passive_close
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/fill_reduce_rcvbuf"

#include "sockapi-test.h"

/** Minimum initial SO_RCVBUF value */
#define MIN_INIT_RCVBUF 30000
/** Maximum initial SO_RCVBUF value */
#define MAX_INIT_RCVBUF 100000

/** Size of send buffer on Tester socket */
#define TST_SNDBUF 30000

/** Coefficient of SO_RCVBUF reduction */
#define BUF_REDUCE_COEFF 0.1

/**
 * How many bytes to send before the buffer reduction, in
 * units of initial SO_RCVBUF size
 */
#define FIRST_SEND_COEFF 0.3

/**
 * How many bytes to send after the buffer reduction, in
 * units of initial SO_RCVBUF size
 */
#define SECOND_SEND_COEFF 10.0

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    sockts_socket_type sock_type;

    int iut_l = -1;
    int iut_s = -1;
    int tst_s = -1;

    int init_rcvbuf;
    int init_rcvbuf_real;
    int reduced_rcvbuf;
    int reduced_rcvbuf_real;
    int tst_sndbuf;

    tapi_pat_sender sender_ctx;
    tapi_pat_receiver receiver_ctx;
    uint64_t total_sent = 0;
    uint64_t max_allowed = 0;

    te_bool test_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    sockts_init_pat_sender_receiver(&sender_ctx, &receiver_ctx,
                                    SOCKTS_MSG_STREAM_MAX / 2,
                                    SOCKTS_MSG_STREAM_MAX,
                                    TE_MS2SEC(pco_iut->def_timeout),
                                    TE_MS2SEC(pco_iut->def_timeout),
                                    TAPI_WAIT_NETWORK_DELAY);

    TEST_STEP("Create a pair of TCP sockets on IUT and Tester.");

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Choose randomly @b init_rcvbuf value; choose "
              "@b reduced_rcvbuf to be multiple times lower than it.");
    init_rcvbuf = rand_range(MIN_INIT_RCVBUF, MAX_INIT_RCVBUF);
    reduced_rcvbuf = init_rcvbuf * BUF_REDUCE_COEFF;

    TEST_STEP("Set @c SO_RCVBUF for the IUT socket to @b init_rcvbuf; "
              "get actually set value @b init_rcvbuf_real with help "
              "of @b getsockopt().");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_RCVBUF, init_rcvbuf);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &init_rcvbuf_real);

    TEST_STEP("Set @c SO_SNDBUF to a specific value on the Tester socket "
              "to avoid its dynamical adjustment. Obtain actually set "
              "value @b tst_sndbuf with @b getsockopt().");
    rpc_setsockopt_int(pco_tst, tst_s, RPC_SO_SNDBUF, TST_SNDBUF);
    rpc_getsockopt(pco_tst, tst_s, RPC_SO_SNDBUF, &tst_sndbuf);

    TEST_STEP("Establish connection between IUT and Tester sockets "
              "according to @p sock_type.");
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, FALSE, TRUE, NULL,
                      &iut_s, &tst_s, &iut_l,
                      SOCKTS_SOCK_FUNC_SOCKET);

    TEST_STEP("Call @b rpc_pattern_sender() to send initial portion of "
              "data from Tester. Number of bytes should be less than "
              "@b init_rcvbuf_real but more than "
              "2 * @b rcvbuf_reduced.");
    sender_ctx.total_size = init_rcvbuf_real * FIRST_SEND_COEFF;
    rpc_pattern_sender(pco_tst, tst_s, &sender_ctx);
    total_sent += sender_ctx.sent;

    TAPI_WAIT_NETWORK;

    TEST_STEP("Set @c SO_RCVBUF on the IUT socket to @b reduced_rcvbuf.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_RCVBUF, reduced_rcvbuf);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &reduced_rcvbuf_real);

    if (reduced_rcvbuf_real >= (int)(sender_ctx.total_size))
    {
        TEST_FAIL("Receive buffer size was not reduced to expectedly "
                  "low value");
    }

    TEST_STEP("With help of @b rpc_pattern_sender() send the second "
              "portion of data from the Tester socket. It should attempt "
              "to send significantly more than @b init_rcvbuf_real + "
              "@b tst_sndbuf.");
    sender_ctx.total_size =
        init_rcvbuf_real * SECOND_SEND_COEFF + tst_sndbuf;
    rpc_pattern_sender(pco_tst, tst_s, &sender_ctx);
    total_sent += sender_ctx.sent;
    max_allowed = (uint64_t)init_rcvbuf_real + tst_sndbuf;

    TEST_STEP("Check that no more was sent by both @b rpc_pattern_sender() "
              "calls than @b init_rcvbuf_real + @b tst_sndbuf bytes.");

    RING("Total number of bytes sent: %llu, maximum allowed: %llu",
         (long long unsigned int)total_sent,
         (long long unsigned int)max_allowed);

    if (total_sent > max_allowed + init_rcvbuf_real)
    {
        ERROR_VERDICT("Much more data was sent than original receive "
                      "buffer size allows");
        test_failed = TRUE;
    }
    else if (total_sent > max_allowed)
    {
        WARN_VERDICT("More data was sent than original receive "
                     "buffer size allows");
    }

    TEST_STEP("Receive and check all data on IUT.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_pattern_receiver(pco_iut, iut_s, &receiver_ctx);
    if (rc < 0)
    {
        TEST_VERDICT("rpc_pattern_receiver() failed on IUT with error "
                     RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    if (receiver_ctx.received != total_sent)
    {
        TEST_VERDICT("Number of bytes received differs from number of "
                     "bytes sent");
    }

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);

    TEST_END;
}
