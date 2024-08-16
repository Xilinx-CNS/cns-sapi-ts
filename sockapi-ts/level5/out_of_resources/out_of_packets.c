/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific tests reproducing run out of hardware resources
 */


/** @page level5-out_of_resources-out_of_packets Sending hangs due to lack of packet buffers
 *
 * @objective Check that sending can block if there is not enough packet
 *            buffers, and it can be unblocked by releasing some of them.
 *
 * @type conformance, robustness
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_peer2peer
 *                            - @ref arg_types_env_peer2peer_ipv6
 * @param create_process      If @c TRUE, create the second IUT socket in a
 *                            new process; else - in a new thread.
 * @param udp_send            If @c TRUE, create additional UDP socket
 *                            on IUT and check that @b send() eventually
 *                            hangs on it.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/out_of_resources/out_of_packets"

#include "out_of_resources.h"

/** Name of the shared Onload stack */
#define STACK_NAME "foo"

/** Value to set for EF_MAX_PACKETS */
#define MAX_PACKETS 1024

/** Value to set for EF_MAX_RX_PACKETS */
#define MAX_RX_PACKETS (MAX_PACKETS - 10)

/**
 * Time to wait for writability or readability on a socket
 * before stopping sending/receiving, in milliseconds.
 */
#define TIME2WAIT 2000

/**
 * Maximum time sending or receiving can take when filling or
 * releasing receive buffer, in seconds.
 */
#define TRANSMIT_TIME 10

/**
 * How many bytes to pass to a single send() call on Tester.
 */
#define TST_DATA_LEN 1000

/**
 * Maximum number of bytes to pass to a single send() call
 * on IUT.
 */
#define MAX_IUT_DATA_LEN 1000

/** Size of the receive buffer on IUT */
#define IUT_RCV_BUF_SIZE (TST_DATA_LEN * MAX_PACKETS * 2)

/** Size of the receive buffer on Tester */
#define TST_RCV_BUF_SIZE 2048

/**
 * Call rpc_pattern_receiver() and check that it received all the
 * data previously sent with rpc_pattern_sender().
 *
 * @param rpcs            RPC server.
 * @param s               Socket FD.
 * @param recv_ctx        Arguments for rpc_pattern_receiver().
 * @param send_ctx        Arguments previously passed to
 *                        rpc_pattern_sender().
 */
static void
check_pattern_receiver(rcf_rpc_server *rpcs, int s,
                       tapi_pat_receiver *recv_ctx,
                       tapi_pat_sender *send_ctx)
{
    int rc;

    RPC_AWAIT_ERROR(rpcs);
    rpcs->timeout = TE_SEC2MS(TRANSMIT_TIME + 1);
    rc = rpc_pattern_receiver(rpcs, s, recv_ctx);
    if (rc < 0)
    {
        TEST_VERDICT("rpc_pattern_receiver() unexpectedly failed with "
                     "error " RPC_ERROR_FMT " on %s",
                     RPC_ERROR_ARGS(rpcs), rpcs->name);
    }
    if (send_ctx->sent != recv_ctx->received)
    {
        ERROR("%lu bytes were received instead of %lu",
              (long unsigned int)(recv_ctx->received),
              (long unsigned int)(send_ctx->sent));

        TEST_VERDICT("rpc_pattern_receiver() received unexpected number of "
                     "bytes on %s", rpcs->name);
    }
}

/**
 * Receive and check data sent from an UDP socket.
 *
 * @param rpcs      RPC server where to receive data.
 * @param s         UDP socket on which to receive.
 * @param send_buf  Sent data.
 * @param send_rc   What send() on peer returned.
 * @param send_len  How many bytes should have been sent.
 * @param msg       Prefix to print in verdicts in case of failure.
 */
static void
receive_check_udp(rcf_rpc_server *rpcs, int s, char *send_buf,
                  int send_rc, int send_len, const char *msg)
{
    char recv_buf[MAX_IUT_DATA_LEN];
    te_bool readable;
    int rc;

    if (send_rc != send_len)
    {
        ERROR("UDP socket sent %d bytes instead of %d",
              send_rc, send_len);

        TEST_VERDICT("%s: UDP socket sent unexpected amount of bytes",
                     msg);
    }

    RPC_GET_READABILITY(readable, rpcs, s, TAPI_WAIT_NETWORK_DELAY);
    if (!readable)
    {
        TEST_VERDICT("%s: UDP socket on Tester is not readable",
                     msg);
    }

    rc = rpc_recv(rpcs, s, recv_buf, sizeof(recv_buf), 0);
    if (rc != send_len)
    {
        TEST_VERDICT("%s: UDP socket on Tester received unexpected "
                     "amount of data", msg);
    }

    if (memcmp(recv_buf, send_buf, send_len) != 0)
    {
        TEST_VERDICT("%s: UDP socket on Tester received unexpected "
                     "data", msg);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_iut_aux = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    te_bool existed_max_packets;
    int init_max_packets;
    te_bool rollback_max_packets = FALSE;

    te_bool existed_max_rx_packets;
    int init_max_rx_packets;
    te_bool rollback_max_rx_packets = FALSE;

    te_bool existed_ef_name;
    char *init_ef_name = NULL;
    te_bool rollback_ef_name = FALSE;

    te_bool create_process;
    te_bool udp_send;

    int iut_s1 = -1;
    int tst_s1 = -1;
    int tst_s_listener = -1;

    int iut_s2 = -1;
    int tst_s2 = -1;
    int iut_s3 = -1;
    int tst_s3 = -1;
    int iut_s = -1;
    const char *sock_name = "";

    te_dbuf iut_s2_sent = TE_DBUF_INIT(0);
    te_dbuf tst_s2_recv = TE_DBUF_INIT(0);

    tapi_pat_sender tst_sender_ctx;
    tapi_pat_receiver iut_receiver_ctx;

    char send_buf[MAX_IUT_DATA_LEN];
    int send_len;
    int send_rc;
    te_bool done;
    te_bool send_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(create_process);
    TEST_GET_BOOL_PARAM(udp_send);

    if (create_process)
    {
        TEST_STEP("If @p create_process is @c TRUE, set @c EF_NAME "
                  "to ensure that Onload stack is shared between "
                  "processes.");
        CHECK_RC(tapi_sh_env_save_set(pco_iut, "EF_NAME", &existed_ef_name,
                                      &init_ef_name, STACK_NAME, FALSE));
        rollback_ef_name = TRUE;
    }

    TEST_STEP("Set @c EF_MAX_RX_PACKETS to a small value on IUT.");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_MAX_RX_PACKETS",
                                      MAX_RX_PACKETS, FALSE,
                                      &existed_max_rx_packets,
                                      &init_max_rx_packets));
    rollback_max_rx_packets = TRUE;

    TEST_STEP("Set @c EF_MAX_PACKETS to a slightly larger value on IUT. "
              "Restart @p pco_iut. ");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_MAX_PACKETS",
                                      MAX_PACKETS, TRUE,
                                      &existed_max_packets,
                                      &init_max_packets));
    rollback_max_packets = TRUE;

    TEST_STEP("Create additional RPC server @b pco_iut_aux on IUT "
              "according to @p create_process.");
    if (create_process)
    {
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_aux",
                                     &pco_iut_aux));
    }
    else
    {
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_iut_aux",
                                              &pco_iut_aux));
    }

    TEST_STEP("Create TCP socket on @p pco_iut, set receive buffer size "
              "to a large value with @c SO_RCVBUFFORCE.");

    iut_s1 = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                        RPC_PROTO_DEF, FALSE, FALSE,
                                        iut_addr);
    rpc_setsockopt_int(pco_iut, iut_s1, RPC_SO_RCVBUFFORCE,
                       IUT_RCV_BUF_SIZE);

    TEST_STEP("Create listener TCP socket on Tester, binding it to "
              "@b tst_addr and setting a small receive buffer size "
              "for it.");

    tst_s_listener = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_STREAM,
                                                RPC_PROTO_DEF, FALSE, FALSE,
                                                tst_addr);
    rpc_setsockopt_int(pco_tst, tst_s_listener, RPC_SO_RCVBUF,
                       TST_RCV_BUF_SIZE);
    rpc_listen(pco_tst, tst_s_listener, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Connect the IUT socket to @b tst_addr, accept connection "
              "on Tester.");

    rpc_connect(pco_iut, iut_s1, tst_addr);
    tst_s1 = rpc_accept(pco_tst, tst_s_listener, NULL, NULL);

    TEST_STEP("Enable @c TCP_NODELAY on the accepted Tester socket to make "
              "sure that data is sent as soon as possible.");
    rpc_setsockopt_int(pco_tst, tst_s1, RPC_TCP_NODELAY, 1);

    TEST_STEP("Create the second TCP socket on IUT (using @b pco_iut_aux), "
              "connect it to @p tst_addr, accept connection on Tester "
              "(obtaining the second connected socket on Tester).");
    iut_s2 = rpc_socket(pco_iut_aux,
                        rpc_socket_domain_by_addr(tst_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_iut_aux, iut_s2, tst_addr);
    tst_s2 = rpc_accept(pco_tst, tst_s_listener, NULL, NULL);

    if (udp_send)
    {
        TEST_STEP("If @p udp_send is @c TRUE, create the third (UDP) "
                  "socket on IUT (using @b pco_iut_aux) and its peer "
                  "on Tester.");

        iut_s3 = rpc_socket(pco_iut_aux,
                            rpc_socket_domain_by_addr(tst_addr),
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_connect(pco_iut_aux, iut_s3, tst_addr);

        tst_s3 = rpc_socket(pco_tst,
                            rpc_socket_domain_by_addr(tst_addr),
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_s3, tst_addr);
    }

    sockts_init_pat_sender_receiver(&tst_sender_ctx, &iut_receiver_ctx,
                                    TST_DATA_LEN, TST_DATA_LEN,
                                    TRANSMIT_TIME, TRANSMIT_TIME + 1,
                                    TIME2WAIT);

    TEST_STEP("With @b rpc_pattern_sender() send as much data as possible "
              "from the first Tester socket.");
    pco_tst->timeout = TE_SEC2MS(TRANSMIT_TIME + 1);
    rpc_pattern_sender(pco_tst, tst_s1, &tst_sender_ctx);

    TEST_STEP("Call @b send() with @c MSG_DONTWAIT on IUT in a loop until "
              "the call blocks.");
    TEST_SUBSTEP("If @p udp_send is @c TRUE, alternate sending data "
                 "from the second TCP IUT socket and from the UDP "
                 "IUT socket. Expect that eventually @b send() on "
                 "the UDP IUT socket will hang.");
    TEST_SUBSTEP("Otherwise, if @p udp_send is @c FALSE, at every loop "
                 "iteration send data from the second TCP IUT socket and "
                 "expect that it will block eventually.");

    done = TRUE;
    while (TRUE)
    {
        if (udp_send && iut_s == iut_s2)
        {
            iut_s = iut_s3;
            sock_name = "UDP";
        }
        else
        {
            iut_s = iut_s2;
            sock_name = "second TCP";
        }

        send_len = rand_range(1, MAX_IUT_DATA_LEN);
        te_fill_buf(send_buf, send_len);
        pco_iut_aux->op = RCF_RPC_CALL;
        rpc_send(pco_iut_aux, iut_s, send_buf,
                 send_len, RPC_MSG_DONTWAIT);

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut_aux, &done));
        if (!done)
        {
            TAPI_WAIT_NETWORK;
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut_aux, &done));
            if (!done)
            {
                RING("send() call on the %s socket was blocked", sock_name);
                break;
            }
        }

        RPC_AWAIT_ERROR(pco_iut_aux);
        send_rc = rpc_send(pco_iut_aux, iut_s, send_buf,
                           send_len, RPC_MSG_DONTWAIT);
        if (send_rc < 0)
        {
            if (RPC_ERRNO(pco_iut_aux) != RPC_EAGAIN)
            {
                TEST_VERDICT("Not blocked send() on the %s IUT socket "
                             "failed with unexpected errno %r",
                             sock_name, RPC_ERRNO(pco_iut_aux));
            }

            if (send_failed)
                break;
            else
                TAPI_WAIT_NETWORK;

            send_failed = TRUE;
        }
        else
        {
            if (send_rc != send_len)
            {
                if (send_rc == 0)
                {
                    TEST_VERDICT("Not blocked send() on the %s IUT "
                                 "socket returned zero", sock_name);
                }
                else
                {
                    WARN("Not blocked send() on the %s IUT socket "
                         "returned unexpected value", sock_name);
                }
            }

            send_failed = FALSE;

            if (iut_s == iut_s3)
            {
                receive_check_udp(pco_tst, tst_s3, send_buf, send_rc,
                                  send_len, "After the normal send()");
            }
            else
            {
                CHECK_RC(te_dbuf_append(&iut_s2_sent, send_buf, send_rc));
            }
        }
    }

    if (done)
    {
        TEST_VERDICT("send() on IUT failed repeatedly with EAGAIN "
                     "instead of blocking");
    }

    if (udp_send && iut_s == iut_s2)
        ERROR_VERDICT("TCP send() was blocked, not UDP one");

    TEST_STEP("Read all the available data on the first IUT socket.");
    /*
     * Set time2wait big enough to get all the retransmits from tester for the
     * packets which might have been dropped due to "memory pressure" state in
     * Onload.
     */
    iut_receiver_ctx.time2wait = 60000;
    check_pattern_receiver(pco_iut, iut_s1, &iut_receiver_ctx,
                           &tst_sender_ctx);

    TEST_STEP("Check that now blocked @b send() call on IUT "
              "succeeds.");
    RPC_AWAIT_ERROR(pco_iut_aux);
    send_rc = rpc_send(pco_iut_aux, iut_s, send_buf, send_len,
                       RPC_MSG_DONTWAIT);
    if (send_rc < 0)
    {
        TEST_VERDICT("The last send() on the %s IUT socket failed "
                     "with %r", sock_name, RPC_ERRNO(pco_iut_aux));
    }
    else if (send_rc != send_len)
    {
        if (send_rc == 0)
        {
            TEST_VERDICT("The last send() on the %s IUT socket "
                         "returned zero", sock_name);
        }
        else
        {
            WARN("The last send() on the %s IUT socket "
                 "returned unexpected value", sock_name);
        }
    }
    if (iut_s == iut_s2)
        CHECK_RC(te_dbuf_append(&iut_s2_sent, send_buf, send_rc));

    TEST_STEP("Receive and check data sent from IUT on the second Tester "
              "socket.");
    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_read_fd2te_dbuf(pco_tst, tst_s2, TIME2WAIT, 0, &tst_s2_recv);
    SOCKTS_CHECK_RECV_EXT(pco_tst, iut_s2_sent.ptr, tst_s2_recv.ptr,
                          iut_s2_sent.len, tst_s2_recv.len,
                          "Receiving data on the second Tester socket");

    if (udp_send)
    {
        TEST_STEP("If @p udp_send is @c TRUE, receive and check data sent "
                  "from IUT on the UDP Tester socket.");

        receive_check_udp(pco_tst, tst_s3, send_buf, send_rc,
                          send_len, "After the blocked send()");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut_aux, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut_aux, iut_s3);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_aux));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s3);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listener);

    if (rollback_ef_name)
    {
        CLEANUP_CHECK_RC(tapi_sh_env_rollback(pco_iut, "EF_NAME",
                                              existed_ef_name,
                                              init_ef_name, FALSE));
        free(init_ef_name);
    }

    if (rollback_max_rx_packets)
    {
        CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut,
                                                  "EF_MAX_RX_PACKETS",
                                                  existed_max_rx_packets,
                                                  init_max_rx_packets,
                                                  FALSE));
    }

    if (rollback_max_packets)
    {
        CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_MAX_PACKETS",
                                                  existed_max_packets,
                                                  init_max_packets, TRUE));
    }

    te_dbuf_free(&iut_s2_sent);
    te_dbuf_free(&tst_s2_recv);

    TEST_END;
}
