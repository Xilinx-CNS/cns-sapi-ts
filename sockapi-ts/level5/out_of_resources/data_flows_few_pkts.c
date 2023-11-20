/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific tests reproducing run out of resources
 */

/** @page level5-out_of_resources-data_flows_few_pkts Sending/receiving with a few packet buffers
 *
 * @objective Check what happens when a lot of data is sent/received over
 *            multiple TCP connections when there is a small number of
 *            packet buffers available.
 *
 * @type conformance, robustness
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/out_of_resources/data_flows_few_pkts"

#include "sockapi-test.h"

/** Value to set for EF_MAX_PACKETS */
#define MAX_PACKETS 1024

/** How many TCP connections to open */
#define TEST_CONNS 50

/** How long to transmit data, in seconds */
#define TRANSMIT_TIME 120

/** How long to receive data, in seconds */
#define RECEIVE_TIME (TRANSMIT_TIME + 10)

/**
 * Maximum time to wait for termination after
 * TRANSMIT_TIME expired, in seconds
 */
#define WAIT_AFTER_TRANSMIT 30

/** Structure describing TCP connection */
typedef struct tcp_conn {
    int sender_s; /**< Sender socket */
    int receiver_s; /**< Receiver socket */

    rcf_rpc_server *rpcs_sender; /**< Sender RPC server */
    rcf_rpc_server *rpcs_receiver; /**< Receiver RPC server */

    tapi_pat_sender sender_ctx; /**< Pattern sender context */
    tapi_pat_receiver receiver_ctx; /**< Pattern receiver context */

    const char *sender_name; /**< Sender name to print in verdicts */
    const char *receiver_name; /**< Receiver name to print in verdicts */
} tcp_conn;

/**
 * Call rpc_pattern_sender() and rpc_pattern_receiver() on
 * a pair of connected TCP sockets with RCF_RPC_CALL.
 *
 * @param conn      TCP connection description.
 */
static void
call_sender_receiver(tcp_conn *conn)
{
    conn->rpcs_sender->op = RCF_RPC_CALL;
    rpc_pattern_sender(conn->rpcs_sender, conn->sender_s,
                       &conn->sender_ctx);

    conn->rpcs_receiver->op = RCF_RPC_CALL;
    rpc_pattern_receiver(conn->rpcs_receiver, conn->receiver_s,
                         &conn->receiver_ctx);
}

/**
 * Wait for termination of rpc_pattern_sender() and rpc_pattern_receiver()
 * on a pair of connected TCP sockets. Check what they return.
 *
 * @param conn      TCP connection description.
 */
static void
wait_sender_receiver(tcp_conn *conn)
{
    int rc;

    conn->rpcs_sender->timeout = TE_SEC2MS(TRANSMIT_TIME +
                                           WAIT_AFTER_TRANSMIT);
    RPC_AWAIT_ERROR(conn->rpcs_sender);
    rc = rpc_pattern_sender(conn->rpcs_sender, conn->sender_s,
                            &conn->sender_ctx);
    if (rc < 0)
    {
        TEST_VERDICT("rpc_pattern_sender() failed on %s with "
                     "error " RPC_ERROR_FMT, conn->sender_name,
                     RPC_ERROR_ARGS(conn->rpcs_sender));
    }

    conn->rpcs_receiver->timeout = TE_SEC2MS(TRANSMIT_TIME +
                                             WAIT_AFTER_TRANSMIT);
    RPC_AWAIT_ERROR(conn->rpcs_receiver);
    rc = rpc_pattern_receiver(conn->rpcs_receiver, conn->receiver_s,
                              &conn->receiver_ctx);
    if (rc < 0)
    {
        TEST_VERDICT("rpc_pattern_receiver() failed on %s with "
                     "error " RPC_ERROR_FMT, conn->receiver_name,
                     RPC_ERROR_ARGS(conn->rpcs_receiver));
    }

    if (conn->sender_ctx.sent != conn->receiver_ctx.received)
    {
        TEST_VERDICT("Number of bytes sent from %s does not match number "
                     "of bytes received on %s", conn->sender_name,
                     conn->receiver_name);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    rcf_rpc_server *sender_base_rpcs = NULL;
    rcf_rpc_server *receiver_base_rpcs = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    const struct sockaddr *sender_base_addr = NULL;
    const struct sockaddr *receiver_base_addr = NULL;

    struct sockaddr_storage sender_bind_addr;
    struct sockaddr_storage receiver_bind_addr;

    te_bool existed_max_packets;
    int init_max_packets;
    te_bool rollback_max_packets = FALSE;

    char rpc_name[RCF_MAX_NAME];
    tcp_conn conns[TEST_CONNS];
    int i;

    int iut_s = -1;
    int tst_s = -1;
    uint64_t sent;

    te_bool normal_termination = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memset(&conns, 0, sizeof(conns));

    TEST_STEP("Set @c EF_MAX_PACKETS to a small value on IUT. "
              "Restart @p pco_iut.");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_MAX_PACKETS",
                                      MAX_PACKETS, TRUE,
                                      &existed_max_packets,
                                      &init_max_packets));
    rollback_max_packets = TRUE;

    TEST_STEP("Establish many TCP connections between IUT and Tester.");
    for (i = 0; i < TEST_CONNS; i++)
    {
        sockts_init_pat_sender_receiver(&conns[i].sender_ctx,
                                        &conns[i].receiver_ctx,
                                        SOCKTS_MSG_STREAM_MAX,
                                        SOCKTS_MSG_STREAM_MAX,
                                        TRANSMIT_TIME, RECEIVE_TIME,
                                        TE_SEC2MS(TRANSMIT_TIME));

        if (i % 2 == 0)
        {
            sender_base_rpcs = pco_iut;
            receiver_base_rpcs = pco_tst;
            sender_base_addr = iut_addr;
            receiver_base_addr = tst_addr;
            conns[i].sender_name = "IUT";
            conns[i].receiver_name = "Tester";
        }
        else
        {
            sender_base_rpcs = pco_tst;
            receiver_base_rpcs = pco_iut;
            sender_base_addr = tst_addr;
            receiver_base_addr = iut_addr;
            conns[i].sender_name = "Tester";
            conns[i].receiver_name = "IUT";
        }

        CHECK_RC(tapi_sockaddr_clone(sender_base_rpcs, sender_base_addr,
                                     &sender_bind_addr));
        CHECK_RC(tapi_sockaddr_clone(receiver_base_rpcs, receiver_base_addr,
                                     &receiver_bind_addr));

        TE_SPRINTF(rpc_name, "%s_child_%d", sender_base_rpcs->name, i);
        CHECK_RC(rcf_rpc_server_thread_create(sender_base_rpcs, rpc_name,
                                              &conns[i].rpcs_sender));

        TE_SPRINTF(rpc_name, "%s_child_%d", receiver_base_rpcs->name, i);
        CHECK_RC(rcf_rpc_server_thread_create(receiver_base_rpcs, rpc_name,
                                              &conns[i].rpcs_receiver));

        GEN_CONNECTION(conns[i].rpcs_sender, conns[i].rpcs_receiver,
                       RPC_SOCK_STREAM, RPC_PROTO_DEF,
                       SA(&sender_bind_addr), SA(&receiver_bind_addr),
                       &conns[i].sender_s, &conns[i].receiver_s);
    }

    TEST_STEP("Start transmitting data over the established TCP "
              "connections with help of @b rpc_pattern_sender() and "
              "@b rpc_pattern_receiver(). For every connection use a "
              "separate thread on IUT and Tester. On IUT receive data "
              "from some connections and send it over other ones.");

    for (i = 0; i < TEST_CONNS; i++)
        call_sender_receiver(&conns[i]);

    TEST_STEP("Create a pair of connected UDP sockets on IUT and Tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Start sending data from the Tester UDP socket with help of "
              "@b rpc_simple_sender(). Do not receive it on IUT. "
              "Wait until sending terminates.");
    pco_tst->timeout = TE_SEC2MS(TRANSMIT_TIME + WAIT_AFTER_TRANSMIT);
    rpc_simple_sender(pco_tst, tst_s, 1, SOCKTS_MSG_DGRAM_MAX, 0, 0, 0, 1,
                      TRANSMIT_TIME, &sent, 1);

    TEST_STEP("Read all the available data on the IUT UDP socket.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_drain_fd(pco_iut, iut_s, SOCKTS_MSG_DGRAM_MAX,
                      TAPI_WAIT_NETWORK_DELAY, NULL);
    if (rc < 0 && RPC_ERRNO(pco_iut) != RPC_EAGAIN)
    {
        TEST_VERDICT("rpc_drain_fd() failed unexpectedly with error "
                     RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }

    TEST_STEP("For each TCP connection, wait for termination of "
              "@p rpc_pattern_sender() and @b rpc_pattern_receiver().");

    for (i = 0; i < TEST_CONNS; i++)
        wait_sender_receiver(&conns[i]);

    normal_termination = TRUE;

    TEST_SUCCESS;

cleanup:

    if (normal_termination)
    {
        for (i = 0; i < TEST_CONNS; i++)
        {
            CLEANUP_RPC_CLOSE(conns[i].rpcs_sender, conns[i].sender_s);
            CLEANUP_RPC_CLOSE(conns[i].rpcs_receiver, conns[i].receiver_s);
            CLEANUP_CHECK_RC(rcf_rpc_server_destroy(conns[i].rpcs_sender));
            CLEANUP_CHECK_RC(rcf_rpc_server_destroy(conns[i].rpcs_receiver));
        }

        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
        CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    }
    else
    {
        /*
         * Here one or more RPC servers may be dead due to RPC call
         * timeout or still hang with not finished RPC call,
         * so it's better not to try to close sockets.
         * Waiting for every remaining RPC call will waste too
         * much time, so instead main RPC servers are restarted.
         */

        for (i = 0; i < TEST_CONNS && conns[i].rpcs_sender != NULL; i++)
        {
            CLEANUP_CHECK_RC(
                        rcf_rpc_server_finished(conns[i].rpcs_sender));
            CLEANUP_CHECK_RC(
                        rcf_rpc_server_destroy(conns[i].rpcs_sender));
        }

        for (i = 0; i < TEST_CONNS && conns[i].rpcs_receiver != NULL; i++)
        {
            CLEANUP_CHECK_RC(
                        rcf_rpc_server_finished(conns[i].rpcs_receiver));
            CLEANUP_CHECK_RC(
                        rcf_rpc_server_destroy(conns[i].rpcs_receiver));
        }

        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));
        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_tst));
    }

    if (rollback_max_packets)
    {
        CLEANUP_CHECK_RC(tapi_sh_env_rollback_int(pco_iut, "EF_MAX_PACKETS",
                                                  existed_max_packets,
                                                  init_max_packets, TRUE));
    }

    TEST_END;
}
