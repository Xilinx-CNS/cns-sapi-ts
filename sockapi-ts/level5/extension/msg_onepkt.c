/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/**
 * @page extension-msg_onepkt Test @c ONLOAD_MSG_ONEPKT flag
 *
 * @objective Check that with @c ONLOAD_MSG_ONEPKT flag only part of data
 *            up to the next packet boundary is retrieved by a receiving
 *            function call.
 *
 * @param env               Network environment configuration:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 *                          - @ref arg_types_env_peer2peer_lo
 *                          - @ref arg_types_env_peer2peer_lo_ipv6
 * @param sock_type         Socket type:
 *                          - @c tcp_active
 *                          - @c tcp_passive_close
 * @param pkts_num          How many packets to send and receive:
 *                          - @c 100
 * @param recv_f            Receiving function to test:
 *                          - @b recv()
 *                          - @b recvfrom()
 *                          - @b recvmsg()
 * @param random_recv_size  If @c TRUE, choose size of buffer passed to
 *                          the tested function randomly. Otherwise use
 *                          buffer big enough for any incoming packet.
 * @param random_recv_flag  If @c TRUE, choose randomly whether to pass
 *                          @c ONLOAD_MSG_ONEPKT when calling the tested
 *                          function; otherwise always specify that flag.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/msg_onepkt"

#include "sockapi-test.h"
#include "onload.h"
#include "tapi_tcp.h"
#include "te_vector.h"
#include "te_dbuf.h"

/** How many packets to send in a single batch */
#define PKTS_BATCH_SIZE 10

/**
 * Send a new batch of packets if less than the following
 * number of packets remains in receive buffer.
 */
#define MIN_PKTS_TO_RECV 5

/* Information about a sent packet */
typedef struct pkt_descr {
    int start_pos;  /**< Index of the first byte in the sequence of all
                         the sent bytes */
    int len;        /**< Length of the packet */
} pkt_descr;

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    int iut_s = -1;
    int tst_s = -1;

    te_vec pkts = TE_VEC_INIT(pkt_descr);
    te_dbuf sent_data = TE_DBUF_INIT(100);
    char send_buf[SOCKTS_MSG_STREAM_MAX];
    pkt_descr pkt;
    int pkt_size;
    int i;

    int pkts_to_recv = 0;
    pkt_descr *recv_pkt;
    int recv_pkt_id = 0;

    char recv_buf[SOCKTS_MSG_STREAM_MAX * 2];
    int recv_size;
    int recv_flags;
    int exp_recv_len;
    int total_received = 0;

    sockts_socket_type sock_type;
    int pkts_num;
    rpc_recv_f recv_f;
    te_bool random_recv_size;
    te_bool random_recv_flag;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(pkts_num);
    TEST_GET_RECV_FUNC(recv_f);
    TEST_GET_BOOL_PARAM(random_recv_size);
    TEST_GET_BOOL_PARAM(random_recv_flag);

    TEST_STEP("Create a pair of connected TCP sockets on IUT and Tester "
              "according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, &iut_s, &tst_s, NULL);

    TEST_STEP("Enable @c TCP_NODELAY socket option on the Tester socket "
              "to ensure that TCP packets of specified size are sent.");
    rpc_setsockopt_int(pco_tst, tst_s, RPC_TCP_NODELAY, 1);

    TEST_STEP("Send @p pkts_num TCP packets of random length from Tester "
              "and receive them on IUT using @p recv_f function called "
              "according to @p random_recv_size and @p random_recv_flag "
              "parameters. Check that when @c ONLOAD_MSG_ONEPKT flag is "
              "set, only data up to the next packet boundary is retreived "
              "by the function call.");
    while (TRUE)
    {
        if (pkts_num > 0 && pkts_to_recv < MIN_PKTS_TO_RECV)
        {
            RING("Sending a batch of packets");

            for (i = 0; i < PKTS_BATCH_SIZE; i++)
            {
                pkt_size = rand_range(1, sizeof(send_buf));
                te_fill_buf(send_buf, pkt_size);

                pkt.start_pos = sent_data.len;
                pkt.len = pkt_size;
                CHECK_RC(te_vec_append(&pkts, &pkt));

                CHECK_RC(te_dbuf_append(&sent_data, send_buf, pkt_size));

                RPC_SEND(rc, pco_tst, tst_s, send_buf, pkt_size, 0);
                pkts_num--;
                pkts_to_recv++;
                MSLEEP(10);
                if (pkts_num == 0)
                    break;
            }

            TAPI_WAIT_NETWORK;
        }

        if (random_recv_size)
            recv_size = rand_range(1, sizeof(recv_buf));
        else
            recv_size = sizeof(recv_buf);

        if (random_recv_flag)
            recv_flags = (rand_range(1, 2) == 1 ? RPC_MSG_ONEPKT : 0);
        else
            recv_flags = RPC_MSG_ONEPKT;

        RPC_AWAIT_ERROR(pco_iut);
        rc = recv_f(pco_iut, iut_s, recv_buf, recv_size, recv_flags);
        if (rc < 0)
        {
            TEST_VERDICT("Receiving function on IUT unexpectedly failed "
                         "with error " RPC_ERROR_FMT,
                         RPC_ERROR_ARGS(pco_iut));
        }

        recv_pkt = (pkt_descr *)te_vec_get(&pkts, recv_pkt_id);

        if (recv_flags & RPC_MSG_ONEPKT)
        {
            exp_recv_len = MIN(recv_pkt->len -
                                    (total_received - recv_pkt->start_pos),
                               recv_size);
        }
        else
        {
            exp_recv_len = MIN(sent_data.len - total_received, recv_size);
        }
        if (exp_recv_len <= 0)
        {
            TEST_FAIL("Expected number of received bytes must be "
                      "positive, but it is not");
        }

        if (rc != exp_recv_len)
        {
            ERROR("%d bytes were received instead of %d",
                  rc, exp_recv_len);
            TEST_VERDICT("Receiving function returned unexpected number "
                         "of bytes");
        }
        else if (memcmp(recv_buf, sent_data.ptr + total_received, rc) != 0)
        {
            TEST_VERDICT("Received data does not match sent data");
        }

        /*
         * Find information about the packet which is going to be received
         * next. We can jump over a few packets if recv_f() without
         * ONLOAD_MSG_ONEPKT flag but with a big buffer size was called.
         */
        total_received += rc;
        while (total_received >= recv_pkt->start_pos + recv_pkt->len)
        {
            recv_pkt_id++;
            pkts_to_recv--;
            if (pkts_to_recv == 0)
                break;
            recv_pkt = (pkt_descr *)te_vec_get(&pkts, recv_pkt_id);
        }

        if (pkts_num == 0 && total_received == (int)(sent_data.len))
            break;
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    te_dbuf_free(&sent_data);
    te_vec_free(&pkts);

    TEST_END;
}
