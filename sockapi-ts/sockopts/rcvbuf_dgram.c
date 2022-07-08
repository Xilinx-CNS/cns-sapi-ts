/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-rcvbuf_dgram Usage of SO_RCVBUF socket option with connectionless sockets
 *
 * @objective Check that value returned by means of getsockopt(SO_RCVBUF)
 *            is effective recieve buffer length.
 *
 * @note This tests checks the number of datagram (datagram length is
 *       payload_len + headers_len) that can be placed to receive buffer
 *       in accordance with effective receive buffer length.
 *       Linux implementation is very strange - in reality it does not
 *       provide to user the receive buffer according to value returned
 *       by getsockopt(SO_RCVBUF).
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_tst
 *                      - @ref arg_types_env_peer2peer_lo
 * @param payload_len   The length of udp datagram payload
 * @param rcvbuf_new    The length to be used in setsockopt(SO_RCVBUF)
 * @param force         If @c TRUE, check SO_RCVBUFFORCE
 *
 * @par Test sequence:
 *
 * @note Some implementations do not allow set SO_RCVBUF value precisely,
 *       so this test checks that returned SO_RCVBUF value are
 *       effective for user.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/rcvbuf_dgram"

#include "sockapi-test.h"

/**
 * Acceptable difference between received packets number and
 * expected packets number, as share of arithmetic mean.
 */
#define ACCEPTABLE_DIFF 0.45

/** Maximum length of packet. */
#define MAX_PKT_LEN 2000

/**
 * Overfill receive buffer on IUT by sending a lot of packets from
 * peer.
 *
 * @param pco_tst         RPC server on Tester.
 * @param tst_s           UDP socket on Tester.
 * @param iut_addr        Address/port to which IUT socket is bound.
 * @param payload_len     How many bytes to send in each packet.
 * @param rcvbuf_len      SO_RCVBUF value on IUT socket.
 * @param exp_pkts_len    Expected number of packets which can fit
 *                        into receive buffer on IUT (ignored if zero).
 */
static void
overfill_receive_buffer(rcf_rpc_server *pco_tst,
                        int tst_s,
                        const struct sockaddr *iut_addr,
                        size_t payload_len,
                        size_t rcvbuf_len,
                        unsigned int exp_pkts_num)
{
    char         data[MAX_PKT_LEN];
    unsigned int i;
    unsigned int max_pkts;

    if (payload_len > sizeof(data))
    {
        TEST_FAIL("Too long packet length %" TE_PRINTF_SIZE_T "u",
                  payload_len);
    }

    if (exp_pkts_num == 0)
        max_pkts = (rcvbuf_len / payload_len) * 2;
    else
        max_pkts = exp_pkts_num * 2;

    for (i = 0; i < max_pkts; i++)
    {
        te_fill_buf(data, payload_len);
        pco_tst->silent = TRUE;
        rpc_sendto(pco_tst, tst_s, data, payload_len, 0, iut_addr);
    }
    RING("%u packets were sent", max_pkts);
}

/**
 * Receive all packets on IUT socket.
 *
 * @param pco_iut         RPC server on IUT.
 * @param iut_s           UDP socket on IUT.
 * @param payload_len     Expected number of bytes in each packet.
 * @param pkts_num        Where to save number of received packets.
 */
static void
receive_packets(rcf_rpc_server *pco_iut,
                int iut_s, size_t payload_len,
                unsigned int *pkts_num)
{
    char   data[MAX_PKT_LEN];

    ssize_t       rc;
    unsigned int  received_pkts = 0;

    while (TRUE)
    {
        RPC_AWAIT_ERROR(pco_iut);
        pco_iut->silent = TRUE;
        rc = rpc_recv(pco_iut, iut_s, data, sizeof(data),
                      RPC_MSG_DONTWAIT);
        if (rc < 0)
        {
            if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            {
                TEST_VERDICT("recv() failed with unexpected errno %r",
                             RPC_ERRNO(pco_iut));
            }
            else
            {
                break;
            }
        }
        else
        {
            if (rc != (ssize_t)payload_len)
            {
                ERROR("recv() returned unexpected value %u",
                      (unsigned int)rc);
                TEST_VERDICT("Packet of unexpected length was received");
            }

            received_pkts++;
        }
    }

    *pkts_num = received_pkts;
}

/**
 * Measure number of packets which fit into receive buffer of IUT socket.
 *
 * @param pco_iut         RPC server on IUT.
 * @param pco_tst         RPC server on Tester.
 * @param iut_s           UDP socket on IUT.
 * @param tst_s           UDP socket on Tester.
 * @param iut_addr        Address/port to which IUT socket is bound.
 * @param payload_len     How many bytes to send in each packet.
 * @param rcvbuf_len      SO_RCVBUF value on IUT socket.
 * @param exp_pkts_len    Expected number of packets which can fit
 *                        into receive buffer on IUT (ignored if zero).
 * @param pkts_num        Where to save number of received packets.
 */
static void
overfill_receive_packets(rcf_rpc_server *pco_iut,
                         rcf_rpc_server *pco_tst,
                         int iut_s, int tst_s,
                         const struct sockaddr *iut_addr,
                         size_t payload_len, size_t rcvbuf_len,
                         unsigned int exp_pkts_num,
                         unsigned int *pkts_num)
{
    RING("Testing receive buffer...");

    overfill_receive_buffer(pco_tst, tst_s, iut_addr, payload_len,
                            rcvbuf_len, exp_pkts_num);
    VSLEEP(1, "Wait for network action");
    receive_packets(pco_iut, iut_s, payload_len, pkts_num);

    RING("%u packets were received", *pkts_num);
}

/**
 * Compare numbers of received packets.
 *
 * @param num1        The first number.
 * @param num2        The second number.
 *
 * @return Comparison result.
 *
 * @retval 0   if numbers does not differ too much.
 * @retval -1  if the first number is significantly
 *             smaller than the second.
 * @retval  1  if the first number is significantly
 *             bigger than the second.
 */
static int
pkts_num_cmp(unsigned int num1, unsigned int num2)
{
    double diff;

    /* Compute difference as a share of arithmetic mean */
    diff = ((double)num1 - (double)num2) / (double)(num1 + num2) * 2.0;
    if (diff < -ACCEPTABLE_DIFF)
        return -1;
    else if (diff > ACCEPTABLE_DIFF)
        return 1;

    return 0;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    size_t                 rcvbuf_init;
    int                    opt_val;
    int                    rcvbuf_new;
    int                    payload_len;
    te_bool                force;

    unsigned int  pkts_num1 = 0;
    unsigned int  pkts_num2 = 0;
    unsigned int  pkts_num3 = 0;
    unsigned int  pkts_num3_exp = 0;
    int           cmp_rc = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_INT_PARAM(payload_len);
    TEST_GET_INT_PARAM(rcvbuf_new);
    TEST_GET_BOOL_PARAM(force);

    TEST_STEP("Create UDP sockets on IUT and Tester, binding them to "
              "@p iut_addr and @p tst_addr.");

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);

    tst_s = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       tst_addr);

    /*
     * L5 specific: first dgram is transmitted via O/S stack,
     * so send some packets before checking SO_RCVBUF.
     */
    sockts_test_udp_sendto(pco_tst, tst_s, pco_iut, iut_s, iut_addr);

    TEST_STEP("Set @c SO_RCVBUF for IUT socket to @p rcvbuf_new, obtain resulting "
              "value from @b getsockopt().");

    opt_val = rcvbuf_new;
    rpc_setsockopt(pco_iut, iut_s,
                   (force ? RPC_SO_RCVBUFFORCE : RPC_SO_RCVBUF),
                   &opt_val);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &opt_val);
    rcvbuf_init = opt_val;

    TEST_STEP("Send a lot of packets from Tester (more than @c SO_RCVBUF value "
              "divided by @p payload_len). Wait for a while and receive all "
              "packets from IUT socket, saving their number in @b pkts_num1.");

    overfill_receive_packets(pco_iut, pco_tst, iut_s, tst_s, iut_addr,
                             payload_len, opt_val, 0, &pkts_num1);

    TEST_STEP("Do the same the second time, now saving number of received "
              "packets in @b pkts_num2");

    overfill_receive_packets(pco_iut, pco_tst, iut_s, tst_s, iut_addr,
                             payload_len, opt_val, 0, &pkts_num2);

    TEST_STEP("Check that @b pkts_num1 and @b pkts_num2 do not differ too much.");

    if (pkts_num_cmp(pkts_num1, pkts_num2) != 0)
    {
        TEST_VERDICT("The same SO_RCVBUF allows to receive too different "
                     "numbers of packets of the same size");
    }

    TEST_STEP("Set @c SO_RCVBUF for IUT socket to @p rcvbuf_new * 3, obtain "
              "really set value via @b getsockopt().");

    opt_val = rcvbuf_new * 3;
    rpc_setsockopt(pco_iut, iut_s,
                   (force ? RPC_SO_RCVBUFFORCE : RPC_SO_RCVBUF),
                   &opt_val);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &opt_val);

    TEST_STEP("Again send a lot of packets from Tester and receive all "
              "possible packets on IUT socket afterwards. Check that number "
              "of received packets has grown in roughly the same proportion "
              "as value of @c SO_RCVBUF.");

    pkts_num3_exp = (double)(pkts_num1 + pkts_num2) / 2.0 *
                                ((double)opt_val / (double)rcvbuf_init);
    overfill_receive_packets(pco_iut, pco_tst, iut_s, tst_s, iut_addr,
                             payload_len, opt_val, pkts_num3_exp,
                             &pkts_num3);

    RING("Expected number of packets after SO_RCVBUF increase: %u",
         pkts_num3_exp);

    cmp_rc = pkts_num_cmp(pkts_num3, pkts_num3_exp);
    if (cmp_rc != 0)
    {
        TEST_VERDICT("After increasing SO_RCVBUF significantly %s "
                     "packets than expected were received",
                     (cmp_rc > 0 ? "more" : "less"));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}

