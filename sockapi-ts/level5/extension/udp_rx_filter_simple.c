/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/** @page extension-udp_rx_filter_simple Using UDP-RX filter to capture traffic
 *
 * @objective Check that UDP-RX filter callback can be used to capture
 *            all datagrams which UDP socket receives.
 *
 * @type use case
 *
 * @param env            Testing environment.
 *                       - @ref arg_types_env_peer2peer
 *                       - @ref arg_types_env_peer2peer_lo
 * @param pkt_num        Number of datagrams to send from Tester:
 *                       - @c 10
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/udp_rx_filter_simple"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut;
    rcf_rpc_server        *pco_tst;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    iut_s = -1;
    int                    tst_s = -1;

    int                    pkt_num;
    rpc_recv_f             recv_f;
    char                   buf[SOCKTS_MSG_DGRAM_MAX];
    char                   buf_captured[SOCKTS_MSG_DGRAM_MAX];
    int                    i;
    size_t                 pkt_len;
    ssize_t                rc1;
    ssize_t                rc2;
    te_bool                readable = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(pkt_num);
    TEST_GET_RECV_FUNC(recv_f);

    TEST_STEP("Create a UDP socket @b iut_s on IUT, bind it to @p iut_addr.");
    TEST_STEP("Create a UDP socket @b tst_s on Tester, bind it to @p tst_addr "
              "and connect to @p iut_addr.");

    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      SOCKTS_SOCK_UDP_NOTCONN, &iut_s, &tst_s, NULL);

    TEST_STEP("Configure packet filtering on @b iut_s.");
    rpc_onload_set_recv_filter_capture(pco_iut, iut_s, 0);

    TEST_STEP("Send @p pkt_num datagrams from @b tst_s.");

    for (i = 0; i < pkt_num; i++)
    {
        pkt_len = rand_range(1, sizeof(buf));
        te_fill_buf(buf, pkt_len);
        rpc_send(pco_tst, tst_s, buf, pkt_len, 0);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Receive datagrams one by one on @b iut_s, checking that RX filter "
              "callback receives the same datagrams in the same order.");

    for (i = 0; i < pkt_num; i++)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc1 = recv_f(pco_iut, iut_s, buf, sizeof(buf), 0);
        if (rc1 < 0)
        {
            TEST_VERDICT("Receive function unexpectedly failed "
                         "with errno %r", RPC_ERRNO(pco_iut));
        }

        RPC_AWAIT_ERROR(pco_iut);
        rc2 = rpc_sockts_recv_filtered_pkt(pco_iut, iut_s,
                                           buf_captured, sizeof(buf_captured));
        if (rc2 < 0)
        {
            TEST_VERDICT("rpc_sockts_recv_filtered_pkt() unexpectedly "
                         "failed with errno %r", RPC_ERRNO(pco_iut));
        }

        if (rc1 != rc2 || memcmp(buf, buf_captured, rc1) != 0)
        {
            RING("Received packet %d: %Tm", i, buf, rc1);
            RING("Captured packet %d: %Tm", i, buf_captured, rc2);

            TEST_VERDICT("Datagram captured by RX filter does not match "
                         "datagram received from socket");
        }
    }

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 0);
    if (readable)
        TEST_VERDICT("Socket is readable after reading all the data");

    RPC_AWAIT_ERROR(pco_iut);
    rc2 = rpc_sockts_recv_filtered_pkt(pco_iut, iut_s,
                                       buf_captured, sizeof(buf_captured));
    if (rc2 >= 0)
    {
        TEST_VERDICT("Final call of rpc_sockts_recv_filtered_pkt() "
                     "unexpectedly succeeded");
    }
    else if (RPC_ERRNO(pco_iut) != TE_RC(TE_TA_UNIX, TE_ENOENT))
    {
        TEST_VERDICT("Final call of rpc_sockts_recv_filtered_pkt() "
                     "failed with unexpected errno %r", RPC_ERRNO(pco_iut));
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    rpc_sockts_recv_filtered_pkts_clear(pco_iut);

    TEST_END;
}
