/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * This test package contains tests for special cases of TCP protocol, such as ICMP and routing table handling, small and zero window, fragmentation of TCP packets, etc.
 */

/**
 * @page tcp-recv_unblock_fin Read (iomux) call unblocking with FIN.
 *
 * @objective Check that blocking read or iomux call is unblocked when FIN is
 *            arrived and it is not unblocked by ACK.
 *
 * @param sock_type  Socket type:
 *      - tcp active
 *      - tcp passive
 * @param out        Test OUT event if @c TRUE.
 * @param block_read Blocking in read call if @c TRUE, otherwise blocking in
 *                   iomux.
 * @param iomux      Iomux type (iterate only if @p block_read is @c FALSE):
 *      - all supported iomux types.
 * @param tst_packet Determines packets sequence of ACK and FIN which are sent
 *                   from tester:
 *      - both (FIN+ACK in one packet)
 *      - fin_ack (FIN with older ACK, then ACK-for-FIN)
 *      - ack_fin (ACK-for-FIN, then FIN)
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/recv_unblock_fin"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "iomux.h"

/**
 * Determines packets and sequence of ACK and FIN which are sent from
 * tester.
 */
typedef enum {
    TST_PACKET_BOTH = 0,   /* FIN+ACK in one packet. */
    TST_PACKET_FIN_ACK,    /* FIN with older ACK, then ACK-for-FIN. */
    TST_PACKET_ACK_FIN,    /* ACK-for-FIN, then FIN. */
} tst_packet_sequence;

#define TST_PACKET  \
    { "both", TST_PACKET_BOTH },        \
    { "fin_ack", TST_PACKET_FIN_ACK },  \
    { "ack_fin", TST_PACKET_ACK_FIN }

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway  gateway;
    sockts_socket_type  sock_type;
    te_bool             block_read;
    te_bool             out;
    tapi_iomux_type     iomux_type;
    tst_packet_sequence tst_packet;

    tapi_iomux_handle   *iomux = NULL;
    tapi_iomux_evt_fd   *evts = NULL;
    uint64_t sent = 0;
    uint64_t read = 0;
    char    *buf = NULL;
    te_bool  done;
    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(block_read);
    TEST_GET_BOOL_PARAM(out);
    TEST_GET_IOMUX_FUNC(iomux_type);
    TEST_GET_ENUM_PARAM(tst_packet, TST_PACKET);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    buf = te_make_buf_by_len(SOCKTS_MSG_STREAM_MAX);

    /*- Establish TCP connection. */
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    /*- If @p out is @c TRUE overfill IUT send buffer. */
    if (out)
    {
        rpc_overfill_buffers(pco_iut, iut_s, &sent);
        TAPI_WAIT_NETWORK;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_send(pco_iut, iut_s, buf, SOCKTS_MSG_STREAM_MAX,
                      RPC_MSG_DONTWAIT);
        if (rc > 0)
            TEST_FAIL("Send data after buffers overfilling");
    }

    /*- If @p tst_packet is @c both break channel tester->IUT using gateway. */
    if (tst_packet == TST_PACKET_BOTH)
        tapi_route_gateway_break_tst_gw(&gateway);
    /*- If @p tst_packet is @c fin_ack break channel IUT->tester. */
    else if (tst_packet == TST_PACKET_FIN_ACK)
        tapi_route_gateway_break_gw_tst(&gateway);
    if (tst_packet != TST_PACKET_ACK_FIN)
        CFG_WAIT_CHANGES;

    /*- Call shutdown(wr) on IUT socket. */
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);

    /*- Block IUT in read or iomux (set WR event if @p out is @c TRUE)
     * call in dependence on @p block_read: */
    if (block_read)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_read(pco_iut, iut_s, buf, SOCKTS_MSG_STREAM_MAX);
    }
    else
    {
        iomux = sockts_iomux_create(pco_iut, iomux_type);
        tapi_iomux_add(iomux, iut_s, EVT_RD | EVT_ERR | (out ? EVT_WR : 0));

        /*-- note, iomux is not blocked after socket shutdown if WR event
         * is set. */
        if (!out)
            pco_iut->op = RCF_RPC_CALL;
        rc = tapi_iomux_call(iomux, -1, &evts);

        if (out)
        {
            SOCKTS_CHECK_IOMUX_EVENTS(rc, 1, evts, EVT_WR,
                                      " after IUT socket shutdown");
        }
    }

    if (!out || block_read)
    {
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
        if (done)
            RING_VERDICT("IUT read/iomux call was not blocked");
    }

    /*- If @p tst_packet is @c both or @c fin_ack call shutdown(wr) on tester
     *  socket. */
     if (tst_packet == TST_PACKET_BOTH || tst_packet == TST_PACKET_FIN_ACK)
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);

    TAPI_WAIT_NETWORK;

    /*- Repair channel IUT->tester or tester->IUT if it was broken. */
    if (tst_packet == TST_PACKET_BOTH)
        tapi_route_gateway_repair_tst_gw(&gateway);
    else if (tst_packet == TST_PACKET_FIN_ACK)
        tapi_route_gateway_repair_gw_tst(&gateway);
    if (tst_packet != TST_PACKET_ACK_FIN)
        CFG_WAIT_CHANGES;

    /*- If @p tst_packet is @c ack_fin: */
    if (tst_packet == TST_PACKET_ACK_FIN)
    {
        /*-- check IUT is still blocked (if it is not iomux(WR)); */
        if (!out || block_read)
        {
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
            if (done)
                RING_VERDICT("IUT read/iomux call was unexpectedly unblocked");
        }

        /*-- call shutdown(wr) on tester socket. */
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);
    }

    /*- IUT read (iomux) call should be unblocked now: */
    /*-- read returns zero; */
    if (block_read)
    {
        rc = rpc_read(pco_iut, iut_s, buf, SOCKTS_MSG_STREAM_MAX);
        if (rc != 0)
            TEST_VERDICT("Read call had to return zero");
    }
    /*-- if WR event is set, call iomux the second time; */
    /*-- iomux returns events: */
    /*--- select, pselect: RD (and WR if it was set) */
    /*--- others: RD | HUP (and WR if it was set). */
    else
    {
        tapi_iomux_evt exp = EVT_RD;
        int exp_rc = 1;

        if (iomux_type != TAPI_IOMUX_SELECT &&
            iomux_type != TAPI_IOMUX_PSELECT)
            exp |= EVT_EXC | EVT_HUP;
        else if (out)
            exp_rc = 2;

        if (out)
        {
            exp |= EVT_WR;
            /* Delay to avoid race condition: make sure tester FIN is
             * delivered before the iomux call below. */
            TAPI_WAIT_NETWORK;
        }

        /* For iterations out=TRUE IUT is not blocked in the iomux call,
         * because @c shutdown() is done on IUT side previously. So the
         * iomux is called in the second time to check events. */
        rc = tapi_iomux_call(iomux, -1, &evts);
        SOCKTS_CHECK_IOMUX_EVENTS(rc, exp_rc, evts, exp,
                                  " after connection repair");
    }

    /*- Read data on tester socket if it is, check the data amount. */
    if (sent > 0)
    {
        rpc_drain_fd(pco_tst, tst_s, SOCKTS_BUF_SZ, -1, &read);
        if (read != sent)
        {
            ERROR("Read %"TE_PRINTF_64"u, sent %"TE_PRINTF_64"u",
                  read, sent);
            TEST_VERDICT("Read data amont is not equal to sent");
        }
    }

    TEST_SUCCESS;

cleanup:
    /*- Close sockets. */
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
