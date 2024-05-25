/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-tcp_ckack Usage of TCP_QUICKACK socket option
 *
 * @objective Check that ACK is sent immediately if @c TCP_QUICKACK
 *            socket options is switched on.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.10
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
 * @param packet_num number of packets to send
 * @param opt_val   0 or 1 - enable or disable TCP_QUICKACK
 * @param do_recv   do/don't call @c recv() on @p pco_iut
 *
 * @par Test sequence:
 * -# Create a connection of type @c SOCK_STREAM.
 * -# Enable or disable @c TCP_QUICKACK socket option.
 * -# Create CSAP which would catch ACKs on @p pco_tst and start listening
 *    on @p tst_if.
 * -# Send @p packet_num number of packets with lenght @c 1.
 * -# Check that number of sent packets is equal to number of recieved
 *    ACKs.
 * -# If @p do_recv, call @c recv() on @p pco_iut at the time when packets
 *    are sent from @p pco_tst.
 * 
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_quickack"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_tad.h"
#include "tapi_tcp.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    int             i;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    int                    sent;
    int                    opt_val;
    int                    opt_val_nodelay = 1;
    int                    opt_get;
    unsigned char          tx_buf[1] = { 234 };
    unsigned char          rx_buf[100];

    csap_handle_t          csap_ack = CSAP_INVALID_HANDLE;

    int                    sid;
    int                    packet_num;
    unsigned int           num;
    te_bool                do_recv;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(packet_num);
    TEST_GET_INT_PARAM(opt_val);
    TEST_GET_BOOL_PARAM(do_recv);

    if (packet_num > (int)sizeof(rx_buf))
        TEST_FAIL("Internal error");

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_setsockopt(pco_tst, tst_s, RPC_TCP_NODELAY, &opt_val_nodelay);

    /* Open congestion window, drop linux neighbour cached values. */
    {
        uint64_t iut_sent = 0, iut_recv = 0, tst_sent = 0, tst_recv = 0;

        pco_iut->op = RCF_RPC_CALL;
        rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, 2000, 1, 5,
                          IC_DEFAULT, &iut_sent, &iut_recv);
        rpc_iomux_echoer(pco_tst, &tst_s, 1, 5, IC_DEFAULT, &tst_sent, &tst_recv);
        pco_iut->op = RCF_RPC_WAIT;
        rpc_iomux_flooder(pco_iut, &iut_s, 1, &iut_s, 1, 2000, 1, 5,
                          IC_DEFAULT, &iut_sent, &iut_recv);
        if (iut_sent != tst_recv || tst_sent != iut_recv)
        {
            TEST_FAIL("Flooder error");
        }

    }

    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));
    rc = tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                      TAD_ETH_RECV_HOST |
                                      TAD_ETH_RECV_NO_PROMISC,
                                      NULL, NULL,
                                      SIN(tst_addr)->sin_addr.s_addr,
                                      SIN(iut_addr)->sin_addr.s_addr,
                                      SIN(tst_addr)->sin_port,
                                      SIN(iut_addr)->sin_port, &csap_ack);
    rc = tapi_tad_trrecv_start(pco_tst->ta, sid, csap_ack, NULL,
                               TAD_TIMEOUT_INF, 0,
                               RCF_TRRECV_PACKETS);

    /* On some hosts 500 msec delay is not enough */
    VSLEEP(1, "wait for CSAP to start");

    rpc_setsockopt(pco_iut, iut_s, RPC_TCP_QUICKACK, &opt_val);
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_QUICKACK, &opt_get);
    if (opt_get != !!opt_val)
        TEST_FAIL("Cannot set TCP_QUICKACK option");
    /* In reality, if you set opt_val=2 and there are pending ACKs,
     * then you'll get opt_get=0.  Yes, it is crazy. */
    rpc_setsockopt(pco_iut, iut_s, RPC_TCP_QUICKACK, &opt_val);

    if (do_recv)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_recv(pco_iut, iut_s, rx_buf, packet_num, RPC_MSG_WAITALL);
    }

    TAPI_WAIT_NETWORK;

    for (i = 0; i < packet_num; ++i)
        RPC_SEND(sent, pco_tst, tst_s, tx_buf, 1, 0);

    if (do_recv)
    {
        pco_iut->op = RCF_RPC_WAIT;
        rpc_recv(pco_iut, iut_s, rx_buf, packet_num, RPC_MSG_WAITALL);
    }

    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, sid, csap_ack, NULL, &num));

    RING("Number of sent packets: %d, number of recieved ACKs: %d", packet_num, num);
    if (opt_val)
    {
        if (num < (unsigned int)packet_num - 1)
        {
            TEST_VERDICT("ACKs are not sent immediately.");
        }
    }
    else
    {
        if (num > (unsigned int)(packet_num * 0.7))
            TEST_VERDICT("ACKs are sent too often.");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (csap_ack != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, sid, csap_ack));

    TEST_END;
}

