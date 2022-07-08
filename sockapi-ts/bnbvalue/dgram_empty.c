/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 */

/** @page bnbvalue-dgram_empty Empty datagram send/recieve
 *
 * @objective Check behaviour of functions @b send() and @b recv() called
 *            with empty datagram.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param sender        @c TRUE if IUT is sender. @c FALSE if IUT is
 *                      reciever.
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 * 
 * @par Test sequence:
 * -# Send some datagram from sender.
 * -# Recieve this datagram on reciever and check, that it is equel to the
 *    sent one.
 * -# Send an empty datagram from sender.
 * -# Call @b ioclt( @c FIONREAD) on reciever and check, that it returns
 *    @c 0.
 * -# Call @b recv() reciever and check that it returns @c 0.
 * -# Call @b ioclt( @c FIONREAD) and check, that it returns @c 0 or @c -1
 *    and sets errno to @c ENOENT.
 * -# Close created sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/dgram_empty"

#include "sockapi-test.h"

#define TST_BUF_LEN  300

int
main(int argc, char *argv[])
{
    te_bool                 sender;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int                iut_s = -1;
    int                tst_s = -1;

    rcf_rpc_server    *pco_snd = NULL;
    rcf_rpc_server    *pco_rcv = NULL;
    int                snd_s = -1;
    int                rcv_s = -1;
    void              *tx_buf = NULL;
    void              *rx_buf = NULL;
    int                sent;
    int                rcv;
    int                data_size;
    
    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(sender);

    tx_buf = te_make_buf_by_len(TST_BUF_LEN);
    rx_buf = te_make_buf_by_len(TST_BUF_LEN);

    /* Get connection for test purposes */
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, & tst_s);
    
    if (sender)
    {
        pco_snd = pco_iut;
        pco_rcv = pco_tst;
        snd_s = iut_s;
        rcv_s = tst_s;
    }
    else
    {
        pco_rcv = pco_iut;
        pco_snd = pco_tst;
        rcv_s = iut_s;
        snd_s = tst_s;
    }

    RPC_SEND(sent, pco_snd, snd_s, tx_buf, TST_BUF_LEN, 0);

    rcv = rpc_recv(pco_rcv, rcv_s, rx_buf, TST_BUF_LEN, 0);
    if (sent != rcv)
        TEST_FAIL("%d bytes recieved, but %d bytes sent", rcv, sent);
    else if( memcmp(tx_buf, rx_buf, sent) != 0)
        TEST_FAIL("Recieved and sent data are not equal");

    RPC_SEND(sent, pco_snd, snd_s, NULL, 0, 0);
    if (sent != 0)
        TEST_FAIL("send() returned %d on sending empty datagram", sent);

    if (pco_iut == pco_rcv)
    {
        rpc_ioctl(pco_rcv, rcv_s, RPC_FIONREAD, &data_size);
        if (data_size != 0)
            RING_VERDICT("ioctl(FIONREAD) returned %d on socket with empty "
                         "datagram", data_size);
    }
    rcv = rpc_recv(pco_rcv, rcv_s, rx_buf, TST_BUF_LEN, 0);
    if (rcv != 0)
        TEST_FAIL("recv() returned %d on recieving empty datagram", rcv);
    
    if (pco_iut == pco_rcv)
    {
        RPC_AWAIT_IUT_ERROR(pco_rcv);
        rc = rpc_ioctl(pco_rcv, rcv_s, RPC_FIONREAD, &data_size);
        if (rc == -1)
            CHECK_RPC_ERRNO(pco_iut, RPC_ENOENT,
                            "There are no data on iut_s, but");
        else if (data_size == 0)
            RING_VERDICT("ioctl(FIONREAD) returns 0 when there is empty"
                         " datagram in receive queue and there is no "
                         "datagrams");
        else
            TEST_FAIL("ioctl(FIONREAD) returned %d on empty socket",
                      data_size);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(rx_buf);
    free(tx_buf);

    TEST_END;
}
