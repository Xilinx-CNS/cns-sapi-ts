/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interface configuring (Control Plane testing)
 */

/** @page ifcfg-if_up_down_influence Put interface down does not affect other interfaces
 *
 * @objective Transmit data using two TCP connections through two different
 *            interfaces. Check if one of interfaces is down the second still
 *            can transmit data.
 *
 * @type conformance
 *
 * @param pco_iut1   PCO on @p IUT
 * @param pco_iut2   PCO on @p IUT
 * @param pco_tst1  PCO on @p TESTER
 * @param pco_tst2  PCO on @p TESTER
 * @param iut_if1   Network interface name on @p IUT that connected to
 *                  @p TESTER
 * @param iut_if2   Network interface name on @p IUT that connected to
 *                  @p TESTER
 * @param change_if What IUT interface will be shutdowned for
 *                  test purposes: TRUE/FALSE - iut_if2/iut_if1
 *
 * @par Test sequence:
 *
 * -# Create two TCP connections using two different interface couples.
 * -# Check that both created connections are able to send/recv data.
 * -# In background start sending data via connection whose interface
 *    will be shoutdowned (according to @p change_if).
 * -# Shut down interface according to @p change_if.
 * -# Check that the connection established via another interface is
 *    able to send/recv data.
 * -# Check that no data is send via connection whose interface has been
 *    shutdowned.
 * -# Activate shutdowned interface.
 * -# Check that the data flow is also activated.
 * -# Close the connection.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_up_down_influence"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"

#define WAIT_FOR_SIMPLE_RECEIVER_START_TO_RECEIVE  2
#define TST_BUF_LEN                                11111

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut1 = NULL;
    rcf_rpc_server        *pco_iut2 = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;
    rcf_rpc_server        *pco_snd1= NULL;
    rcf_rpc_server        *pco_snd2= NULL;
    rcf_rpc_server        *pco_rcv1= NULL;
    rcf_rpc_server        *pco_rcv2= NULL;

    const struct if_nameindex *iut1_if = NULL;
    const struct if_nameindex *iut2_if = NULL;
    const struct if_nameindex *if_to_shutdown = NULL;

    const struct sockaddr *iut1_addr = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *iut2_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;

    int                    iut1_s = -1;
    int                    tst1_s = -1;
    int                    iut2_s = -1;
    int                    tst2_s = -1;

    int                    snd1_s = -1;
    int                    rcv1_s = -1;
    int                    snd2_s = -1;
    int                    rcv2_s = -1;

    void     *tx_buf;

    te_bool                change_if = FALSE;

    uint64_t received_before = 0;
    uint64_t received_after  = 0;
    uint64_t sent            = 0;

    TEST_START;

    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_IF(iut1_if);
    TEST_GET_IF(iut2_if);

    TEST_GET_ADDR(pco_iut1, iut1_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_iut2, iut2_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    TEST_GET_BOOL_PARAM(change_if);

    tx_buf = te_make_buf_by_len(TST_BUF_LEN);

    GEN_CONNECTION(pco_tst1, pco_iut1, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst1_addr, iut1_addr, &tst1_s, &iut1_s);

    GEN_CONNECTION(pco_tst2, pco_iut2, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst2_addr, iut2_addr, &tst2_s, &iut2_s);

    if (change_if)
    {
        snd1_s = iut2_s;
        rcv1_s = tst2_s;
        pco_snd1 = pco_iut2;
        pco_rcv1 = pco_tst2;
        if_to_shutdown = iut2_if;
        snd2_s = iut1_s;
        rcv2_s = tst1_s;
        pco_snd2 = pco_iut1;
        pco_rcv2 = pco_tst1;
    }
    else
    {
        snd1_s = iut1_s;
        rcv1_s = tst1_s;
        pco_snd1 = pco_iut1;
        pco_rcv1 = pco_tst1;
        if_to_shutdown = iut1_if;
        snd2_s = iut2_s;
        rcv2_s = tst2_s;
        pco_snd2 = pco_iut2;
        pco_rcv2 = pco_tst2;
    }

    RPC_SEND(rc, pco_snd1, snd1_s, tx_buf, TST_BUF_LEN, 0);
    MSLEEP(500);
    sockts_read_check_fd(pco_rcv1, rcv1_s, tx_buf, TST_BUF_LEN);

    RPC_SEND(rc, pco_snd2, snd2_s, tx_buf, TST_BUF_LEN, 0);
    MSLEEP(500);
    sockts_read_check_fd(pco_rcv2, rcv2_s, tx_buf, TST_BUF_LEN);

    pco_snd1->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_snd1, snd1_s, 1, 10, 0, 0, 10000, 1, 20, &sent, 0);
    pco_rcv1->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_rcv1, rcv1_s, 0, &received_before);
    SLEEP(WAIT_FOR_SIMPLE_RECEIVER_START_TO_RECEIVE);

    /* Shut down iut_if */
    CHECK_RC(tapi_cfg_base_if_down(pco_iut1->ta, if_to_shutdown->if_name));
    CFG_WAIT_CHANGES;

    RPC_SEND(rc, pco_snd2, snd2_s, tx_buf, TST_BUF_LEN, 0);
    MSLEEP(500);
    sockts_read_check_fd(pco_rcv2, rcv2_s, tx_buf, TST_BUF_LEN);

    /* Call simple reciever to get number of bytes received */
    rpc_simple_receiver(pco_rcv1, rcv1_s, 0, &received_before);

    /* Once again call simple receiver */
    pco_rcv1->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_rcv1, rcv1_s, 0, &received_after);

    /* Up iut_if */
    CHECK_RC(tapi_cfg_base_if_up(pco_iut1->ta, if_to_shutdown->if_name));
    CFG_WAIT_CHANGES;

    rpc_simple_sender(pco_snd1, snd1_s, 1, 10, 0, 0, 10000, 1, 20, &sent, 0);

    rpc_simple_receiver(pco_rcv1, rcv1_s, 0, &received_after);

    if (received_before + received_after != sent)
        TEST_FAIL("Number of bytes sent %d is not as "
                  "number of bytes received %d + %d = %d",
                  sent, received_before, received_after,
                  received_before + received_after);
    if (received_after == 0)
        TEST_FAIL("Number of bytes received after "
                  "interface status changed to 'up' must be non-zero");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut1, iut1_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    free(tx_buf);
    TEST_END;
}
