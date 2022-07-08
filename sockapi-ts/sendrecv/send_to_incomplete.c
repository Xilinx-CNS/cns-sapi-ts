/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 *
 * $Id$
 */

/** @page sendrecv-send_to_incomplete Sharing of the one socket by several threads for different socket operations
 *
 * @objective Check that several threads may use a single socket for
 *            different socket operations.
 *
 * @type stress
 *
 * @param pco_iut1      IUT thread #1
 * @param pco_iut2      IUT thread #2
 * @param pco_tst       Auxiliary IUT for other side network operations
 *
 * -# Create socket @p tst_s on @p pco_tst of the @c SOCK_STREAM type;
 * -# Call @b listen() on @p tst_s on @p pco_tst;
 * -# Call @b accept() on @p tst_s on @p pco_tst to get @p acc_s
 *    socket descriptor;
 * -# Create socket @p iut_s on @p pco_iut1 of the @c SOCK_STREAM type;
 * -# Call @ref lib-simple_sender on @p pco_iut1 on @p iut_s for @c 60 seconds.
 *    Any errors arising while sending should be ignored;
 * -# @b connect() @p iut_s to the @p tst_s on @p pco_iut2;
 * -# Call @ref lib-simple_receiver on @p acc_s on @p pco_tst to receive 
 *    all transmitted data through @p iut_s;
 * -# Check that number of sent and received bytes is the same;
 * -# Call @b send() on @p iut_s on @p pco_iut2 to transmit @p data_2;
 * -# Check that @p data_1 and data_2 are sent through @p iut_s on @p pco_iut1
 *    and @p pco_iut2 were received on @p tst_s;
 * -# Call @ref lib-simple_receiver on @p acc_s on @p pco_tst to receive
 *    all transmitted data through @p iut_s;
 * -# Call @ref lib-simple_sender on @p pco_iut1 on @p iut_s for @c 10 seconds;
 * -# Call @b shutdown(SHUT_RD) on @p pco_iut2 on @p iut_s;
 * -# Check that number of sent and received bytes is the same;
 * -# Call @b rpc_simple_receiver() on @p acc_s on @p pco_tst to receive
 *    all transmitted data through @p iut_s;
 * -# Call @ref lib-simple_sender on @p pco_iut1 on @p iut_s for @c 10 seconds;
 * -# Call @b shutdown(SHUT_WR) on @p pco_iut2 on @p iut_s;
 * -# Check that @ref lib-simple_sender on @p pco_iut1 on @p iut_s returns
 *    -1 and @b errno set to @c EPIPE;
 * -# Close all sockets and free all resources created for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/send_to_incomplete"

#include "sockapi-test.h"

#define TST_BUF_SIZE      555
#define TST_TIME2RUN1      60
#define TST_TIME2RUN2      10

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     acc_s = -1;

    char                    tx_buf[TST_BUF_SIZE];
    char                    rx_buf[TST_BUF_SIZE];

    int                     recv;
    uint64_t                received;
    uint64_t                sent;

    int                     time2run = TST_TIME2RUN1;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    pco_tst->op = RCF_RPC_CALL;
    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    iut_s = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    /* This function attempts to send for time2run ignoring any errors */
    pco_iut1->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_iut1, iut_s, 1, 1000, 0, 0, 0, 1, time2run,
                      &sent, TRUE);

    /* Attempt to bind(), connect() and recv() */
#if 0
    /*
     * This operation leads to error and returns errno set to EINVAL
     * because rpc_simple_sender() uses send() that in turn makes
     * implicit bind() on socket.
     */
    rpc_bind(pco_iut2, iut_s, iut_addr);
#endif

    rpc_connect(pco_iut2, iut_s, tst_addr);

    pco_tst->op = RCF_RPC_WAIT;
    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    pco_tst->timeout = TE_SEC2MS(time2run + 10);
    rpc_simple_receiver(pco_tst, acc_s, 0, &received);

    pco_iut1->op = RCF_RPC_WAIT;
    rpc_simple_sender(pco_iut1, iut_s, 1, 1000, 0, 0, 0, 1, time2run,
                      &sent, TRUE);

    if (received != sent)
    {
        TEST_FAIL("The number of sent bytes (%d) is not the same "
                  "as received (%d)", sent, received);
    }

    te_fill_buf(tx_buf, sizeof(tx_buf));

    RPC_SEND(sent, pco_iut2, iut_s, tx_buf, sizeof(tx_buf), 0);
    recv = rpc_recv(pco_tst, acc_s, rx_buf, sizeof(rx_buf), 0);

    if ((int64_t)sent != recv)
    {
        TEST_FAIL("The number of sent bytes (%d) is not the same "
                  "as received (%d)", sent, received);
    }

    if (memcmp(rx_buf, tx_buf, sent) != 0)
    {
        TEST_FAIL("The data sent is not the same as received one");
    }

    /*
     * Try shutdown() socket on read while traffic exists
     */
    time2run = TST_TIME2RUN2;
    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, acc_s, 0, &received);

    /* this function attempts to send for time2run with detecting errors */
    pco_iut1->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_iut1, iut_s, 1, 1000, 0, 0, 0, 1, time2run,
                      &sent, FALSE);

    pco_iut1->op = RCF_RPC_CALL_WAIT;
    rpc_shutdown(pco_iut2, iut_s, RPC_SHUT_RD);

    pco_iut1->op = RCF_RPC_WAIT;
    rpc_simple_sender(pco_iut1, iut_s, 1, 1000, 0, 0, 0, 1, time2run,
                      &sent, FALSE);

    pco_tst->op = RCF_RPC_WAIT;
    rpc_simple_receiver(pco_tst, acc_s, 0, &received);

    if (received != sent)
        TEST_FAIL("The number of sent bytes (%d) is not the same "
                  "as received (%d)", sent, received);

    /*
     * Try shutdown() socket on write while traffic exists
     */

    time2run = TST_TIME2RUN2;
    
    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_tst, acc_s, 0, &received);

    /* this function attempts to send for time2run with detecting errors */
    pco_iut1->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_iut1, iut_s, 1, 1000, 0, 0, 0, 1, time2run,
                      &sent, FALSE);
 
    
    pco_iut1->op = RCF_RPC_CALL_WAIT;
    rpc_shutdown(pco_iut2, iut_s, RPC_SHUT_WR);


    pco_iut1->op = RCF_RPC_WAIT;
    RPC_AWAIT_IUT_ERROR(pco_iut1);

    rc = rpc_simple_sender(pco_iut1, iut_s, 1, 1000, 0, 0, 0, 1, time2run,
                           &sent, FALSE);
    if (rc != -1)
    {
        TEST_FAIL("rpc_simple_sender() returns %d instead -1 when socket "
                  " is shutdowned on write");
    }

    CHECK_RPC_ERRNO(pco_iut1, RPC_EPIPE,
                    "rpc_simple_sender() returns -1, but ");

    pco_tst->op = RCF_RPC_WAIT;
    rpc_simple_receiver(pco_tst, acc_s, 0, &received);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    TEST_END;
}
