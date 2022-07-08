/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-exec_fork_traffic exec() and fork() with loaded TCP connection
 *
 * @objective Perform exec() and fork() in a thread while the second thread
 *            continuously receives and reads traffic.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_twothr2peer
 *              - @ref arg_types_env_twothr2peer_ipv6
 *
 * @par Scenario:
 *
 * -# Create network connection of sockets of @p sock_type by means of
 *    @c GEN_CONNECTION, obtain sockets @p iut_s on @p pco_iut1 and
 *    @p tst_s on @p pco_tst;
 * -# Perform @c CHECK_SOCKET_STATE for @p pco_iut1, @p iut_s;
 * -# Check that obtained state of @p iut_s is @c STATE_CONNECTED;
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Run @ref lib-simple_receiver on @p pco_iut1 to catch traffic 
 *    on @p iut_s;
 * -# Run @ref lib-simple_sender to create traffic through @p tst_s to
 *    @p iut_s during 20 seconds;
 * -# Create child process @p iut_child1 from @p pco_iut2 with @b fork();
 * -# Change image of process @p iut_child1 by means of @b execve() call;
 * -# Wait for completing of @ref lib-simple_sender and return
 *    the number of sent bytes;
 * -# Wait for completing of @ref lib-simple_receiver and return
 *    the number of received bytes;
 * -# Check that received data has the same length as sent;
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Change image of process @p pco_iut1 by means of @b execve() call;
 * -# Create child process @p iut_child2 from @p pco_iut1 with @b fork();
 * -# @b send() data through @p iut_s on @p iut_child2;
 * -# Catch sent data by @b recv() on @p iut_child1;
 * -# Check that received data are the same as sent;
 * -# @b close() all sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/exec_fork_traffic"

#include "sockapi-test.h"

/* time of simple sender performing */
#define TIME2RUN_SENDER     10

int
main(int argc, char *argv[])
{

    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *iut_child1 = NULL;
    rcf_rpc_server         *iut_child2 = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    uint64_t                received;
    uint64_t                sent;


    TEST_START;

    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    GEN_CONNECTION(pco_iut1, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    CHECK_SOCKET_STATE(pco_iut1, iut_s, pco_tst, tst_s, STATE_CONNECTED);

    pco_iut1->op = RCF_RPC_CALL;
    rpc_simple_receiver(pco_iut1, iut_s, 0, &received);

    pco_tst->op = RCF_RPC_CALL;
    rpc_simple_sender(pco_tst, tst_s, 1, 1000, 0, 0, 0, 1,
                      TIME2RUN_SENDER, &sent, FALSE);

    CHECK_RC(rcf_rpc_server_fork_exec(pco_iut2, "pco_child1",
                                      &iut_child1));

    pco_tst->op = RCF_RPC_WAIT;
    rpc_simple_sender(pco_tst, tst_s, 1, 1000, 0, 0, 0, 1,
                      TIME2RUN_SENDER, &sent, FALSE);
    pco_iut1->op = RCF_RPC_WAIT;
    rpc_simple_receiver(pco_iut1, iut_s, 0, &received);

    if (sent != received)
    {
        TEST_FAIL("number of bytes received on 'pco_iut1' is not the same"
                  " as it was sent from 'pco_tst'");
    }

#if 0
    /* TE bug in this case */
    CHECK_RC(rcf_rpc_server_exec(pco_iut1));
    rcf_rpc_server_destroy(pco_iut2); /* thread of pco_iut1 is dead */
#endif
    CHECK_SOCKET_STATE(pco_iut1, iut_s, pco_tst, tst_s, STATE_CONNECTED);
    CHECK_RC(rcf_rpc_server_fork(pco_iut1, "pco_child2", &iut_child2));
    CHECK_SOCKET_STATE(iut_child2, iut_s, pco_tst, tst_s, STATE_CONNECTED);

    RPC_SEND(rc, iut_child2, iut_s, tx_buf, buf_len, 0);

    rc = rpc_recv(pco_tst, tst_s, rx_buf, buf_len, 0);

    if ((unsigned)rc != buf_len)
    {
        TEST_FAIL("number of bytes received on tst_s differs than was sent"
                  " from pco_iut");
    }
    if (memcmp(tx_buf, rx_buf, buf_len) != 0)
    {
        TEST_FAIL("data received on 'pco_tst' is not the same as  "
                  "sent from 'iut_child2'");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
