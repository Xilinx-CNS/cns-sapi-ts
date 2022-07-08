/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-fork_nb_receive Fork during intensive non-block receive operations
 *
 * @objective Check that fork() can be performed simultaniously with
 *            intensive non-block receive operations on empty socket.
 *
 * @type stress
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type   Socket type:
 *                    - SOCK_STREAM
 *                    - SOCK_DGRAM
 * @param iterations  The main loop iterations number:
 *                    - 5
 *
 * @par Scenario:
 *
 * -# Create network connection of sockets of @p sock_type, obtain sockets
 *    @p iut_s and @p tst_s on @p pco_iut and @p pco_tst respectively.
 * -# Create additional thread for second RPC server @p pco_iut_thread
 * -# Repeat @p iterations times
 *    -# Start non-block receiver on @p pco_iut as non-blocking RPC operation.
 *       non-block permanently calls recv() on the socket and checks that
 *       there is no data received and recv() returns EAGAIN.
 *    -# Sleep for @p nb_receive_interval seconds.
 *    -# Try to fork() @p pco_iut_thread RPC server to @p pco_iut_forked.
 *    -# Check that RPC server has been successfuly forked.
 *    -# Stop non-block receiver, check status code.
 *    -# Send/Receive some data between @b TST and @b IUT using
 *       @p pco_iut_forked RPC server to verify that the socket API still
 *       works correctly.
 *    -# Destroy @p pco_iut_forked RPC server.
 * -# Destroy @p pco_iut_thread RPC server.
 * -# @b close() all sockets.
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/fork_nb_receive"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_receiver = NULL;
    rcf_rpc_server         *pco_iut_forked = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    rpc_ptr                 recv_handle = RPC_NULL;

    rpc_socket_type         sock_type; 
    
    int                     iterations;
    int                     step;
    int                     val;
    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_GET_INT_PARAM(iterations);

    /*
     * Test Scenario
     */ 

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Create additional thread */
    CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "receiver",
             &pco_iut_receiver));

    recv_handle = rpc_malloc(pco_iut_receiver,
                             rpc_get_sizeof(pco_iut_receiver, "int"));
    val = 1;
    rpc_ioctl(pco_iut_receiver, iut_s, RPC_FIONBIO, &val);

    for (step = 0; step < iterations; step++)
    {
        /* Start NB-Receiver */
        pco_iut_receiver->op = RCF_RPC_CALL;
        CHECK_RC(rpc_nb_receiver_start(pco_iut_receiver,
                                       iut_s, recv_handle));
        TAPI_WAIT_NETWORK;

        /*
         * Try to fork RPC agent when NB-Receive is performed in different
         * thread simultaneously
         */
#if 0 /* UL stack fails here, and following code helps in debug */
        rpc_setenv(pco_iut, "EF_UNIX_LOG", "0x1400b", 1);
        rpc_setenv(pco_iut, "TP_LOG", "0x20b", 1);
#endif
        CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, "forked",
                                          &pco_iut_forked));

        /* Stop NB-Receiver */
        CHECK_RC(rpc_nb_receiver_stop(pco_iut, recv_handle));

        /* Check the NB-Receiver status */
        pco_iut_receiver->op = RCF_RPC_WAIT;
        CHECK_RC(rpc_nb_receiver_start(pco_iut_receiver,
                                       iut_s, recv_handle));


        /* Check that the socket API is working on the forked RPC server */
        sockts_test_connection(pco_iut_forked, iut_s,
                               pco_tst, tst_s);

        rcf_rpc_server_destroy(pco_iut_forked);
        pco_iut_forked = NULL;
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s); 
    CLEANUP_RPC_CLOSE(pco_tst, tst_s); 

    if (recv_handle != RPC_NULL)
        rpc_free(pco_iut, recv_handle);

    rcf_rpc_server_destroy(pco_iut_forked);
    rcf_rpc_server_destroy(pco_iut_receiver);

    TEST_END;
}
