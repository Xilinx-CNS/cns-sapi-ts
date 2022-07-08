/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-nested_requests  Initiate the AIO request from the completion callback
 *
 * @objective Check that it's possible to post AIO request from completion
 *            callback of other AIO request.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Prepare @p N (@p N is random, > 30) buffers with data for transmit and 
 *    N buffers for receive.
 * -# Run @ref iomux-echoer on @p pco_tst for @p tst_s for a @p N / 10 seconds.
 * -# Post 1 read and 1 write request.
 * -# Following callback should be specified for completion notification
 *    of each request:
 *   -# If there are no untransmitted data and free buffers for receiving, 
 *      silently return.
 *   -# Otherwise post 1 read and 1 write request with the same callback.
 * -# Wait until echoer procedure finishes.
 * -# Check that all data are received and nothing is corrupted.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/nested_requests"

#include "sockapi-test.h"
#include "aio_internal.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    te_bool req_num;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    
    uint64_t echo_rx, echo_tx;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(req_num);
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    pco_tst->op = RCF_RPC_CALL;
    CHECK_RC(rpc_iomux_echoer(pco_tst, &tst_s, 1, 20, IC_SELECT,
                              &echo_tx, &echo_rx));

    rpc_nested_requests_test(pco_iut, iut_s, req_num);
    CHECK_RC(rpc_iomux_echoer(pco_tst, &tst_s, 1, 20, IC_SELECT,
                              &echo_tx, &echo_rx));


    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

