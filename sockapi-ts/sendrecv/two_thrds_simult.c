/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-two_thrds_simult TCP over IPv4: Simultaneous usage of a socket from two threads for send/receive operations
 *
 * @objective Check robustness of the stream sockets send/receive
 *            functionality when a socket is used from two threads
 *            simultaneously.
 *
 * @type stress
 *
 * @param pco_iut   PCO with IUT
 * @param iut_addr  Address assigned on IUT
 * @param pco_tst   Tester PCO
 * @param tst_addr  Address assigned on Tester
 * @param fork      To be passed to the 
 *                  @ref sendrecv-lib-two_threads_simultaneous
 *
 * -# Create TCP over IPv4 connection using algorithm
 *    @ref lib-stream_client_server with the following parameters
 *    (opened sockets are referred as @p srvr_s and @p clnt_s below):
 *      - @p pco_iut;
 *      - @p pco_tst;
 *      - @p iut_addr;
 *      - server binds to not wildcard address
 *      - @p tst_addr.
 *      .
 * -# Apply @ref sendrecv-lib-two_threads_simultaneous scenario for 
 *    opened connection (@p pco_iut, @p pco_tst, @p srvr_s, @p clnt_s
 *    parameters).
 * -# Close @p srvr_s and @p clnt_s sockets.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/two_thrds_simult"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"


int
main(int argc, char *argv[])
{
    /* Environment variables */
    unsigned int        time2run;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const char     *method;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    /* Auxiliary variables */

    int iut_s = -1;
    int tst_s = -1;
    

    TEST_START;

    TEST_GET_INT_PARAM(time2run);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(method);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    if (two_threads_stress(pco_iut, iut_s, 
                           rpc_socket_domain_by_addr(iut_addr), 
                           pco_tst, tst_s, method, 
                           time2run) < 0)
    {
        TEST_STOP;    
    }
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END; 
}
