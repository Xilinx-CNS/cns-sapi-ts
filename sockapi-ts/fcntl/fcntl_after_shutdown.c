/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page fcntl-fcntl_after_shutdown Call fcntl() on the socket after shutdown()
 *
 * @objective Check that @b fcntl() called on the socket after @b shutdown()
 *            handled correctly.
 * 
 * @type conformance
 *
 * @param domain                Domain used for the test  
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on TESTER
 * @param iut_addr              IUT network address
 * @param tst_addr              TESTER network address
 *
 * @par Test sequence:
 * -# Create TCP connection between @p pco_iut and @p pco_tst. @p iut_s and
 *    @p tst_s should be created.
 * -# Call @b close() on @ tst_s and @b shutdown(@c SHUT_WR) on @p iut_s.
 * -# Call @b fcntl(@c F_SETFL) on @p iut_s socket.
 *   
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "fcntl/fcntl_after_shutdown"

#include "sockapi-test.h"

#define BUF_SIZE 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    RPC_CLOSE(pco_tst, tst_s);
    TAPI_WAIT_NETWORK;
    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
    rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_ASYNC);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

