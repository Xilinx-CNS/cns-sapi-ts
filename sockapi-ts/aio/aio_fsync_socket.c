/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_fsync_socket  Call aio_fsync() for socket
 *
 * @objective Check @b aio_fsync() applicability for socket
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param op        O_SYNC or O_DSYNC
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Fill AIO control block with socket @p iut_s and event notification
 *    @c SIGEV_NONE.
 * -# Call @b aio_fsync() with operaton code @p op and filled control block -
 *    @p aio_fsync() should return 0.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 * @author Georgij Volfson <Georgij.Volfson@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_fsync_socket"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    
    rpc_socket_type         sock_type;

    /* Auxiliary variables */
    
    int iut_s = -1;
    int tst_s = -1;
    
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    const char             *op;
    rpc_aiocb_p             cb = RPC_NULL;
    tarpc_sigevent          ev;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(op);


    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;
    
    /* Create and fill aiocb */
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, 0, 0, 0, 0, &ev);
    
    if (strcmp(op, "O_SYNC") == 0)
        rpc_aio_fsync(pco_iut, RPC_O_SYNC, cb);
    else if (strcmp(op, "O_DSYNC") == 0)
        rpc_aio_fsync(pco_iut, RPC_O_DSYNC, cb);
    else
        TEST_FAIL("Incorrect parameter op");
        
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);

    TEST_END;
}

