/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_ret_no_aio_error  aio_return() without aio_error() for completed request
 *
 * @objective Check that @b aio_return() called without @b aio_error()
 *            works properly.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post AIO read request on socket @p iut_s using @b aio_read() function
 *    with signal notification.
 * -# Send data via @p tst_s to satisfy the request.
 * -# Wait while signal is delivered.
 * -# Call @b aio_return() - it should return the correct length.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_ret_no_aio_error"
#include "sockapi-test.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    int len;
    
    rpc_sigset_p set = RPC_NULL;
    rpc_aiocb_p  cb = RPC_NULL;
    rpc_ptr      buf = RPC_NULL;
    
    tarpc_sigevent ev;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_SIGNAL;
    ev.signo = RPC_SIGUSR1;
    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGUSR1,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;
    set = rpc_sigreceived(pco_iut);
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    te_fill_buf(tx_buf, DATA_BULK);

    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK + 1);
    
    /* Create and fill aiocb */
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, 0, 0, buf, DATA_BULK + 1, &ev);
    
    /* Post AIO read request */
    rpc_aio_read(pco_iut, cb);
    
    if ((rc = rpc_aio_error(pco_iut, cb)) != RPC_EINPROGRESS)
        TEST_FAIL("aio_error() immediately after rpc_read() returned %r"
                  " instead EINPROGRESS", rc);
    
    RPC_SEND(len, pco_tst, tst_s, tx_buf, DATA_BULK, 0);
    MSLEEP(100);
    
    if (!rpc_sigismember(pco_iut, set, RPC_SIGUSR1))
            TEST_FAIL("Signal is not delivered");
        
    if ((len = rpc_aio_return(pco_iut, cb)) != DATA_BULK)
        TEST_FAIL("aio_return() returned %u instead %u", len, DATA_BULK);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);

    /* Restore default signal handler */
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGUSR1, &old_act, 
                              SIGNAL_REGISTRAR);

    TEST_END;
}
