/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_write  aio_write() usecase
 *
 * @objective Check that @b aio_write() and @b aio_return() work
 *            properly for simple use case
 *
 * @type conformance
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param signum    Signal to be used as notification event
 * @param blk       If @c TRUE/ @c FALSE enable / do not enable @c FIONBIO
 *                  ioctl request
 *                  
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * -# If signum != 0 install signal handler for @c SIGUSR1 on the
 *    @p pco_iut.
 * -# Call @b aio_write() for socket @p iut_s and signal @p signum on
 *    the @p pco_iut.
 * -# Call @b aio_return() on the @p pco_iut to obtain the length of
 *    received data.
 * -# Receive data on the @p pco_tst.
 * -# Check that data sent from @p pco_tst equal to data received on the
 *    @p pco_iut.
 *
 * @post Sockets @p iut_s and @p tst_s are kept connected.
 * 
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_write"

#include "sockapi-test.h"


#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t tx_buf[DATA_BULK];
static uint8_t rx_buf[DATA_BULK + 1];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;
    te_bool             sig;
    te_bool             blk;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    int len;
    int req_val;
    
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
    TEST_GET_BOOL_PARAM(sig);
    TEST_GET_BOOL_PARAM(blk);
    
    memset(&ev, 0, sizeof(ev));
    if (sig)
    {
        ev.notify = RPC_SIGEV_SIGNAL;
        ev.signo = RPC_SIGUSR1;
        CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGUSR1,
                                       SIGNAL_REGISTRAR, &old_act));
        restore_signal_handler = TRUE;
        set = rpc_sigreceived(pco_iut);
    }
    else
        ev.notify = RPC_SIGEV_NONE;
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    if (!blk)
    {
        req_val = TRUE;
        rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);
    }
    te_fill_buf(tx_buf, DATA_BULK);
    
    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK);
    rpc_set_buf(pco_iut, tx_buf, DATA_BULK, buf);
    
    /* Create and fill aiocb */
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, 0, 0, buf, DATA_BULK, &ev);
    
    /* Post AIO read request */
    rpc_aio_write(pco_iut, cb);
    
    len = rpc_recv(pco_tst, tst_s, rx_buf, DATA_BULK + 1, 0);
    
    if (len != DATA_BULK)
        TEST_FAIL("%u bytes instead %u is received on tester", 
                  len, DATA_BULK);
    
    if ((rc = rpc_aio_error(pco_iut, cb)) != 0)
        TEST_FAIL("aio_error() returned %r after request finishing", rc);
        
    if ((len = rpc_aio_return(pco_iut, cb)) != DATA_BULK)
        TEST_FAIL("aio_return() returned %u instead %u", len, DATA_BULK);

    if (sig)
    {
        if (!rpc_sigismember(pco_iut, set, RPC_SIGUSR1))
            TEST_FAIL("Signal is not delivered");
    }
    
    if (memcmp(tx_buf, rx_buf, DATA_BULK) != 0)
        TEST_FAIL("Data sent from the TST do not match data received "
                  "on the IUT");

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

