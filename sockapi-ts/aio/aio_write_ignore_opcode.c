/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_write_ignore_opcode  Check that lio_opcode is ignored by aio_write()
 *
 * @objective Check that field @a aio_lio_opcode is ignored if request is
 *            not posted by @b lio_listio().
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post AIO write request on socket @p iut_s using @b aio_write() function.
 *    @a aio_lio_opcode should be set to @c LIO_READ.
 * -# Receive data via @p tst_s.
 * -# Check that AIO read request is satisfied using functions @b aio_error()
 *    and @b aio_return().
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_write_ignore_opcode"
#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

static uint8_t tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    
    rpc_socket_type         sock_type;
    
    /* Auxiliary variables */
    
    int                     iut_s = -1;
    int                     tst_s = -1;
    
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    

    rpc_aiocb_p             cb = RPC_NULL;
    rpc_ptr                 buf = RPC_NULL;
    tarpc_sigevent          ev;

    int len;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    te_fill_buf(tx_buf, DATA_BULK);
    
    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, DATA_BULK);
    rpc_set_buf(pco_iut, tx_buf, DATA_BULK, buf);
    
    /* Create and fill aiocb */
    cb = rpc_create_aiocb(pco_iut);
    rpc_fill_aiocb(pco_iut, cb, iut_s, RPC_LIO_READ, 0, buf, DATA_BULK, &ev);
    
    /* Post AIO write request */
    rpc_aio_write(pco_iut, cb);
    
    len = rpc_recv(pco_tst, tst_s, tx_buf, DATA_BULK, 0);
    if (len != DATA_BULK)
        TEST_FAIL("recv() return %d instead %d", len, DATA_BULK);

    if ((rc = rpc_aio_error(pco_iut, cb)) != 0)
        TEST_FAIL("aio_error() returned %r after request finishing", rc);

    if ((len = rpc_aio_return(pco_iut, cb)) != DATA_BULK)
        TEST_FAIL("aio_return() returned %u instead %u", len, DATA_BULK);


    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
