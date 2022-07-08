/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-garbage_cb  AIO request with cb filled by garbage
 *
 * @objective Check calling of AIO functions with incorrect control block
 *            does not lead to system crash.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_aux   Auxiliary PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param func      Function to be tested: @b aio_read(), @b aio_write(), 
 *                  @b lio_listio()
 * @param field     Field to be filled by garbage: @a aio_buf, @a aio_nbytes, 
 *                  @a aio_sigevent.
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Create socket @p aux_s on @p pco_aux, bind it to IUT address and
 *    connect it to Tester address.
 * -# Create AIO control block @p cb. Set @a aio_fildes field to @p aux_s.
 * -# If @p field is @a aio_buf, assign @a aio_buf of @p cb to address of 
 *    allocated and released buffer.
 * -# If @p field is @a aio_nbytes, allocate buffer of length N, set
 *    cb.aio_buf to address of this buffer and assign @a aio_len of @p cb 
 *    to 2 * N.
 * -# If @p field is @a aio_sigevent, specify notification type
 *    @c SIGEV_THREAD and incorrect address of the callback function.
 * -# Post AIO request with control block @p cb using @p func.
 * -# If @p func is @b aio_read(), send data of length N * 2 from @p tst_s 
 *    to @p aux_s using sendto().
 * -# Sleep 5 seconds.
 * -# Restart @p pco_iut and generate new connestion between @p pco_iut and
 *    @p pco_tst.
 * -# Check that connection between @p iut_s and @p tst_s is working
 *    correctly.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/garbage_cb"

#include "sockapi-test.h"
#include "aio_internal.h"

#define BUF_LEN       1024  /**< Size of buffers */

static uint8_t tx_buf[BUF_LEN];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;
    const char         *func;
    const char         *field;
    
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    int aux_s = -1;
    
    rpc_aiocb_p  cb[1] ={ RPC_NULL };
    rpc_ptr      buf = RPC_NULL;

    tarpc_sigevent ev;
    tarpc_sigevent ev1;
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_STRING_PARAM(field);
    
    INIT_EV(&ev);
    INIT_EV(&ev1);
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, 
                   &iut_s, &tst_s);
    
    aux_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    TAPI_SET_NEW_PORT(pco_iut, iut_addr);
    rpc_bind(pco_iut, aux_s, iut_addr);
    rpc_connect(pco_iut, aux_s, tst_addr);

    te_fill_buf(tx_buf, BUF_LEN);

    /* Allocate buffer on the pco_iut */
    buf = rpc_malloc(pco_iut, BUF_LEN);
    
    /* Create AIO control block */
    cb[0] = rpc_create_aiocb(pco_iut);
    if (strcmp(field, "aio_nbytes") == 0)
    {
        rpc_fill_aiocb(pco_iut, cb[0], aux_s, 0, 0, buf, 2 * BUF_LEN, &ev);
    }
    else if (strcmp(field, "aio_buf") == 0)
    {
        rpc_fill_aiocb(pco_iut, cb[0], aux_s, 0, 0, buf, BUF_LEN, &ev);
        rpc_free(pco_iut, buf);
    }
    else
    {
        ev.notify = RPC_SIGEV_THREAD;
        ev.value.tarpc_sigval_u.sival_int = 0;
        ev.function = AIO_WRONG_CALLBACK;
        rpc_fill_aiocb(pco_iut, cb[0], aux_s, 0, 0, buf, BUF_LEN, &ev);
    }
    
    /* Post AIO request */
    if (strcmp(func, "write") == 0)
        rpc_aio_write(pco_iut, cb[0]);
    else if (strcmp(func, "read") == 0)
        rpc_aio_read(pco_iut, cb[0]);
    else
        rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, cb, 1, &ev1);

    /* Satisfy AIO read request */
    if (strcmp(func, "read") == 0)
        RPC_SENDTO(rc, pco_tst, tst_s, tx_buf, BUF_LEN, 0, iut_addr);
    SLEEP(5);
    
    CHECK_RC(rcf_rpc_server_restart(pco_iut));
    
    RPC_CLOSE(pco_tst, tst_s);
    
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Check that connection is alive */
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[0]);
    CLEANUP_RPC_FREE(pco_iut, buf);
    
    TEST_END;
}
