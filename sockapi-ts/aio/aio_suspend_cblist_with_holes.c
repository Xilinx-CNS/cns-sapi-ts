/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-aio_suspend_cblist_with_holes  Pass cblist with holes to aio_suspend()
 *
 * @objective Check that @b aio_suspend() handles properly list with 
 *            @c NULL elements.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Overfill transmit buffers of @p iut_s.
 * -# Post 2 AIO read and 2 AIO write requests for socket @p iut_s.
 * -# Create list of 6 control blocks with @c NULL pointers and pointers
 *    to control blocks corresponding to posted requests on random places.
 * -# Call @b aio_suspend() with @c NULL timeout.
 * -# Satisfy random request either sending or receiving data via @p tst_s.
 * -# Check that @b aio_suspend() is unblocked immediately after request
 *    completion.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/aio_suspend_cblist_with_holes"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       4096  /**< Size of data to be sent */

static char tx_buf[DATA_BULK];

static rcf_rpc_server *pco_iut = NULL;
static tarpc_sigevent  ev;

/* Create request sequence in cb list */
static te_bool
gen_ran(int num, int *ran)
{
    int i;
    int n0 = 0;
    int n1 = 0;
    int n2 = 0;
    
    for (i = 0; i < 6; i++)
    {
        ran[i] = num % 3;
        num = num / 3;
        switch (ran[i])
        {
            case 0:
                n0++;
                break;

            case 1:
                n1++;
                break;

            case 2:
                n2++;
                break;
        }
    }
    
    if ((n0 > 2) || (n1 > 2) || (n2 > 2))
        return FALSE;
    return TRUE;
}

/* Create cblist */
static void
list_gen(int iut_s, rpc_aiocb_p *cb, rpc_ptr *buf)
{
    int ran[6];
    int i;

    while (!gen_ran(rand_range(1, 729), ran));
    for (i = 0; i < 6; i++)
    {
        switch (ran[i])
        {
            case 1:
                buf[i] = rpc_malloc(pco_iut, DATA_BULK + 1);
                cb[i] = rpc_create_aiocb(pco_iut);
                rpc_fill_aiocb(pco_iut, cb[i], iut_s, 0, 0, buf[i],
                               DATA_BULK + 1, &ev);
                rpc_aio_read(pco_iut, cb[i]);
                break;
                
            case 2:
                buf[i] = rpc_malloc(pco_iut, DATA_BULK);
                rpc_set_buf(pco_iut, (uint8_t *)tx_buf, DATA_BULK, buf[i]);
                cb[i] = rpc_create_aiocb(pco_iut);
                rpc_fill_aiocb(pco_iut, cb[i], iut_s, 0, 0, buf[i],
                               DATA_BULK, &ev);
                rpc_aio_write(pco_iut, cb[i]);
                break;
        }
    }
}

int
main(int argc, char *argv[])
{
    /* Environment variables */

    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    int i;
    
    uint64_t n;
    
    rpc_aiocb_p  cb[6] = { RPC_NULL, RPC_NULL, RPC_NULL, RPC_NULL,
                           RPC_NULL, RPC_NULL, };
    rpc_ptr      buf[6] = { RPC_NULL, RPC_NULL, RPC_NULL, RPC_NULL,
                           RPC_NULL, RPC_NULL, };
                           
    te_bool done = TRUE;                           
     
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_overfill_buffers(pco_iut, iut_s, &n);

    /* Generate cblist for the test purposes */
    list_gen(iut_s, cb, buf);

    /* Call AIO suspend */
    pco_iut->op = RCF_RPC_CALL;
    rpc_aio_suspend(pco_iut, cb, 6, NULL);

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
    if (done)
        TEST_FAIL("Suspend has unblocked before requests completion");

    /* Satisfy AIO requests */
    rpc_simple_receiver(pco_tst, tst_s, 0, &n);
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
    rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);

    /* Check suspend status */
    pco_iut->op = RCF_RPC_WAIT;
    if ((rc = rpc_aio_suspend(pco_iut, cb, 6, NULL)) != 0)
        TEST_FAIL("aio_suspend returned %r instead 0", rc);
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    for (i = 0; i < 6; i++)
    {
        CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb[i]);
        CLEANUP_RPC_FREE(pco_iut, buf[i]);
    }   
    
    TEST_END;
}
