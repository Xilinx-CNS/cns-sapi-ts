/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_cblist_with_holes  Pass cblist with holes to lio_listio()
 *
 * @objective Check that list with holes is handled properly by @b lio_listio().
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 * @param hole      @c NULL if "hole" should be NULL request or @c LIO_NOP if
 *                  "hole" should be reference to request with @c LIO_NOP
 *                  @a aio_lio_opcode
 * @param wait      if @c TRUE, call @b lio_listio() with @c LIO_WAIT.
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Construct two AIO read control blocks for the socket @p iut_s.
 * -# Create a list of three elements for lio_listio(): the first request, 
 *    @p hole request and the second request.
 * -# Post requests calling @b lio_listio(@p wait) with constructed list.
 *    If @p wait is @c FALSE, specify callback notification in @a sig parameter
 *    of @b lio_listio().
 * -# Send data via @p tst_s to satisfy both requests.
 * -# If @p wait is @c TRUE, check that @b lio_listio() is unblocked.
 * -# Otherwise check that notification callback specified in @a sig parameter
 *    is called.
 * -# Check that @b aio_return() for each request returned correct data
 *    length and buffers corresponding to the requests contain correct data.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_cblist_with_holes"
#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024 /**< Size of data to be sent */

#define LIST_LEN        3    /**< Length of the list passed to lio_listio() */
#define HOLE_INDEX      1    /**< Index of the hole in the list */

static uint8_t lio_buf[DATA_BULK];
static uint8_t tx_buf[LIST_LEN][DATA_BULK];

int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;
    const char             *hole;
    te_bool                 wait;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     i;
    rpc_aiocb_p             lio_cb[LIST_LEN];
    rpc_ptr                 buf[LIST_LEN];
    tarpc_callback_item     list[2];
    unsigned int            len = 2;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(hole);
    TEST_GET_BOOL_PARAM(wait);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    rpc_get_callback_list(pco_iut, NULL, NULL);

    for (i = 0; i < LIST_LEN; i++)
    {
        if (i == HOLE_INDEX)
        {
            if (strcmp(hole, "LIO_NOP") == 0)
            {
                create_aiocb(pco_iut, iut_s, RPC_LIO_NOP,
                             buf + i, DATA_BULK, DATA_BULK, NULL, 
                             lio_cb + i);
            }
            else
            {
                lio_cb[i] = RPC_NULL;
                buf[i] = RPC_NULL;
            }
        }
        else
            create_aiocb(pco_iut, iut_s, RPC_LIO_READ,
                         buf + i, DATA_BULK, DATA_BULK, NULL, lio_cb + i);
    }
    
    if (wait)
    {   
        te_bool done;
        
        pco_iut->op = RCF_RPC_CALL;
        rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, NULL);

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
        if (done)
            TEST_FAIL("lio_listion() has unblocked before "
                      "requests completion");
    }
    else
    {
        tarpc_sigevent ev;
        
        INIT_EV(&ev);
        ev.notify = RPC_SIGEV_THREAD;
        ev.value.tarpc_sigval_u.sival_int = 1;
        ev.function = AIO_CALLBACK_NAME "1";
        
        rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, lio_cb, LIST_LEN, &ev);
        rpc_get_callback_list(pco_iut, list, &len);
        if (len > 0)
            TEST_FAIL("Notification is delivered before "
                      "requests completion");
    }

    for (i = 0; i < LIST_LEN; i++)
    {
        if (i == HOLE_INDEX)
            continue;
        te_fill_buf(tx_buf[i], DATA_BULK);
        rpc_write(pco_tst, tst_s, tx_buf[i], DATA_BULK);
    }
    MSLEEP(10);
    
    if (wait)
    { 
        pco_iut->op = RCF_RPC_WAIT;
        if ((rc = rpc_lio_listio(pco_iut, RPC_LIO_WAIT, lio_cb, LIST_LEN, 
                                 NULL)) != 0)
        TEST_FAIL("lio_listio returned %r instead 0", rc);

    }
    else
    {
        len = 2;
        rpc_get_callback_list(pco_iut, list, &len);
        
        if (len == 0)
            TEST_FAIL("No completion notification is delivered");
            
        if (len > 1)
            TEST_FAIL("Completion notification is delivered twice");
    }
    
    for (i = 0; i < LIST_LEN; i++)
    {
        if (i == HOLE_INDEX)
            continue;

        if ((rc = rpc_aio_error(pco_iut, lio_cb[i])) != 0)
            TEST_FAIL("aio_error() returned %r instead 0", rc);

        if ((rc = rpc_aio_return(pco_iut, lio_cb[i])) != DATA_BULK)
            TEST_FAIL("aio_return() returned %d instead %d", rc, DATA_BULK);

        rpc_get_buf(pco_iut, buf[i], DATA_BULK, lio_buf);

        if (memcmp(tx_buf[i], lio_buf, DATA_BULK) != 0)
            TEST_FAIL("Data sent from the Tester do not match data received"
                      " on the IUT");
    }
        
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    
    for (i = 0; i < LIST_LEN; i++)
    {
        if (lio_cb[i] != RPC_NULL)
        {
            CLEANUP_RPC_DELETE_AIOCB(pco_iut, lio_cb[i]);
            CLEANUP_RPC_FREE(pco_iut, buf[i]);
        }
    }

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
 
