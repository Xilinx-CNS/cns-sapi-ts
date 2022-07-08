/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_cblist_dummy  Pass cblist containing only dummy control blocks
 *
 * @objective Check that lio_listio() processes properly list containing
 *            only @c NULL and @c LIO_NOP requests.
 *
 * @param pco_iut   PCO with IUT
 * @param req1      first request in the list: @c NULL or @c LIO_NOP
 * @param req2      second request in the list: @c NULL or @c LIO_NOP
 *
 * @par Scenario
 * -# Open and bind socket @p s of @p pco_iut.
 * -# Construct @c LIO_NOP requests (if exist) using @p s, correct buffer and
 *    notification type @c SIGEV_NONE.
 * -# Call @b lio_listio() with list { req1, req2 }. It should return 0.
 * -# Call @b aio_cancel() for @c LIO_NOP requests - it should return
 *    @c AIO_ALLDONE.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_cblist_dummy"
#include "sockapi-test.h"


#define LIST_LEN        2     /**< Number of calls in the list */
#define DATA_BULK       1024  /**< Maximum size of buffer */

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server         *pco_iut = NULL;
 
    const char             *req1;
    const char             *req2;
    rpc_socket_type         sock_type;

    const struct sockaddr  *iut_addr;

    
    /* Auxiliary variables */
    
    rpc_aiocb_p lio_cb[LIST_LEN] = { RPC_NULL, RPC_NULL };
    
    int             iut_s = -1;
    int             i;
    tarpc_sigevent  ev;
    rpc_ptr         buf = RPC_NULL;
    te_bool         flag[LIST_LEN] = { FALSE, FALSE };
    
    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(req1);
    TEST_GET_STRING_PARAM(req2);
    
    memset(&ev, 0, sizeof(ev));
    ev.notify = RPC_SIGEV_NONE;

    buf = rpc_malloc(pco_iut, DATA_BULK);
    
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
       
    if (strcmp(req1, "LIO_NOP") == 0)
    {
        lio_cb[0] = rpc_create_aiocb(pco_iut);
        rpc_fill_aiocb(pco_iut, lio_cb[0], iut_s, RPC_LIO_NOP, 0, buf, 
                       DATA_BULK, &ev);
        flag[0] = TRUE; 
    }
    if (strcmp(req2, "LIO_NOP") == 0)
    {
        lio_cb[1] = rpc_create_aiocb(pco_iut);
        rpc_fill_aiocb(pco_iut, lio_cb[1], iut_s, RPC_LIO_NOP, 0, buf, 
                       DATA_BULK, &ev);
        flag[1] = TRUE;    
    }
    
    if ((rc = rpc_lio_listio(pco_iut, RPC_LIO_NOWAIT, lio_cb, LIST_LEN, 
                             &ev)) != 0)
       TEST_FAIL("Incorrect behavior of lio_listio()");
    
    for (i = 0; i < LIST_LEN; i++)
    {
        if (flag[i] &&
            (rc = rpc_aio_cancel(pco_iut, iut_s, lio_cb[i])) != 
            RPC_AIO_ALLDONE)
        {
            TEST_FAIL("aio_cancel() returned %d instead RPC_AIO_ALLDONE "
                      "for LIO_NOP request", rc);
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (buf != RPC_NULL)
        rpc_free(pco_iut, buf);

    TEST_END;
}


