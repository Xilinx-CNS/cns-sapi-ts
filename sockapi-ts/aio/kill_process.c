/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test aio/kill_process  
 * Kill process before completion of AIO request
 * 
 * $Id$
 */

/** @page aio-kill_process  Kill process before completion of AIO request
 *
 * @objective Check that system does not crash if process is killed before
 *            AIO request completion.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Post lot of AIO read and write request with callback notification type.
 * -# Start reading and writing data via @p tst_s of @p pco_tst.
 * -# Kill process @p pco_iut.
 * -# Re-create @p pco_iut.
 * -# Create connection between @p pco_iut and @p pco_tst and verify
 *    that it is usable.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/kill_process"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

#define REQ_NUM         512   /**< Sum number of read and write requests
                                   to be posted */

static uint8_t aux_buf[DATA_BULK];

typedef struct aio_req_data {
    rpc_aiocb_p cb;
    rpc_ptr     buf;
} aio_req_data;

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_socket_type     sock_type;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    rcf_rpc_server *sender = NULL;
    rcf_rpc_server *receiver = NULL;
    rcf_rpc_server *killer = NULL;
    
    /* Auxiliary variables */
    int iut_s = -1;
    int tst_s = -1;
    int i;
    
    uint64_t n;
    
    aio_req_data reqs[REQ_NUM];
    rpc_aiocb_p  cb;
    rpc_ptr      buf;

    tarpc_sigevent ev;
    pid_t          pid;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    
    pid = rpc_getpid(pco_iut);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    INIT_EV(&ev);
    ev.notify = RPC_SIGEV_THREAD;
    ev.value.tarpc_sigval_u.sival_int = rand_range(1, 100);
    ev.function = AIO_CALLBACK_NAME "1";

    for (i = 0; i < REQ_NUM; i++)
    {
        create_aiocb(pco_iut, iut_s, RPC_LIO_WRITE,
                     &reqs[i].buf, DATA_BULK, DATA_BULK, &ev, &reqs[i].cb);
        rpc_aio_write(pco_iut, reqs[i].cb);

        i++;
        
        create_aiocb(pco_iut, iut_s, RPC_LIO_READ,
                     &reqs[i].buf, DATA_BULK, DATA_BULK, &ev, &reqs[i].cb);
        rpc_aio_read(pco_iut, reqs[i].cb);
    }
    
    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "killer", &killer));
    CHECK_RC(rcf_rpc_server_thread_create(pco_tst, "sender", &sender));
    CHECK_RC(rcf_rpc_server_thread_create(pco_tst, "receiver", &receiver));

    receiver->op = RCF_RPC_CALL;
    rpc_simple_receiver(receiver, tst_s, 3, &n);
                            
    sender->op = RCF_RPC_CALL;
    rpc_simple_sender(sender, tst_s, DATA_BULK, DATA_BULK, TRUE,
                      10000, 10000, TRUE, 2, &n, TRUE);

    rpc_kill(killer, pid, RPC_SIGKILL);
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    TAPI_SET_NEW_PORT(pco_iut, iut_addr);
    TAPI_SET_NEW_PORT(pco_tst, tst_addr);
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
                   
    create_aiocb(pco_iut, iut_s, RPC_LIO_WRITE,
                 &buf, DATA_BULK, DATA_BULK, NULL, &cb);
    rpc_aio_write(pco_iut, cb);
    if (rpc_read(pco_tst, tst_s, aux_buf, DATA_BULK) <= 0)
        TEST_FAIL("Data posted by aio_write() are not received on IUT");
    MSLEEP(10);        
    if (rpc_aio_error(pco_iut, cb) != 0 || 
        rpc_aio_return(pco_iut, cb) != DATA_BULK)
    {
        TEST_FAIL("AIO write request is not satisfied");
    }
    rpc_delete_aiocb(pco_iut, cb);
    rpc_free(pco_iut, buf);

    create_aiocb(pco_iut, iut_s, RPC_LIO_READ,
                 &buf, DATA_BULK, DATA_BULK, NULL, &cb);
    rpc_aio_read(pco_iut, cb);
    rpc_write(pco_tst, tst_s, aux_buf, DATA_BULK);
    MSLEEP(100);
    if (rpc_aio_error(pco_iut, cb) != 0 || 
        rpc_aio_return(pco_iut, cb) <= 0)
    {
        TEST_FAIL("AIO read request is not satisfied");
    }
    rpc_delete_aiocb(pco_iut, cb);
    rpc_free(pco_iut, buf);

    TEST_SUCCESS;

cleanup:
    
    for (i = 0; i < REQ_NUM; i++)
        if (reqs[i].cb != RPC_NULL)
        {
            CLEANUP_AIO_CANCEL(pco_iut, iut_s, reqs[i].cb);
            CLEANUP_RPC_DELETE_AIOCB(pco_iut, reqs[i].cb);
            CLEANUP_RPC_FREE(pco_iut, reqs[i].buf);
        }
        
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}

