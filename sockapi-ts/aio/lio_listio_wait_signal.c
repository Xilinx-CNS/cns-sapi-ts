/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output
 * 
 * $Id$
 */

/** @page aio-lio_listio_wait_signal  Interrupt lio_listio(LIO_WAIT) by signal.
 *
 * @objective Check that @b lio_listio(@c LIO_WAIT) returns -1 with errno
 *            @c EINTR if interrupted by the signal.
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Socket on @p pco_iut
 * @param pco_tst   Tester PCO
 * @param tst_s     Socket on @p pco_tst
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Create AIO read request control blocks with socket @p iut_s and
 *    SIGEV_NONE notification.
 * -# Install @c SIGUSR1 signal handler on @p pco_iut.
 * -# Post request using @b lio_listio(@c LIO_WAIT). 
 * -# Send signal @c SIGUSR1 to the process @p pco_iut.
 * -# Check that @b lio_listio() is unblocked, returned -1 and set errno
 *    to @c EINTR.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "aio/lio_listio_wait_signal"

#include "sockapi-test.h"
#include "aio_internal.h"

#define DATA_BULK       1024        /**< Buffer size */

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_iut1 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int            iut_s = -1;
    int            tst_s = -1;
    rpc_aiocb_p    cb = RPC_NULL;
    rpc_ptr        buf = RPC_NULL;
    pid_t          pco_iut_pid;
    tarpc_timeval  tv = { 0, 0 };

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
      
    pco_iut_pid = rpc_getpid(pco_iut);
    rcf_rpc_server_fork(pco_iut, "pco_iut1", &pco_iut1);
    
    /* Install signal handler */
    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGUSR1,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    create_aiocb(pco_iut, iut_s, RPC_LIO_READ,
                 &buf, DATA_BULK, DATA_BULK, NULL, &cb);

    rpc_gettimeofday(pco_iut, &tv, NULL);
    pco_iut1->start = (tv.tv_sec + 1) * 1000 + tv.tv_usec / 1000;
    pco_iut1->op = RCF_RPC_CALL;
    rpc_kill(pco_iut1, pco_iut_pid, RPC_SIGUSR1);

    rpc_lio_listio(pco_iut, RPC_LIO_WAIT, &cb, 1, NULL);

    rpc_kill(pco_iut1, pco_iut_pid, RPC_SIGUSR1);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_DELETE_AIOCB(pco_iut, cb);
    CLEANUP_RPC_FREE(pco_iut, buf);

    if (pco_iut1 != NULL)
    {
        if (rcf_rpc_server_destroy(pco_iut1) < 0)
        {
            ERROR("Failed to destroy thread RPC server on the IUT");
            result = EXIT_FAILURE;
        }
    }
    /* Restore default signal handler */
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGUSR1, &old_act, 
                              SIGNAL_REGISTRAR);

    TEST_END;
}

