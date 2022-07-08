/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_linger_close
 *    Usage of system close() call after close on socket 
 * with SO_LINGER option and vice versa
 *
 * @objective Check that sytem @b close() function works correctly
 *            after @b close() function on L5 socket with SO_LINGER
 *            socket option with non-zero timeout and vice versa
 *
 * @type interop
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @param system_first     On/Off
 *
 * @par Test sequence:
 * -# Call @b sockopt() on @p iut_s socket with @c SO_LINGER option passing
 *    linger structure filled in as follow:
 *        - @a l_onoff - @c 1;
 *        - @a l_linger - @c 1.
 * -# Overfill receive buffer of @p tst_s socket sending data from 
 *    @p iut_s socket and not reading the data from @p tst_s socket
 *    by means of @b rpc_overfill_buffers.
 * -# If system_first is on resolve @b close() with system(libc) library in
 * @p pco_iut thread else do it in @p pco_aux thread
 * -# Call @b close() on @p iut_s socket in @p pco_iut_thread.
 * -# Wait some time
 * -# Call @b close() on @p iut_s socket in @p pco_aux thread.
 * -# Wait for @b close() function on @p pco_iut.
 * -# Close @p tst_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_linger_close"

#include "sockapi-test.h"

#define WAIT_TIME 2

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_aux = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const char             *syscall_method = NULL;
    const char             *aux_syscall_method = NULL;
    const char             *iut_syscall_method = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    tarpc_linger            opt_val;

    uint64_t                total_filled = 0;

    te_bool                 system_first;    
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(system_first);
    TEST_GET_STRING_PARAM(syscall_method);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);


    /* Switch on SO_LINGER socket option */
    opt_val.l_onoff  = 1;
    opt_val.l_linger = WAIT_TIME;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_LINGER, &opt_val);
    if (opt_val.l_onoff == 0 || opt_val.l_linger != WAIT_TIME)
    {
        TEST_FAIL("The value of SO_LINGER socket option is not updated "
                  "by setsockopt() function");
    }

    rpc_overfill_buffers(pco_iut, iut_s, &total_filled);

    /* Set thread that will use system close call */
    if (system_first)
    {
        pco_iut->use_libc = TRUE;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        iut_syscall_method = syscall_method;
        /* This string guaranteed that aux use L5 close method */
        aux_syscall_method = "libc";
    }
    else
    {
        pco_aux->use_libc = TRUE;
        RPC_AWAIT_IUT_ERROR(pco_aux);
        aux_syscall_method = syscall_method;
        /* This string guaranteed that iut use L5 close method */
        iut_syscall_method = "libc";
    }
 
    pco_iut->op = RCF_RPC_CALL;
    rpc_close_alt(pco_iut, iut_s, iut_syscall_method);
    MSLEEP(500);
   
    RPC_AWAIT_IUT_ERROR(pco_aux); 
    rc = rpc_close_alt(pco_aux, iut_s, aux_syscall_method);

    if (rc != -1)
    {
        if (system_first)
            TEST_FAIL("After system closing 'iut_s' socket, "
                      "close() on 'iut_s' socket doesn't return -1");
        else 
            TEST_FAIL("After closing 'iut_s' socket, system "
                      "close() on 'iut_s' socket doesn't return -1");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_aux, RPC_EBADF, "After closing 'iut_s' socket, "
                        "close() on 'iut_s' socket returns -1, but");
    }
   
    pco_iut->op = RCF_RPC_WAIT;
    rpc_close_alt(pco_iut, iut_s, iut_syscall_method);
    iut_s = -1;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
