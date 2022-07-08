/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_shutdown_socket Usage of system close() call on fully shutdown socket
 *
 * @objective Check that it is possible to use system provided @b close()
 *            function on fully shutdown L5 socket.
 *
 * @type interop
 *  
 * @pre Sockets @p iut_s and @p tst_s are connected.
 * 
 * @par Test sequence:
 * -# @b shutdown(@c SHUT_RDWR) @p iut_s socket.
 * -# Check that obtained state of @p iut_s is @c STATE_SHUT_RDWR.
 * -# Resolve @b close() function with system (libc) library.
 * -# Call @b close() function on @p iut_s socket.
 * -# Close @p tst_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_shutdown_socket"

#include "sockapi-test.h"

#define DATA_BULK 1024
int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const char             *syscall_method = NULL;
    
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int                     sock;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(syscall_method);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);
    
    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_SHUT_RDWR);  

    sock = iut_s;
    pco_iut->use_libc_once = TRUE;
    rpc_close_alt(pco_iut, iut_s, syscall_method);
    
    CHECK_SOCKET_STATE(pco_iut, sock, NULL, -1, STATE_CLOSED);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    TEST_END;
}
