/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_after_close Usage of system close() call on just closed socket
 *
 * @objective Check that system provided @b close() function works
 *            correctly on L5 socket that has just been closed.
 *
 * @type interop
 *
 * @param sock_type   Socket type used in the test
 *
 * @par Test sequence:
 * -# Create @p iut_s socket.
 * -# Close @p iut_s socket with L5 library function @b close().
 * -# Resolve @b close() function with system (libc) library.
 * -# Call @b close() function once more.
 * -# Check that the function returns @c -1 and sets @b errno to @c EBADF.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_after_close"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    int                     iut_s = -1;
    int                     sock;

    rpc_socket_type         sock_type;

    const struct sockaddr  *iut_addr;

    const char             *syscall_method = NULL;

    TEST_START;

    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(syscall_method);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    
    sock = iut_s;
    rpc_close(pco_iut, iut_s);
    iut_s = -1;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    pco_iut->use_libc_once = TRUE;
    if ((rc = rpc_close_alt(pco_iut, sock, syscall_method)) != -1)
        TEST_FAIL("close() on closed returned %d instead -1", rc);
    CHECK_RPC_ERRNO(pco_iut, RPC_EBADF, "close()");

    CHECK_SOCKET_STATE(pco_iut, sock, NULL, -1, STATE_CLOSED);
        
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    
    TEST_END;
}
