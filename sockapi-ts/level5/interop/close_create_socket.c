/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_create_socket Usage of system close() call on just created/bound socket
 *
 * @objective Check that it is possible to use system provided @b close()
 *            function on L5 socket just after socket creation or after
 *            socket binding.
 *
 * @type interop
 *
 * @param sock_type   Socket type used in the test
 * @param bind        TRUE/FALSE call/don't call @b bind() function before
 *                    @b close() one.
 *
 * @par Test sequence:
 * -# Create @p iut_s socket.
 * -# If @b bind parameter is @c TRUE @b bind() @p iut_s socket to some
 *    address.
 * -# Resolve @b close() function with system (libc) library
 * -# Call @b close() function on @p iut_s.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_create_socket"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    int                     iut_s = -1;
    const char             *syscall_method = NULL;

    rpc_socket_type         sock_type;

    const struct sockaddr  *iut_addr;

    int                     sock;

    te_bool                 bind;

    TEST_START;

    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(bind);
    TEST_GET_STRING_PARAM(syscall_method);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    if (bind)
        rpc_bind(pco_iut, iut_s, iut_addr);

    sock = iut_s;
    pco_iut->use_libc_once = TRUE;
    rpc_close_alt(pco_iut, iut_s, syscall_method);
    iut_s = -1;
    CHECK_SOCKET_STATE(pco_iut, sock, NULL, -1, STATE_CLOSED);
 
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    
    TEST_END;
}
