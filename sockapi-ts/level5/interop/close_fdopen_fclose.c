/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-close_fdopen_fclose Usage of system close() call with fdclose() call
 *
 * @objective Check that @b fdclose() call closes socket that has been
 *            created by @b socket() call.
 *
 * @type interop
 *
 * @param sock_type   Socket type used in the test
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *  
 * @par Test sequence:
 * -# Call @b fdopen() function on @p pco_iut with @p iut_s socket to
 *    assosiate it with @p f file.
 * -# Call @b fclose() function on @p pco_iut with @p f file.
 * -# Check that state of @p iut_s socket is @c STATE_CLOSED.
 * -# Close @p tst_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/close_fdopen_fclose"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    int                     iut_fd = -1;
    int                     tst_fd = -1;
    int                     fds[2] = { -1, -1 };

    rpc_socket_type         sock_type;
    
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    rpc_file_p              f;

    te_bool                 is_pipe;

    TEST_START;

    TEST_GET_BOOL_PARAM(is_pipe);
    TEST_GET_PCO(pco_iut);
    if (!is_pipe)
    {
        TEST_GET_SOCK_TYPE(sock_type);
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_iut, iut_addr);
        TEST_GET_ADDR(pco_tst, tst_addr);
    }

    if (!is_pipe)
        GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &iut_fd, &tst_fd);
    else
    {
        rpc_pipe(pco_iut, fds);
        iut_fd = fds[0];
        tst_fd = fds[1];
    }

    f = rpc_fdopen(pco_iut, iut_fd, "w+");
    rpc_fclose(pco_iut, f);
    
    CHECK_SOCKET_STATE(pco_iut, iut_fd, NULL, -1, STATE_CLOSED);
    iut_fd = -1;
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    CLEANUP_RPC_CLOSE((is_pipe ? pco_iut : pco_tst), tst_fd);
    
    TEST_END;
}
