/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page interop-sock_with_flags_acc Check that socket created with flags is accelerated
 *
 * @objective Check that socket created with help of @b socket() call with
 *            @c SOCK_NONBLOCK, @c SOCK_CLOEXEC or without flag is
 *            accelerated
 *
 * @type interop
 *
 * @param pco_iut       PCO on IUT
 * @param iut_addr      Network address on IUT
 * @param sock_type     @c SOCK_STREAM or @c SOCK_DGRAM
 * @param sock_flags    Create socket with @c SOCK_NONBLOCK,
 *                      @c SOCK_CLOEXEC or without flags
 * @param connection    If it is @c TRUE generate connection
 * @param active        Generate acrive or passive TCP connection
 *
 * @par Scenario:
 * -# Create a socket @p iut_s of type @p sock_type with @b socket()
 *    call setting flag according to @p sock_flags if @p connection is
 *    @c FALSE.
 * -# Generate connection according to @p active and @p sock_flags
 *    parameters if @p connection is @c TRUE.
 * -# Check that socket on IUT side is accelerated via Onload.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "interop/sock_with_flags_acc"

#include "sockapi-test.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    int                 iut_s = -1;
    int                 tst_s = -1;
    rpc_socket_type     sock_type;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    const char         *sock_flags;

    int                 sf = 0;

    te_bool             connection;
    te_bool             active;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(sock_flags);
    TEST_GET_BOOL_PARAM(connection);
    TEST_GET_BOOL_PARAM(active);

    if (strcmp(sock_flags, "cloexec") == 0)
        sf = RPC_SOCK_CLOEXEC;
    else if (strcmp(sock_flags, "nonblock") == 0)
        sf = RPC_SOCK_NONBLOCK;
    else if (strcmp(sock_flags, "none") != 0)
        TEST_VERDICT("Incorrect 'sock_flags' parameter");

    if (connection)
    {
        if (active)
            gen_conn_with_flags(pco_tst, pco_iut, tst_addr, iut_addr,
                                &tst_s, &iut_s, sock_type,
                                sf, FALSE, TRUE, FALSE);
        else
            gen_conn_with_flags(pco_iut, pco_tst, iut_addr, tst_addr,
                                &iut_s, &tst_s, sock_type,
                                sf, TRUE, FALSE, FALSE);
    }
    else
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type | sf, RPC_PROTO_DEF);

    if (!tapi_onload_is_onload_fd(pco_iut, iut_s))
        TEST_VERDICT("Socket was not accelerated");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
