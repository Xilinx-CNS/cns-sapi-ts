/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * IOCTL Requests
 *
 * $Id$
 */

/** @page fcntl-fcntl_getfl fcntl(F_GETFL) conformance
 *
 * @objective Check that @b fcntl(F_GETFL) returns correct flags for socket
 *
 * @type conformance
 *
 * @param pco_iut1      PCO on IUT
 * @param pco_tst       Auxiliary PCO on TST
 * @param bind_iut      Whether to bind socket on IUT to local address
 * @param connect_iut   Whether to connect socket on iut to remote address
 * @param sock_type     Socket type used in the test
 *
 * @par Test sequence:
 * -# Create socket @p iut_s on @p pco_iut of type @p sock_type.
 * -# If @p bind_iut is true, bind @p iut_s socket to local address.
 * -# If @p connect_iut is true, connect @p iut_s socket to remote address.
 * -# Call @b fcntl(F_GETFL). Check the flags it returns.
 * -# Issue verdicts.
 * -# Close created sockets.
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#include "sockapi-test.h"
#include "fcntl_getfl_lib.h"

#define TE_TEST_NAME  "fcntl/fcntl_getfl"

int
main(int argc, char *argv[])
{

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    acc_s = -1;

    te_bool                bind_iut;
    te_bool                connect_iut;

    rpc_socket_type        sock_type;


    TEST_START;

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(bind_iut);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_SOCK_TYPE(sock_type);

    if (bind_iut)
        iut_s = rpc_create_and_bind_socket(pco_iut, sock_type,
                                           RPC_PROTO_DEF, TRUE, FALSE,
                                           iut_addr);
    else
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);

    if (connect_iut)
    {
        if (sock_type == RPC_SOCK_STREAM)
        {
            tst_s = rpc_socket(pco_tst,
                               rpc_socket_domain_by_addr(tst_addr),
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
            rpc_bind(pco_tst, tst_s, tst_addr);
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_iut, iut_s, tst_addr);
            acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
        }
        else
            rpc_connect(pco_iut, iut_s, tst_addr);
    }

    FCNTL_GETFL_TEST_FLAGS(pco_iut, iut_s, RPC_O_RDWR);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
