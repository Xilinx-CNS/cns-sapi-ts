/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-listen_shutdown_wr Check that nothing happens on SHUT_WR for listening socket
 *
 * @objective Check that listening socket doesn't drop accept queue and
 *            continues to accept connection after shutdown.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of the @c SOCK_STREAM type;
 * -# @b bind() it to the @p iut_addr;
 * -# Call @b listen() on @p iut_s;
 * -# Create @p tst_s1 and @p tst_s2 sockets of @c SOCK_STREAM type on
 *    @p pco_tst.
 * -# Call @b connect() on @p tst_s1 and @p tst_s2 to connect them to
 *    @p iut_s socket.
 * -# Call @b accept() once on @p iut_s socket.
 * -# Call @b shutdown(@c SHUT_WR) on @p iut_s socket.
 * -# Call @b accept() once again on @p iut_s socket.
 * -# Create @p tst_s3 socket on @p pco_tst.
 * -# Call @p connect() on @p tst_s3 socket.
 * -# Call @p accept() on @p iut_s socket.
 * -# Check that corresponding sockets are connected well.
 * -# Close sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/listen_shutdown_wr"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut;
    rcf_rpc_server        *pco_tst;

    int                    iut_s = -1;
    int                    tst_s1 = -1;
    int                    tst_s2 = -1;
    int                    tst_s3 = -1;
    int                    acc_s1 = -1;
    int                    acc_s2 = -1;
    int                    acc_s3 = -1;

    const struct sockaddr *iut_addr;

    int                    ret;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_s, 2);

    /* Create two sockets on TST. */
    tst_s1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s2 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    /* Connect two sockets to IUT */
    rpc_connect(pco_tst, tst_s1, iut_addr);

    rpc_connect(pco_tst, tst_s2, iut_addr);

    /* Call accept once on iut_s. */
    acc_s1 = rpc_accept(pco_iut, iut_s, NULL, NULL);

    /* Shutdown iut_s socket on write. */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
    if (ret != 0)
    {
        TEST_VERDICT("shutdown(SHUT_WR) of listening socket failed "
                     "with errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    /* Check that shutdown hasn't dropped accept queue. */
    acc_s2 = rpc_accept(pco_iut, iut_s, NULL, NULL);

    /* Check that iut_s continues to accept connections after shutdown. */
    tst_s3 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_connect(pco_tst, tst_s3, iut_addr);

    acc_s3 = rpc_accept(pco_iut, iut_s, NULL, NULL);

    /* Check sockets state. */
    CHECK_SOCKET_STATE(pco_iut, acc_s1, pco_tst, tst_s1, STATE_CONNECTED);
    CHECK_SOCKET_STATE(pco_iut, acc_s2, pco_tst, tst_s2, STATE_CONNECTED);
    CHECK_SOCKET_STATE(pco_iut, acc_s3, pco_tst, tst_s3, STATE_CONNECTED);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s1);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s2);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s3);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s3);

    TEST_END;
}
