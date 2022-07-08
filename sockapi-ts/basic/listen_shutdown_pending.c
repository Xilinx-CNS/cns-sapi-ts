/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-listen_shutdown_pending Check that client will receive RST in the case listening socket is shutdowned on read
 *
 * @objective Check that server host transmit RST TCP segment to
 *            the client if connection is incomplete one and listening
 *            socket is shutdowned on read.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_tst
 *              - @ref arg_types_env_peer2peer_lo
 *
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of the @p SOCK_STREAM type;
 * -# @b bind() it to the @p iut_addr;
 * -# Call @b listen() on @p iut_s;
 * -# Create the @p tst_s socket of the @p SOCK_STREAM type;
 * -# @b bind() @p tst_s to the @p tst_addr;
 * -# @b connect() @p tst_s to the @p iut_s server socket;
 * -# @b shutdown() @p iut_s for reading;
 * -# @b recv() on @p tst_s socket with @c MSG_DONTWAIT;
 * -# Check that @b recv() returns -1 and @b errno set to @c ECONNRESET;
 * -# @b close() created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/listen_shutdown_pending"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut;
    rcf_rpc_server        *pco_tst;

    int                    iut_s = -1;
    int                    tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    uint8_t                tst_buf[4096];
    int                    ret;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_connect(pco_tst, tst_s, iut_addr);

    TAPI_WAIT_NETWORK;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);
    if (ret != 0)
    {
        TEST_VERDICT("shutdown(SHUT_RD) of listening socket failed "
                     "with errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    TAPI_WAIT_NETWORK;

    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_recv(pco_tst, tst_s, tst_buf,
                  sizeof(tst_buf), RPC_MSG_DONTWAIT);
    if (rc != -1)
        TEST_FAIL("recv() returns %d instead of -1 after "
                  "listening socket shutdown for reading", rc);
    CHECK_RPC_ERRNO(pco_tst, RPC_ECONNRESET, "recv() returns -1, but");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
