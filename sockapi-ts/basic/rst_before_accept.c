/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-rst_before_accept RST is got before accept()
 *
 * @objective Check @b accept() behaviour if RST packet is received after
 *            connection establishing.
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * -# Create @p iut_s on @p pco_iut of the @c SOCK_STREAM type.
 * -# Create @p tst_s on @p pco_tst of the @c SOCK_STREAM type.
 * -# @b bind() iut_s with the local address;
 * -# @b bind() tst_s with the local address;
 * -# Call @b listen() on @p iut_s.
 * -# @b connect() @p tst_s to the @p sock_tst;
 * -# Call @b setsockopt(SO_LINGER) with:
 *    @p l_onoff=1, @p l_linger=0 to generate RST on @b close();
 * -# @b close() tst_s to provoke one hand socket closing;
 * -# Call @b accept() to obtain new connection on @p iut_s and return new
 *    @b accepted socket;
 * -# Call @b recv() on @p accepted socket;
 * -# Check that @b recv() returns -1 and @b errno set to @c ECONNRESET;
 * -# Close all sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 * @author Daria Terskikh <Daria.Terskikh@oktetlabs.ru> (@b AcceptEx())
 */

#define TE_TEST_NAME  "basic/rst_before_accept"

#include "sockapi-test.h"

#define TST_BUF_LEN    10

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     accepted = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    tarpc_linger            optval;

    unsigned char           buf[TST_BUF_LEN];
    rpc_ptr                 recv_buf = RPC_NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_s = rpc_stream_server(pco_iut, RPC_PROTO_DEF, TRUE, iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_connect(pco_tst, tst_s, iut_addr);

    optval.l_onoff = 1;
    optval.l_linger = 0;
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER, &optval);

    RPC_CLOSE(pco_tst, tst_s);
    TAPI_WAIT_NETWORK; /* Wait for RST to be delivered */

    accepted = rpc_accept(pco_iut, iut_s, NULL, NULL);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, accepted, buf, TST_BUF_LEN, 0);
    if (rc != -1)
        TEST_FAIL("rpc_recv() should returns -1, because TCP peer sent RST");

    CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET,
                    "Accepted socket had got RST, recv() failed, but");
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_CLOSE(pco_iut, accepted);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (recv_buf != RPC_NULL)
        rpc_free(pco_iut, recv_buf);

    TEST_END;
}

