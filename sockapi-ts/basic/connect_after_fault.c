/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-connect_after_fault connect() when server is temporarily unreachable
 *
 * @objective Check behaviour of @b connect() on TCP socket if server is
 *            unreachable.
 *
 * @type Conformance, compatibility
 *
 * @param env   Private environment similar to @ref arg_types_env_peer2peer
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut of @c SOCK_STREAM type;
 * -# Bind @p iut_s and @p tst_s to local address;
 * -# Get unoccupied @p tst_addr from @p net;
 * -# Imitate unreachability to create needed conditions for testing @p check;
 * -# Call @b connect() to connect @p iut_s to the @p tst_addr socket address;
 * -# Check that @b connect() returns -1 and errno set to @b ECONNREFUSED;
 * -# Repair test conditions and check a connection possibility;
 * -# Close created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/connect_after_fault"

#include "sockapi-test.h"
#include "tapi_cfg.h"

/* Timeout should be >3 min */
#define TST_CONNECT_TIMEOUT       5 * 60 * 1000

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     acc_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    struct sockaddr_storage  addr;
    socklen_t                addrlen = sizeof(addr);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);

    rpc_bind(pco_tst, tst_s, tst_addr);


    pco_iut->timeout = TST_CONNECT_TIMEOUT;
    RPC_AWAIT_IUT_ERROR(pco_iut);

    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (rc != -1)
        TEST_FAIL("connect() returns %d instead of -1 when "
                  "server can not satisfy connection request", rc);

    CHECK_RPC_ERRNO(pco_iut, RPC_ECONNREFUSED,
                    "connect() returns -1, but");

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if(rc < 0)
    {
        TEST_VERDICT("connect() failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    sockts_test_connection(pco_iut, iut_s, pco_tst, acc_s);

    rc = rpc_getpeername(pco_iut, iut_s, (struct sockaddr *)&addr, &addrlen);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    TEST_END;
}

