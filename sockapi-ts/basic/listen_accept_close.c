/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-listen_accept_close Connecting to closed listening socket
 *
 * @objective Check listening socket stops to accept connections after
 *            @b close().
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - (one_tst=FALSE) Private environment the first tester socket
 *              is connected from remote host, but the second from the local.
 *              - (one_tst=FALSE) the same as the prious env, but vise vers -
 *              the first socket is connected from local host and the second -
 *              from remote.
 *              - @ref arg_types_env_peer2peer_ipv6
 *              - (one_tst=FALSE) Private environment the first tester socket
 *              is connected from remote host, but the second from the local.
 *              IPv6 addresses are issued for testing.
 *              - (one_tst=FALSE) the same as the prious env, but vise vers -
 *              the first socket is connected from local host and the second -
 *              from remote. IPv6 addresses are issued for testing.
 * @param one_tst   Only one tester RPCs server is used if @c TRUE.
 * @param handover  Do @c rpc_bind_to_device() to @b lo on listener socket
 *                  if @c TRUE.
 *
 * @par Scenario:
 *
 * -# Create sockets @p iut_s and @p tst1_s1 on @p pco_iut and @p pco_tst
 *    respectively.
 * -# @b connect() @p tst1_s1 socket and call @b accept() on iut_s socket.
 *    @p acc_s should appear.
 * -# @b close() @p iut_s socket.
 * -# Check that @p acc_s and @p tst1_s1 sockets are still connected.
 * -# Create @p tst1_s2 and @p tst2_s sockets on @p pco_tst and @p pco_tst2
 *    respectively.
 * -# Call @b connect() on @p tst1_s2 and @p tst2_s sockets to connect them
 *    to @p iut_s socket.
 * -# Check that @b connect() returns @c -1 and sets errno to
 *    @c ECONNREFUSED.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/listen_accept_close"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    rcf_rpc_server            *pco_tst2 = NULL;

    const struct sockaddr     *iut_addr;
 
    int     iut_s = -1;
    int     tst1_s1 = -1;
    int     tst1_s2 = -1;
    int     tst2_s = -1;
    int     acc_s = -1;
    te_bool handover;
    te_bool one_tst;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(one_tst);
    if (!one_tst)
        TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_BOOL_PARAM(handover);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    tst1_s1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst, tst1_s1, iut_addr);
    
    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    if (handover)
    {
        unsigned    i;
        cfg_handle *handles;
        cfg_handle  handle;
        char       *name;

        CHECK_RC(cfg_find_pattern_fmt(&i, &handles,
                    "/agent:%s/interface:*/net_addr:127.0.0.1", pco_iut->ta));
        if (i == 0)
            TEST_FAIL("Failed to find loopback interface");
        CHECK_RC(cfg_get_father(handles[0], &handle));
        CHECK_RC(cfg_get_inst_name(handle, &name));
        VERB("loopback interface is %s", name);
        rpc_bind_to_device(pco_iut, iut_s, name);
        free(handles);
        free(name);
    }
    RPC_CLOSE(pco_iut, iut_s);

    sockts_test_connection(pco_iut, acc_s, pco_tst, tst1_s1);

    tst1_s2 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst1_s2, iut_addr);
    if (rc != -1)
        TEST_VERDICT("connect() from remote host to closed listening "
                     "socket returns %d instead of -1 with ECONNREFUSED",
                     rc);
    CHECK_RPC_ERRNO(pco_tst, RPC_ECONNREFUSED,
                    "connect() from remote host to closed listening "
                    "socket fails, but");

    if (!one_tst)
    {
        tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(iut_addr),
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
        RPC_AWAIT_IUT_ERROR(pco_tst2);
        rc = rpc_connect(pco_tst2, tst2_s, iut_addr);
        if (rc != -1)
            TEST_VERDICT("connect() from local host to closed listening "
                         "socket returns %d instead of -1 with ECONNREFUSED",
                         rc);
        CHECK_RPC_ERRNO(pco_tst, RPC_ECONNREFUSED,
                        "connect() from local host to closed listening "
                        "socket fails, but");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst1_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst1_s2);
    if (!one_tst)
        CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    TEST_END;
}
